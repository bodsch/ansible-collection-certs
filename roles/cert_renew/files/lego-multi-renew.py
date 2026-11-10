#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
lego-multi-renew — issue and renew multiple TLS certificates via lego.

Successor of ``certbot-renew.py`` (certbot role) and ``lego-renew.py``
(lego role). Combines both:

* lego as ACME client (single static binary, no certbot / python-acme)
* http-01 (webroot or standalone) and dns-01 (any lego DNS provider)
* several issuers (Let's Encrypt, step-ca, ... incl. EAB + private trust anchor)
* own renewal decision: expiry threshold *and* SAN changes (expand / shrink)
* http-01 pre-checks: DNS resolution and ``.well-known/acme-challenge``
  reachability per name; unreachable names can be dropped or fail the domain
* install of cert/key/chain with owner/mode, optional certbot-like
  ``live/<domain>/`` layout
* pre/post/cleanup hooks per domain, service reload/restart after changes
* summary e-mail via SMTP (plain, STARTTLS or SSL)

Configuration files
-------------------

``/etc/lego/renew.yml`` (all keys optional)::

    lego_binary: /usr/local/bin/lego
    state_dir: /var/lib/lego
    issuers_dir: /etc/lego/issuers.d
    domains_dir: /etc/lego/domains.d
    default_issuer: letsencrypt      # used when a domain names no issuer
    renewal_days: 30
    key_type: ec256                  # rsa2048|rsa3072|rsa4096|rsa8192|ec256|ec384
    lock_file: /run/lego-renew.lock
    log_file: /var/log/lego-renew.log
    lego_timeout: 600                # seconds per lego call
    live_dir: /etc/letsencrypt/live  # optional, certbot compatible layout

    checks:                          # only for http-01
      dns: true
      well_known: true               # only in webroot mode
      on_unreachable: drop           # drop | fail | ignore
      timeout: 5

    dns_resolver:                    # resolvers for the DNS pre-check
      - 9.9.9.9

    restarts:                        # after any changed certificate
      - service: nginx
        action: reload               # reload | restart (default: restart)

    notification:
      enabled: true
      events: [changed, failed]      # or: [always]
      sender: lego@example.com
      recipient: admin@example.com   # string or list
      smtp:
        server_name: smtp.example.com
        port: 587
        tls: starttls                # starttls | ssl | none (true = starttls)
        auth:
          username: ""
          password: ""

``/etc/lego/issuers.d/<name>.yml``::

    name: letsencrypt
    server: https://acme-v02.api.letsencrypt.org/directory
    email: pki@example.com
    ca_certificate: /etc/ssl/step-ca/root_ca.crt   # optional trust anchor
    preferred_chain: "ISRG Root X1"                # optional
    eab:                                           # optional
      kid: "..."
      hmac_key: "..."
    challenge:
      type: http                     # http | dns
      webroot: /var/www/certbot      # http: webroot mode ...
      # port: ":80"                  # ... or standalone mode
      # provider: pdns               # dns: lego provider code
      # resolvers: ["127.0.0.1:53"]
      # propagation: {disable_ans: false, rns: false, wait: 0s}
      # env: {PDNS_API_URL: ..., PDNS_API_KEY: ...}
      # env_file: /etc/lego/pdns.env

``/etc/lego/domains.d/<domain>.yml``::

    domain: example.com
    subdomains: [www.example.com]
    issuer: letsencrypt              # optional with default_issuer
    key_type: rsa4096                # optional
    challenge:                       # optional, merged over the issuer's
      type: dns
      provider: hetzner
      env: {HETZNER_API_KEY: ...}
    install:                         # optional
      cert: /etc/nginx/tls/example.com/fullchain.pem
      key: /etc/nginx/tls/example.com/privkey.pem
      ca: /etc/nginx/tls/example.com/chain.pem
      combined: /etc/haproxy/certs/example.com.pem   # key + fullchain
      owner: root
      group: www-data
      cert_mode: "0644"
      key_mode: "0640"
    pre_hook: []                     # before lego is called
    post_hook: []                    # after a new cert has been installed
    cleanup_hook: []                 # after every lego call (success or not)
    restarts: [postfix]              # services for this domain only

Legacy certbot domain files (``domains: [example.com, www.example.com]``)
are accepted as well: the first entry becomes the primary domain.

Exit codes: 0 = ok, 1 = at least one domain / hook / restart failed,
2 = configuration or pre-flight error.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime as dt
import fcntl
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Optional

import yaml

try:
    from cryptography import x509
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        f"ERROR: the 'cryptography' Python package is required.\n       {exc}\n"
    )
    sys.exit(2)

try:  # optional: only needed for explicit DNS resolvers
    import dns.exception
    import dns.resolver

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAS_DNSPYTHON = False


log = logging.getLogger("lego-multi-renew")

PREFLIGHT_TIMEOUT = 10
KEY_TYPES = {"rsa2048", "rsa3072", "rsa4096", "rsa8192", "ec256", "ec384"}
CHALLENGE_TYPES = {"http", "dns"}
NAME_RE = re.compile(r"[a-z0-9_]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9])?)*")
PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s.+?\s-----END CERTIFICATE-----\s*", re.DOTALL
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "lego_binary": "/usr/local/bin/lego",
    "state_dir": "/var/lib/lego",
    "issuers_dir": "/etc/lego/issuers.d",
    "domains_dir": "/etc/lego/domains.d",
    "default_issuer": None,
    "renewal_days": 30,
    "key_type": "ec256",
    "lock_file": "/run/lego-renew.lock",
    "log_file": None,
    "lego_timeout": 600,
    "live_dir": None,
    "checks": {
        "dns": True,
        "well_known": True,
        "on_unreachable": "drop",
        "timeout": 5,
    },
    "dns_resolver": [],
    "restarts": [],
    "notification": {
        "enabled": False,
        "events": ["changed", "failed"],
        "sender": None,
        "recipient": None,
        "smtp": {
            "server_name": None,
            "port": 587,
            "tls": "starttls",
            "timeout": 30,
            "auth": {"username": None, "password": None},
        },
    },
}


def _merge(base: dict, override: dict) -> dict:
    """Recursive dict merge; *override* wins, nested dicts are merged."""
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _as_list(value: Any) -> list:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [v for v in value if v is not None and v != ""]
    return [value]


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level is not a mapping")
    return data


def load_config(path: Optional[Path]) -> dict[str, Any]:
    config = copy.deepcopy(DEFAULT_CONFIG)
    if path is not None and path.is_file():
        try:
            data = _load_yaml(path)
        except (yaml.YAMLError, ValueError) as exc:
            raise RuntimeError(f"cannot parse {path}: {exc}") from exc
        unknown = set(data) - set(DEFAULT_CONFIG)
        if unknown:
            raise RuntimeError(f"{path}: unknown keys: {sorted(unknown)}")
        config = _merge(config, data)

    if config["key_type"] not in KEY_TYPES:
        raise RuntimeError(f"invalid key_type {config['key_type']!r}")
    if config["checks"]["on_unreachable"] not in ("drop", "fail", "ignore"):
        raise RuntimeError("checks.on_unreachable must be drop, fail or ignore")
    config["renewal_days"] = int(config["renewal_days"])
    return config


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Issuer:
    name: str
    server: str
    email: str
    ca_certificate: Optional[str] = None
    preferred_chain: Optional[str] = None
    challenge: dict = dataclasses.field(default_factory=dict)
    eab: Optional[dict] = None


@dataclasses.dataclass
class Domain:
    domain: str
    subdomains: list[str]
    issuer: Optional[str]
    challenge: dict
    key_type: Optional[str]
    install: dict
    pre_hook: list[str]
    post_hook: list[str]
    cleanup_hook: list[str]
    restarts: list[dict]
    source: Optional[Path] = None

    @property
    def all_names(self) -> list[str]:
        seen: list[str] = []
        for name in [self.domain] + self.subdomains:
            name = str(name).strip().lower()
            if name and name not in seen:
                seen.append(name)
        return seen


@dataclasses.dataclass
class CertInfo:
    not_after: dt.datetime
    serial: int
    names: set[str]

    def days_left(self) -> int:
        # same truncation as lego's needRenewal()
        delta = self.not_after - dt.datetime.now(dt.timezone.utc)
        return int(delta.total_seconds() / 86400)


@dataclasses.dataclass
class Result:
    domain: str
    action: str  # skipped | issued | renewed | planned | failed
    changed: bool = False
    error: Optional[str] = None
    hook_failures: list[str] = dataclasses.field(default_factory=list)
    dropped: list[str] = dataclasses.field(default_factory=list)
    restarts: list[dict] = dataclasses.field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.action != "failed" and not self.hook_failures


def normalise_restarts(value: Any) -> list[dict]:
    result = []
    for entry in _as_list(value):
        if isinstance(entry, str):
            entry = {"service": entry}
        if not isinstance(entry, dict) or not entry.get("service"):
            raise ValueError(f"invalid restart entry: {entry!r}")
        action = str(entry.get("action", "restart")).lower()
        if action not in ("restart", "reload"):
            raise ValueError(f"invalid restart action {action!r} for {entry['service']}")
        result.append({"service": str(entry["service"]), "action": action})
    return result


def load_issuers(path: Path) -> tuple[dict[str, Issuer], list[str]]:
    issuers: dict[str, Issuer] = {}
    errors: list[str] = []
    if not path.is_dir():
        return issuers, errors
    for f in sorted(path.glob("*.yml")):
        try:
            data = _load_yaml(f)
            missing = [k for k in ("name", "server", "email") if not data.get(k)]
            if missing:
                raise ValueError(f"missing keys: {', '.join(missing)}")
            eab = data.get("eab")
            if eab and not (eab.get("kid") and eab.get("hmac_key")):
                raise ValueError("eab needs 'kid' and 'hmac_key'")
            issuer = Issuer(
                name=str(data["name"]),
                server=str(data["server"]),
                email=str(data["email"]),
                ca_certificate=data.get("ca_certificate"),
                preferred_chain=data.get("preferred_chain"),
                challenge=data.get("challenge") or {},
                eab=eab or None,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"issuer file {f}: {exc}")
            continue
        issuers[issuer.name] = issuer
    return issuers, errors


def _domain_from_data(data: dict, source: Path) -> Domain:
    if data.get("domain"):
        primary = str(data["domain"])
        subdomains = [str(x) for x in _as_list(data.get("subdomains"))]
    elif data.get("domains"):
        # legacy certbot-renew format
        names = [str(x) for x in _as_list(data["domains"])]
        primary, subdomains = names[0], names[1:]
    else:
        raise ValueError("neither 'domain' nor 'domains' defined")

    key_type = data.get("key_type")
    if key_type and key_type not in KEY_TYPES:
        raise ValueError(f"invalid key_type {key_type!r}")

    return Domain(
        domain=primary.strip().lower(),
        subdomains=subdomains,
        issuer=data.get("issuer"),
        challenge=data.get("challenge") or {},
        key_type=key_type,
        install=data.get("install") or {},
        pre_hook=[str(x) for x in _as_list(data.get("pre_hook"))],
        post_hook=[str(x) for x in _as_list(data.get("post_hook"))],
        cleanup_hook=[str(x) for x in _as_list(data.get("cleanup_hook"))],
        restarts=normalise_restarts(data.get("restarts")),
        source=source,
    )


def load_domains(path: Path) -> tuple[list[Domain], list[tuple[str, str]]]:
    """Returns (domains, [(file stem, error)])."""
    domains: list[Domain] = []
    errors: list[tuple[str, str]] = []
    if not path.is_dir():
        return domains, errors
    for f in sorted(path.glob("*.yml")):
        try:
            domains.append(_domain_from_data(_load_yaml(f), f))
        except Exception as exc:  # noqa: BLE001
            errors.append((f.stem, f"domain file {f}: {exc}"))
    return domains, errors


def effective_challenge(issuer: Issuer, domain: Domain) -> dict:
    """Issuer challenge with the domain's challenge merged on top."""
    base = copy.deepcopy(issuer.challenge or {})
    override = domain.challenge or {}
    # switching the type must not inherit type-specific keys of the issuer
    if override.get("type") and override.get("type") != base.get("type"):
        base = {}
    return _merge(base, override)


def validate_domain(
    domain: Domain, issuer: Optional[Issuer], challenge: dict
) -> list[str]:
    problems: list[str] = []
    if issuer is None:
        return [f"issuer {domain.issuer!r} is not defined"]

    ctype = challenge.get("type")
    if ctype not in CHALLENGE_TYPES:
        problems.append(f"challenge.type must be one of {sorted(CHALLENGE_TYPES)}, got {ctype!r}")
    elif ctype == "dns" and not challenge.get("provider"):
        problems.append("dns challenge needs 'provider'")
    elif ctype == "http":
        wildcards = [n for n in domain.all_names if n.startswith("*.")]
        if wildcards:
            problems.append(f"wildcards need the dns challenge: {', '.join(wildcards)}")

    env_file = challenge.get("env_file")
    if env_file and not Path(env_file).is_file():
        problems.append(f"challenge.env_file not found: {env_file}")

    for name in domain.all_names:
        plain = name[2:] if name.startswith("*.") else name
        if not NAME_RE.fullmatch(_sanitize(plain)):
            problems.append(f"invalid domain name {name!r}")
    return problems


# ---------------------------------------------------------------------------
# Certificate files
# ---------------------------------------------------------------------------


def _sanitize(name: str) -> str:
    """File name lego uses for a domain (wildcard -> '_', IDN -> punycode)."""
    name = name.replace("*", "_")
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def lego_files(state_dir: Path, domain: Domain) -> dict[str, Path]:
    base = state_dir / "certificates" / _sanitize(domain.domain)
    return {
        "cert": base.with_name(base.name + ".crt"),  # leaf + chain (bundle)
        "key": base.with_name(base.name + ".key"),
        "issuer": base.with_name(base.name + ".issuer.crt"),
    }


def read_cert_info(path: Path) -> Optional[CertInfo]:
    if not path.is_file():
        return None
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
    except Exception as exc:  # noqa: BLE001
        log.warning("cannot parse %s: %s", path, exc)
        return None
    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    )
    names: set[str] = set()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = {n.lower() for n in san.value.get_values_for_type(x509.DNSName)}
    except x509.ExtensionNotFound:
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn:
            names = {str(cn[0].value).lower()}
    return CertInfo(not_after=not_after, serial=cert.serial_number, names=names)


# ---------------------------------------------------------------------------
# http-01 pre-checks
# ---------------------------------------------------------------------------


def resolve_name(name: str, resolvers: list[str], timeout: float) -> Optional[str]:
    """Returns None if *name* resolves (A or AAAA), else an error text."""
    if resolvers and HAS_DNSPYTHON:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [str(r) for r in resolvers]
        res.timeout = res.lifetime = float(timeout)
        last_error = "no A/AAAA record"
        for rtype in ("A", "AAAA"):
            try:
                if res.resolve(name, rtype):
                    return None
            except dns.resolver.NXDOMAIN:
                return "no such domain"
            except dns.resolver.NoAnswer:
                continue
            except dns.exception.Timeout:
                last_error = "timeout"
            except dns.exception.DNSException as exc:
                last_error = repr(exc)
        return last_error

    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(name, None)
        return None
    except socket.gaierror as exc:
        return exc.strerror or str(exc)
    finally:
        socket.setdefaulttimeout(old)


def _http_opener() -> urllib.request.OpenerDirector:
    # The ACME server follows redirects to https without verifying the
    # certificate, so the probe does the same.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def probe_well_known(names: list[str], webroot: str, timeout: float) -> dict[str, str]:
    """Place a token below the webroot and fetch it for every name.

    Returns {name: error} for every name that failed.
    """
    failures: dict[str, str] = {}
    challenge_dir = Path(webroot) / ".well-known" / "acme-challenge"
    token = uuid.uuid4().hex
    token_file = challenge_dir / token
    try:
        challenge_dir.mkdir(parents=True, exist_ok=True)
        token_file.write_text(token, encoding="ascii")
        os.chmod(token_file, 0o644)
    except OSError as exc:
        return {n: f"cannot write token to {challenge_dir}: {exc}" for n in names}

    opener = _http_opener()
    try:
        for name in names:
            url = f"http://{name}/.well-known/acme-challenge/{token}"
            try:
                with opener.open(url, timeout=timeout) as resp:
                    body = resp.read(512).decode("utf-8", "replace").strip()
                if body != token:
                    failures[name] = f"unexpected content from {url}"
            except urllib.error.HTTPError as exc:
                failures[name] = f"HTTP {exc.code} for {url}"
            except Exception as exc:  # noqa: BLE001
                reason = getattr(exc, "reason", exc)
                failures[name] = f"{url}: {reason}"
    finally:
        try:
            token_file.unlink()
        except OSError:
            pass
    return failures


def check_names(
    config: dict, names: list[str], challenge: dict
) -> dict[str, str]:
    """Run the configured http-01 pre-checks, returns {name: error}."""
    checks = config["checks"]
    timeout = float(checks["timeout"])
    failures: dict[str, str] = {}

    if checks["dns"]:
        resolvers = _as_list(config["dns_resolver"])
        if resolvers and not HAS_DNSPYTHON:
            log.warning("dns_resolver set but dnspython is missing, using system resolver")
        for name in names:
            err = resolve_name(name, resolvers, timeout)
            if err:
                failures[name] = f"DNS: {err}"

    webroot = challenge.get("webroot")
    if checks["well_known"] and webroot:
        remaining = [n for n in names if n not in failures]
        if remaining:
            failures.update(probe_well_known(remaining, webroot, timeout))

    for name, err in failures.items():
        log.warning("  %s: %s", name, err)
    return failures


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def check_global(config: dict) -> list[str]:
    problems: list[str] = []
    binary = config["lego_binary"]
    resolved = shutil.which(binary) if os.path.basename(binary) == binary else binary
    if not resolved or not os.path.isfile(resolved):
        problems.append(f"lego binary not found: {binary}")
    elif not os.access(resolved, os.X_OK):
        problems.append(f"lego binary not executable: {resolved}")

    state_dir = Path(config["state_dir"])
    if state_dir.exists():
        if not state_dir.is_dir() or not os.access(state_dir, os.W_OK):
            problems.append(f"state_dir is not a writable directory: {state_dir}")
    elif not os.access(state_dir.parent, os.W_OK):
        problems.append(f"state_dir cannot be created: {state_dir}")

    for key in ("issuers_dir", "domains_dir"):
        if not Path(config[key]).is_dir():
            problems.append(f"{key} is not a directory: {config[key]}")
    return problems


def check_issuer(issuer: Issuer, probe_tls: bool) -> Optional[str]:
    """Validate the trust anchor and optionally probe the ACME directory."""
    if issuer.ca_certificate:
        path = Path(issuer.ca_certificate)
        if not path.is_file():
            return f"ca_certificate not found: {path}"
        info = read_cert_info(path)
        if info is None:
            return f"ca_certificate is not a valid PEM certificate: {path}"
        if info.days_left() < 0:
            return f"ca_certificate expired on {info.not_after:%Y-%m-%d}: {path}"

    if not probe_tls:
        return None
    try:
        ctx = ssl.create_default_context(cafile=issuer.ca_certificate or None)
    except (ssl.SSLError, OSError) as exc:
        return f"cannot load ca_certificate: {exc}"
    req = urllib.request.Request(
        issuer.server, headers={"User-Agent": "lego-multi-renew-preflight"}
    )
    try:
        with urllib.request.urlopen(req, timeout=PREFLIGHT_TIMEOUT, context=ctx):
            return None
    except urllib.error.HTTPError:
        return None  # TLS fine, status code irrelevant here
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            detail = getattr(reason, "verify_message", None) or reason
            return f"TLS verification failed for {issuer.server}: {detail}"
        return f"cannot reach {issuer.server}: {reason}"
    except Exception as exc:  # noqa: BLE001
        return f"error probing {issuer.server}: {exc}"


# ---------------------------------------------------------------------------
# lego
# ---------------------------------------------------------------------------


def build_lego_argv(
    config: dict,
    issuer: Issuer,
    domain: Domain,
    challenge: dict,
    names: list[str],
    mode: str,
) -> list[str]:
    argv = [
        config["lego_binary"],
        "--accept-tos",
        "--email", issuer.email,
        "--server", issuer.server,
        "--path", str(config["state_dir"]),
        "--key-type", domain.key_type or config["key_type"],
    ]

    if issuer.eab:
        argv += ["--eab", "--kid", str(issuer.eab["kid"]), "--hmac", str(issuer.eab["hmac_key"])]

    if challenge["type"] == "http":
        argv.append("--http")
        if challenge.get("webroot"):
            argv += ["--http.webroot", str(challenge["webroot"])]
        elif challenge.get("port"):
            port = str(challenge["port"])
            argv += ["--http.port", port if ":" in port else f":{port}"]
    else:
        argv += ["--dns", str(challenge["provider"])]
        for resolver in _as_list(challenge.get("resolvers")):
            argv += ["--dns.resolvers", str(resolver)]
        prop = challenge.get("propagation") or {}
        if prop.get("disable_ans"):
            argv.append("--dns.propagation-disable-ans")
        if prop.get("rns"):
            argv.append("--dns.propagation-rns")
        if prop.get("wait"):
            argv += ["--dns.propagation-wait", str(prop["wait"])]

    for name in names:
        argv += ["-d", name]

    if mode == "run":
        argv.append("run")
    else:
        argv += ["renew", "--days", str(config["renewal_days"]), "--no-random-sleep"]
    if issuer.preferred_chain:
        argv += ["--preferred-chain", str(issuer.preferred_chain)]
    return argv


def _read_env_file(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        env[key] = value.strip().strip("'\"")
    return env


def build_lego_env(issuer: Issuer, challenge: dict) -> dict[str, str]:
    env = os.environ.copy()
    if issuer.ca_certificate:
        env["LEGO_CA_CERTIFICATES"] = str(issuer.ca_certificate)
    if challenge.get("env_file"):
        env.update(_read_env_file(challenge["env_file"]))
    for key, value in (challenge.get("env") or {}).items():
        env[str(key)] = str(value)
    return env


def mask_argv(argv: list[str]) -> str:
    out, hide = [], False
    for arg in argv:
        out.append("***" if hide else arg)
        hide = arg in ("--hmac", "--kid")
    return " ".join(out)


def run_lego(argv: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return 127, f"lego binary not found: {exc}"
    except subprocess.TimeoutExpired:
        return 124, f"lego did not finish within {timeout}s"
    return proc.returncode, proc.stdout or ""


# ---------------------------------------------------------------------------
# Install + hooks
# ---------------------------------------------------------------------------


def _resolve_id(name: Any, kind: str) -> int:
    if name is None or name == "":
        return -1
    if isinstance(name, int) or str(name).isdigit():
        return int(name)
    import grp
    import pwd

    try:
        if kind == "user":
            return pwd.getpwnam(str(name)).pw_uid
        return grp.getgrnam(str(name)).gr_gid
    except KeyError:
        raise RuntimeError(f"{kind} {name!r} does not exist") from None


def write_atomic(target: Path, data: bytes, mode: str, uid: int, gid: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, int(str(mode), 8))
        if uid != -1 or gid != -1:
            os.chown(tmp, uid, gid)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    log.info("  installed %s", target)


def install_cert(config: dict, domain: Domain) -> list[Path]:
    """Copy the lego output to the configured places. Returns written paths."""
    files = lego_files(Path(config["state_dir"]), domain)
    for path in files.values():
        if not path.is_file():
            raise RuntimeError(f"expected lego output missing: {path}")

    fullchain = files["cert"].read_bytes()
    key = files["key"].read_bytes()
    issuer = files["issuer"].read_bytes()
    blocks = PEM_CERT_RE.findall(fullchain)
    leaf = blocks[0] if blocks else fullchain
    chain = b"".join(blocks[1:]) if len(blocks) > 1 else issuer

    inst = domain.install
    uid = _resolve_id(inst.get("owner"), "user")
    gid = _resolve_id(inst.get("group"), "group")
    cert_mode = inst.get("cert_mode", "0644")
    key_mode = inst.get("key_mode", "0640")
    ca_mode = inst.get("ca_mode", "0644")

    plan: list[tuple[Path, bytes, str]] = []
    for target_key, data, mode in (
        ("cert", fullchain, cert_mode),
        ("fullchain", fullchain, cert_mode),
        ("leaf", leaf, cert_mode),
        ("ca", chain, ca_mode),
        ("key", key, key_mode),
        ("combined", key + b"\n" + fullchain, key_mode),
    ):
        if inst.get(target_key):
            plan.append((Path(inst[target_key]), data, mode))

    if config.get("live_dir"):
        live = Path(config["live_dir"]) / _sanitize(domain.domain)
        plan += [
            (live / "cert.pem", leaf, cert_mode),
            (live / "chain.pem", chain, ca_mode),
            (live / "fullchain.pem", fullchain, cert_mode),
            (live / "privkey.pem", key, key_mode),
        ]

    for target, data, mode in plan:
        write_atomic(target, data, mode, uid, gid)
    return [p for p, _, _ in plan]


def run_hooks(hooks: list[str], label: str, env: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for cmd in hooks:
        log.info("  %s: %s", label, cmd)
        try:
            proc = subprocess.run(
                cmd, shell=True, env=env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=300, check=False,
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{label} {cmd!r}: {exc}")
            continue
        if proc.returncode != 0:
            failures.append(f"{label} {cmd!r} exited {proc.returncode}: {proc.stdout.strip()}")
    for f in failures:
        log.error("  %s", f)
    return failures


def hook_env(config: dict, domain: Domain, names: list[str], action: str) -> dict[str, str]:
    files = lego_files(Path(config["state_dir"]), domain)
    env = os.environ.copy()
    env.update({
        "LEGO_RENEW_DOMAIN": domain.domain,
        "LEGO_RENEW_DOMAINS": " ".join(names),
        "LEGO_RENEW_ACTION": action,
        "LEGO_RENEW_CERT_PATH": str(files["cert"]),
        "LEGO_RENEW_KEY_PATH": str(files["key"]),
        "LEGO_RENEW_ISSUER_PATH": str(files["issuer"]),
    })
    return env


# ---------------------------------------------------------------------------
# Per-domain processing
# ---------------------------------------------------------------------------


def decide(
    current: Optional[CertInfo],
    effective: list[str],
    configured: list[str],
    force: bool,
    renewal_days: int,
) -> tuple[Optional[str], str]:
    """Returns (mode, reason). mode None = nothing to do."""
    if current is None:
        return "run", "no certificate yet"
    if force:
        return "run", "forced"
    added = sorted(set(effective) - current.names)
    removed = sorted(current.names - set(configured))
    if added or removed:
        parts = [f"+{n}" for n in added] + [f"-{n}" for n in removed]
        return "run", f"names changed ({' '.join(parts)})"
    days = current.days_left()
    if days <= renewal_days:
        # 'lego renew' keeps all names of the current cert; if some of them
        # were dropped by the pre-checks the cert must be re-issued instead.
        if current.names - set(effective):
            return "run", f"expires in {days} days, unreachable names are dropped"
        return "renew", f"expires in {days} days"
    return None, f"valid for {days} more days (renewal at <= {renewal_days})"


def process_domain(
    config: dict,
    domain: Domain,
    issuer: Optional[Issuer],
    issuer_problem: Optional[str],
    args: argparse.Namespace,
) -> Result:
    log.info("- %s", domain.domain)

    if issuer_problem:
        log.error("  issuer %s: %s", domain.issuer, issuer_problem)
        return Result(domain.domain, "failed", error=f"issuer: {issuer_problem}")

    challenge = effective_challenge(issuer, domain) if issuer else {}
    problems = validate_domain(domain, issuer, challenge)
    if problems:
        for p in problems:
            log.error("  %s", p)
        return Result(domain.domain, "failed", error="; ".join(problems))

    configured = domain.all_names
    files = lego_files(Path(config["state_dir"]), domain)
    current = read_cert_info(files["cert"])

    mode, reason = decide(current, configured, configured, args.force, config["renewal_days"])
    if mode is None:
        log.info("  nothing to do: %s", reason)
        return Result(domain.domain, "skipped")

    log.debug("  issuer=%s challenge=%s", issuer.name, challenge.get("type"))

    # -- http-01 pre-checks ----------------------------------------------
    effective = configured
    dropped: list[str] = []
    policy = config["checks"]["on_unreachable"]
    if challenge["type"] == "http" and policy != "ignore":
        failures = check_names(config, configured, challenge)
        if failures:
            if policy == "fail" or domain.domain in failures:
                msg = f"pre-check failed for {', '.join(sorted(failures))}"
                log.error("  %s", msg)
                return Result(domain.domain, "failed", error=msg)
            dropped = [n for n in configured if n in failures]
            effective = [n for n in configured if n not in failures]
            log.warning("  dropping unreachable names: %s", ", ".join(dropped))
            mode, reason = decide(current, effective, configured, args.force, config["renewal_days"])
            if mode is None:
                log.info("  nothing to do: %s", reason)
                return Result(domain.domain, "skipped", dropped=dropped)

    log.info("  %s: %s", "issue" if mode == "run" else "renew", reason)
    argv = build_lego_argv(config, issuer, domain, challenge, effective, mode)

    if args.dry_run:
        log.info("  [dry-run] would exec: %s", mask_argv(argv))
        return Result(domain.domain, "planned", dropped=dropped)

    action_label = "issue" if current is None else ("renew" if mode == "renew" else "reissue")
    henv = hook_env(config, domain, effective, action_label)

    hook_failures = run_hooks(domain.pre_hook, "pre_hook", henv)

    log.debug("  exec: %s", mask_argv(argv))
    started = time.monotonic()
    rc, output = run_lego(argv, build_lego_env(issuer, challenge), int(config["lego_timeout"]))
    log.debug("  lego finished in %.1fs (rc=%d)", time.monotonic() - started, rc)
    for line in output.strip().splitlines():
        if rc != 0:
            log.error("    lego: %s", line)
        elif args.verbose:
            log.info("    lego: %s", line)
        else:
            log.debug("    lego: %s", line)

    hook_failures += run_hooks(domain.cleanup_hook, "cleanup_hook", henv)

    if rc != 0:
        return Result(
            domain.domain, "failed", error=f"lego exited with {rc}",
            hook_failures=hook_failures, dropped=dropped,
        )

    after = read_cert_info(files["cert"])
    changed = after is not None and (current is None or after.serial != current.serial)
    if not changed:
        log.info("  lego did not replace the certificate")
        return Result(domain.domain, "skipped", hook_failures=hook_failures, dropped=dropped)

    action = "issued" if current is None else "renewed"
    try:
        install_cert(config, domain)
    except Exception as exc:  # noqa: BLE001
        log.error("  install failed: %s", exc)
        return Result(
            domain.domain, "failed", changed=True, error=f"install: {exc}",
            hook_failures=hook_failures, dropped=dropped,
        )

    hook_failures += run_hooks(domain.post_hook, "post_hook", henv)
    log.info("  %s, valid until %s", action, after.not_after.strftime("%Y-%m-%d %H:%M UTC"))
    return Result(
        domain.domain, action, changed=True, hook_failures=hook_failures,
        dropped=dropped, restarts=domain.restarts,
    )


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def detect_init_system() -> str:
    if os.path.isdir("/run/systemd/system") and shutil.which("systemctl"):
        return "systemd"
    if shutil.which("rc-service"):
        return "openrc"
    return "unknown"


def restart_services(services: list[dict], dry_run: bool) -> list[str]:
    """Restart/reload services that are currently running. Returns failures."""
    if not services:
        return []
    init = detect_init_system()
    failures: list[str] = []

    # de-duplicate, 'restart' wins over 'reload'
    merged: dict[str, str] = {}
    for s in services:
        if merged.get(s["service"]) != "restart":
            merged[s["service"]] = s["action"]

    log.info("Restart services")
    for service, action in merged.items():
        if init == "systemd":
            unit = service if "." in service else f"{service}.service"
            status_cmd = ["systemctl", "is-active", "--quiet", unit]
            action_cmd = ["systemctl", action, unit]
        elif init == "openrc":
            status_cmd = ["rc-service", service, "status"]
            action_cmd = ["rc-service", service, action]
        else:
            failures.append(f"{service}: unsupported init system")
            log.error("  %s: unsupported init system", service)
            continue

        if subprocess.run(status_cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode != 0:
            log.warning("  %s is not running, skipped", service)
            continue
        if dry_run:
            log.info("  [dry-run] would %s %s", action, service)
            continue
        proc = subprocess.run(action_cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, check=False)
        if proc.returncode == 0:
            log.info("  %s: %s done", service, action)
        else:
            msg = f"{service}: {action} failed: {proc.stdout.strip()}"
            log.error("  %s", msg)
            failures.append(msg)
    return failures


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------


class MemoryLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.lines: list[str] = []
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))

    def text(self) -> str:
        return "\n".join(self.lines)


def should_notify(config: dict, results: list[Result], extra_failures: list[str]) -> bool:
    notification = config["notification"]
    if not notification.get("enabled"):
        return False
    events = {str(e).lower() for e in _as_list(notification.get("events"))}
    if "always" in events:
        return True
    if "failed" in events and (extra_failures or any(not r.ok for r in results)):
        return True
    if "changed" in events and any(r.changed for r in results):
        return True
    return False


def send_mail(config: dict, subject: str, body: str) -> None:
    import smtplib
    from email.message import EmailMessage
    from email.utils import formatdate, make_msgid

    n = config["notification"]
    smtp = n.get("smtp") or {}
    recipients = [str(r) for r in _as_list(n.get("recipient"))]
    if not (smtp.get("server_name") and n.get("sender") and recipients):
        log.error("notification: smtp.server_name, sender or recipient missing")
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = str(n["sender"])
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body)

    tls = smtp.get("tls", "starttls")
    if tls is True:
        tls = "starttls"
    elif tls in (False, None):
        tls = "none"
    tls = str(tls).lower()
    port = int(smtp.get("port") or (465 if tls == "ssl" else 587 if tls == "starttls" else 25))
    timeout = float(smtp.get("timeout", 30))
    ctx = ssl.create_default_context()
    auth = smtp.get("auth") or {}

    try:
        if tls == "ssl":
            server = smtplib.SMTP_SSL(smtp["server_name"], port, timeout=timeout, context=ctx)
        else:
            server = smtplib.SMTP(smtp["server_name"], port, timeout=timeout)
        with server:
            server.ehlo(socket.getfqdn())
            if tls == "starttls":
                server.starttls(context=ctx)
                server.ehlo(socket.getfqdn())
            if auth.get("username") and auth.get("password"):
                server.login(str(auth["username"]), str(auth["password"]))
            server.send_message(msg, to_addrs=recipients)
        log.info("notification sent to %s", ", ".join(recipients))
    except (smtplib.SMTPException, OSError) as exc:
        log.error("notification failed: %s", exc)


# ---------------------------------------------------------------------------
# --list
# ---------------------------------------------------------------------------


def cmd_list(config: dict, domains: list[Domain], issuers: dict[str, Issuer], as_json: bool) -> int:
    rows = []
    for d in domains:
        issuer = issuers.get(d.issuer or "")
        challenge = effective_challenge(issuer, d).get("type") if issuer else None
        info = read_cert_info(lego_files(Path(config["state_dir"]), d)["cert"])
        if info is None:
            status, days, not_after = "not-issued", None, None
        else:
            days = info.days_left()
            not_after = info.not_after
            if days < 0:
                status = "EXPIRED"
            elif info.names != set(d.all_names):
                status = "names-changed"
            elif days <= config["renewal_days"]:
                status = "renew-due"
            else:
                status = "ok"
        rows.append({
            "domain": d.domain,
            "names": d.all_names,
            "issuer": d.issuer,
            "challenge": challenge,
            "not_after": not_after.isoformat() if not_after else None,
            "days_left": days,
            "status": status,
        })

    if as_json:
        json.dump(rows, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if not rows:
        print("No domains configured.")
        return 0
    fmt = "{:<35} {:<18} {:<9} {:<17} {:>9}  {}"
    print(fmt.format("DOMAIN", "ISSUER", "CHALLENGE", "NOT_AFTER", "DAYS_LEFT", "STATUS"))
    print("-" * 104)
    for r in rows:
        print(fmt.format(
            r["domain"], str(r["issuer"] or "-"), str(r["challenge"] or "-"),
            (r["not_after"] or "-")[:16].replace("T", " "),
            "-" if r["days_left"] is None else r["days_left"], r["status"],
        ))
    return 0


# ---------------------------------------------------------------------------
# Locking / logging
# ---------------------------------------------------------------------------


class Lock:
    def __init__(self, path: str) -> None:
        self.path = path
        self.fd: Optional[int] = None

    def __enter__(self) -> "Lock":
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        except OSError as exc:
            raise RuntimeError(f"cannot open lock file {self.path}: {exc}") from exc
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            raise RuntimeError(f"another run holds {self.path}") from None
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def setup_logging(level: str, silent: bool) -> MemoryLogHandler:
    log.setLevel(logging.DEBUG)
    log.propagate = False
    for h in list(log.handlers):
        log.removeHandler(h)
    if not silent:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(level)
        sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S"))
        log.addHandler(sh)
    memory = MemoryLogHandler()
    log.addHandler(memory)
    return memory


def add_file_logging(path: str, level: str) -> None:
    try:
        fh = logging.FileHandler(path)
    except OSError as exc:
        log.warning("cannot open log file %s: %s", path, exc)
        return
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(fh)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lego-multi-renew",
        description="Issue and renew multiple TLS certificates via lego (http-01 / dns-01).",
    )
    p.add_argument("-C", "--config", default="/etc/lego/renew.yml",
                   help="configuration file (default: %(default)s)")
    p.add_argument("-d", "--domain", action="append", default=[],
                   help="process only this domain (repeatable)")
    p.add_argument("-L", "--list", action="store_true",
                   help="list configured certificates and their state")
    p.add_argument("--json", action="store_true", help="JSON output for --list")
    p.add_argument("--preflight", action="store_true",
                   help="check binary, directories, issuers, domain definitions and exit")
    p.add_argument("--dry-run", action="store_true",
                   help="run all checks, print the lego calls, change nothing")
    p.add_argument("--force", action="store_true",
                   help="re-issue the selected certificates regardless of expiry")
    p.add_argument("--force-restarts", action="store_true",
                   help="restart/reload the configured services even without changes")
    p.add_argument("--no-notify", action="store_true", help="do not send an e-mail")
    p.add_argument("--lego-binary", help="override lego_binary")
    p.add_argument("--renewal-days", type=int, help="override renewal_days")
    p.add_argument("--verbose", action="store_true", help="show lego output on success")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--log-file", help="additional log file (overrides log_file)")
    p.add_argument("--silent", action="store_true", help="no console output")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    memory = setup_logging(args.log_level, args.silent)

    try:
        config = load_config(Path(args.config))
        normalise_restarts(config["restarts"])
    except Exception as exc:  # noqa: BLE001
        log.error("configuration error: %s", exc)
        return 2
    if args.lego_binary:
        config["lego_binary"] = args.lego_binary
    if args.renewal_days is not None:
        config["renewal_days"] = args.renewal_days

    log_file = args.log_file or config.get("log_file")
    if log_file and not args.list:
        add_file_logging(log_file, args.log_level)

    issuers, issuer_errors = load_issuers(Path(config["issuers_dir"]))
    domains, domain_errors = load_domains(Path(config["domains_dir"]))
    for d in domains:
        if not d.issuer:
            d.issuer = config["default_issuer"]

    if args.domain:
        wanted = {x.lower() for x in args.domain}
        domains = [d for d in domains if d.domain in wanted or (d.source and d.source.stem in wanted)]
        domain_errors = [e for e in domain_errors if e[0] in wanted]
        if not domains and not domain_errors:
            log.error("domain(s) %s not found in %s", ", ".join(args.domain), config["domains_dir"])
            return 2

    if args.list:
        return cmd_list(config, domains, issuers, args.json)

    for err in issuer_errors:
        log.error(err)

    problems = check_global(config)
    if args.preflight:
        for d in domains:
            issuer = issuers.get(d.issuer or "")
            challenge = effective_challenge(issuer, d) if issuer else {}
            problems += [f"{d.domain}: {p}" for p in validate_domain(d, issuer, challenge)]
        for name in sorted({d.issuer for d in domains if d.issuer in issuers}):
            problem = check_issuer(issuers[name], probe_tls=True)
            if problem:
                problems.append(f"issuer {name}: {problem}")
        problems += [e for _, e in domain_errors] + issuer_errors
        for p in problems:
            log.error("  %s", p)
        log.info("pre-flight %s", "failed" if problems else "passed")
        return 2 if problems else 0

    if problems:
        for p in problems:
            log.error("pre-flight: %s", p)
        return 2

    lock: Optional[Lock] = None
    if not args.dry_run:
        try:
            lock = Lock(config["lock_file"]).__enter__()
        except RuntimeError as exc:
            log.error("%s", exc)
            return 1

    fqdn = socket.getfqdn()
    log.info("Renew TLS certificates via lego on %s", fqdn)
    results: list[Result] = []
    extra_failures: list[str] = []
    try:
        for stem, err in domain_errors:
            log.error(err)
            results.append(Result(stem, "failed", error=err))

        issuer_state: dict[str, Optional[str]] = {}
        for d in domains:
            issuer = issuers.get(d.issuer or "")
            if issuer is not None and issuer.name not in issuer_state:
                issuer_state[issuer.name] = check_issuer(issuer, probe_tls=not args.dry_run)
            problem = issuer_state.get(issuer.name) if issuer else None
            try:
                results.append(process_domain(config, d, issuer, problem, args))
            except Exception as exc:  # noqa: BLE001
                log.exception("%s: unexpected error", d.domain)
                results.append(Result(d.domain, "failed", error=str(exc)))

        services: list[dict] = []
        if args.force_restarts or any(r.changed for r in results):
            services = normalise_restarts(config["restarts"])
        for r in results:
            services += r.restarts
        extra_failures = restart_services(services, args.dry_run)
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)

    counts: dict[str, int] = {}
    for r in results:
        counts[r.action] = counts.get(r.action, 0) + 1
    failed = [r for r in results if not r.ok]
    log.info("summary: %s", " ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing")
    if failed:
        log.error("failures: %s", ", ".join(r.domain for r in failed))
    dropped = [f"{r.domain}: {', '.join(r.dropped)}" for r in results if r.dropped]
    if dropped:
        log.warning("dropped names: %s", "; ".join(dropped))

    if not args.no_notify and not args.dry_run and should_notify(config, results, extra_failures):
        state = "FAILED" if failed or extra_failures else "OK"
        subject = f"[{state}] TLS certificates on {fqdn} - {dt.date.today().isoformat()}"
        send_mail(config, subject, memory.text())
    elif args.dry_run and config["notification"].get("enabled"):
        log.info("[dry-run] no notification sent")

    return 1 if failed or extra_failures else 0


if __name__ == "__main__":
    sys.exit(main())
