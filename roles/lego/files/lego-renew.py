#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
lego-renew — issue and renew TLS certificates declared in
``/etc/lego/domains.d/*.yml`` against the matching issuers in
``/etc/lego/issuers.d/*.yml``.

Designed to be invoked on a schedule (systemd timer, cron) and also
ad-hoc for debugging single domains.

Per-domain operation:
  1. Determine whether the cert exists (→ issue) or exists already
     (→ renew). lego decides itself whether a renew actually needs
     to refresh the cert (default threshold: 30 days remaining).
  2. Run lego with the issuer's configuration.
  3. If the cert's notAfter changed: run pre_hook, copy cert/key/ca
     to their install paths with the configured ownership/modes, run
     post_hook. Hook failures are reported but do not abort the run.
  4. Continue with the next domain regardless. Exit non-zero if any
     domain failed or any hook returned non-zero, so a systemd unit
     can pick it up.

Configuration is layered: hardcoded defaults < config file < environment
variables < CLI flags. Each layer overrides the previous one.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fcntl
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

import yaml

try:
    from cryptography import x509
except ImportError as exc:
    sys.stderr.write(
        "ERROR: the 'cryptography' Python package is required.\n"
        f"       {exc}\n"
    )
    sys.exit(2)


log = logging.getLogger("lego-renew")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: Built-in defaults. Every key here MUST exist after merging — keys that are
#: not exposed via env or CLI cannot be reset to None.
DEFAULT_CONFIG: dict[str, Any] = {
    "lego_binary":   "/usr/local/bin/lego",
    "state_dir":     "/var/lib/lego",
    "issuers_dir":   "/etc/lego/issuers.d",
    "domains_dir":   "/etc/lego/domains.d",
    "renewal_days":  30,
    "key_type":      "ec256",
    "lock_file":     "/run/lego-renew.lock",
}

#: Map environment variable names to config keys. Env vars override the
#: config file, CLI flags override env vars. Naming follows the
#: ``LEGO_RENEW_<UPPER_KEY>`` convention.
ENV_OVERRIDES: dict[str, str] = {
    "LEGO_RENEW_LEGO_BINARY":   "lego_binary",
    "LEGO_RENEW_STATE_DIR":     "state_dir",
    "LEGO_RENEW_ISSUERS_DIR":   "issuers_dir",
    "LEGO_RENEW_DOMAINS_DIR":   "domains_dir",
    "LEGO_RENEW_RENEWAL_DAYS":  "renewal_days",
    "LEGO_RENEW_KEY_TYPE":      "key_type",
    "LEGO_RENEW_LOCK_FILE":     "lock_file",
}

#: Keys whose env-var values must be coerced to int.
_INT_KEYS = {"renewal_days"}


def load_config(config_path: Optional[Path]) -> dict[str, Any]:
    """
    Assemble the effective configuration from layered sources.

    Order (later wins):
      1. :data:`DEFAULT_CONFIG`
      2. YAML at ``config_path`` if the file exists
      3. ``LEGO_RENEW_*`` environment variables

    CLI flags are applied separately in ``main()`` because argparse
    needs to know which flags were explicitly given vs. left at default.
    """
    config = dict(DEFAULT_CONFIG)

    if config_path is not None and config_path.is_file():
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise RuntimeError(f"Cannot parse {config_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"{config_path}: top-level is not a mapping")
        unknown = set(data) - set(DEFAULT_CONFIG)
        if unknown:
            raise RuntimeError(
                f"{config_path}: unknown keys: {sorted(unknown)}"
            )
        config.update(data)

    for env_key, cfg_key in ENV_OVERRIDES.items():
        if env_key in os.environ:
            raw = os.environ[env_key]
            config[cfg_key] = int(raw) if cfg_key in _INT_KEYS else raw

    return config


def apply_cli_overrides(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """
    Apply CLI flag overrides to *config*. Only flags that were explicitly
    set (i.e. not None) take effect.
    """
    cli_map = {
        "lego_binary":  args.lego_binary,
        "state_dir":    args.state_dir,
        "issuers_dir":  args.issuers_dir,
        "domains_dir":  args.domains_dir,
        "renewal_days": args.renewal_days,
    }
    for key, value in cli_map.items():
        if value is not None:
            config[key] = value
    return config


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Issuer:
    """One loaded issuer YAML, normalised."""
    name: str
    server: str
    email: str
    ca_certificate: Optional[str]
    challenge: dict
    eab: Optional[dict]


@dataclasses.dataclass
class Domain:
    """One loaded domain spec YAML, normalised."""
    domain: str
    subdomains: list[str]
    issuer: str
    install: dict
    pre_hook: list[str]
    post_hook: list[str]

    @property
    def all_names(self) -> list[str]:
        return [self.domain] + self.subdomains


@dataclasses.dataclass
class RenewalResult:
    """Outcome of processing one domain."""
    domain: str
    action: str              # "skipped" | "issued" | "renewed" | "failed"
    cert_changed: bool
    hook_failures: list[str] = dataclasses.field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.action != "failed" and not self.hook_failures


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> dict:
    """Read a YAML file as a dict. Empty files map to {}."""
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level is not a mapping")
    return data


def load_issuers(path: Path) -> dict[str, Issuer]:
    """Read all issuer definitions, keyed by name."""
    issuers: dict[str, Issuer] = {}
    if not path.is_dir():
        return issuers
    for f in sorted(path.glob("*.yml")):
        data = _load_yaml(f)
        issuer = Issuer(
            name=data["name"],
            server=data["server"],
            email=data["email"],
            ca_certificate=data.get("ca_certificate"),
            challenge=data["challenge"],
            eab=data.get("eab"),
        )
        issuers[issuer.name] = issuer
    return issuers


def load_domains(path: Path) -> list[Domain]:
    """Read all domain specs."""
    domains: list[Domain] = []
    if not path.is_dir():
        return domains
    for f in sorted(path.glob("*.yml")):
        data = _load_yaml(f)
        domains.append(
            Domain(
                domain=data["domain"],
                subdomains=data.get("subdomains") or [],
                issuer=data["issuer"],
                install=data.get("install") or {},
                pre_hook=data.get("pre_hook") or [],
                post_hook=data.get("post_hook") or [],
            )
        )
    return domains


# ---------------------------------------------------------------------------
# Cert path helpers (depend on state_dir, so passed at runtime)
# ---------------------------------------------------------------------------

def cert_path(state_dir: Path, domain: Domain) -> Path:
    """Path lego writes the leaf certificate to."""
    return state_dir / "certificates" / f"{domain.domain}.crt"


def key_path(state_dir: Path, domain: Domain) -> Path:
    return state_dir / "certificates" / f"{domain.domain}.key"


def issuer_cert_path(state_dir: Path, domain: Domain) -> Path:
    """Lego stores the intermediate as ``<domain>.issuer.crt``."""
    return state_dir / "certificates" / f"{domain.domain}.issuer.crt"


# ---------------------------------------------------------------------------
# Cert inspection
# ---------------------------------------------------------------------------

def read_not_after(path: Path) -> Optional[dt.datetime]:
    """
    Return notAfter (UTC) of a PEM cert file, or None if the file is
    missing or unreadable.
    """
    if not path.is_file():
        return None
    try:
        data = path.read_bytes()
        cert = x509.load_pem_x509_certificate(data)
    except Exception as exc:                       # noqa: BLE001
        log.warning("Cannot parse %s: %s", path, exc)
        return None
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------------------
# lego invocation
# ---------------------------------------------------------------------------

def build_lego_argv(
    config: dict[str, Any],
    issuer: Issuer,
    domain: Domain,
    mode: str,
) -> list[str]:
    """
    Build the lego argv for the given domain and mode.

    :param mode: ``"run"`` (issue new) or ``"renew"`` (lego decides).
    """
    argv = [
        config["lego_binary"],
        "--accept-tos",
        "--email",     issuer.email,
        "--server",    issuer.server,
        "--path",      str(config["state_dir"]),
        "--key-type",  config["key_type"],
    ]

    ctype = issuer.challenge.get("type")
    if ctype == "http":
        argv += ["--http", "--http.webroot", issuer.challenge["webroot"]]
    elif ctype == "dns":
        argv += ["--dns", issuer.challenge["provider"]]
    # else: rejected by the role's validate_issuers filter before we get here.

    if issuer.eab:
        argv += [
            "--eab",
            "--kid",  issuer.eab["kid"],
            "--hmac", issuer.eab["hmac_key"],
        ]

    for name in domain.all_names:
        argv += ["-d", name]

    if mode == "run":
        argv.append("run")
    else:
        argv += [
            "renew",
            "--days", str(config["renewal_days"]),
            "--no-random-sleep",  # the systemd timer applies its own jitter
        ]

    return argv


def build_lego_env(issuer: Issuer) -> dict[str, str]:
    """
    Compose the environment for the lego subprocess:

    * Current process env (PATH, HOME).
    * ``LEGO_CA_CERTIFICATES`` for internal-CA trust.
    * Per-challenge provider env (e.g. ``PDNS_API_URL``, ``PDNS_API_KEY``).
    """
    env = os.environ.copy()
    if issuer.ca_certificate:
        env["LEGO_CA_CERTIFICATES"] = issuer.ca_certificate
    provider_env = (issuer.challenge.get("env") or {}) if isinstance(issuer.challenge, dict) else {}
    for k, v in provider_env.items():
        env[str(k)] = str(v)
    return env


def run_lego(argv: list[str], env: dict[str, str]) -> tuple[int, str, str]:
    """Execute lego and capture (rc, stdout, stderr)."""
    log.debug("exec: %s", " ".join(argv))
    try:
        proc = subprocess.run(
            argv,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        return 127, "", f"lego binary not found: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


# ---------------------------------------------------------------------------
# Install + hooks
# ---------------------------------------------------------------------------

def _resolve_id(name_or_none: Optional[str], kind: str) -> Optional[int]:
    """Translate a user/group name to its numeric id, or None."""
    if name_or_none is None:
        return None
    import grp
    import pwd
    try:
        if kind == "user":
            return pwd.getpwnam(name_or_none).pw_uid
        return grp.getgrnam(name_or_none).gr_gid
    except KeyError:
        raise RuntimeError(f"{kind} {name_or_none!r} does not exist")


def install_cert(state_dir: Path, domain: Domain) -> None:
    """
    Copy lego-produced cert/key/ca to the configured destinations with
    the requested ownership and modes.

    Uses copy-via-temp + os.replace so a half-written file never appears
    at the destination (matters for webservers watching the file).
    """
    inst = domain.install
    owner_id = _resolve_id(inst.get("owner"), "user")
    group_id = _resolve_id(inst.get("group"), "group")

    sources_and_targets = [
        (cert_path(state_dir, domain),        inst.get("cert"), inst.get("cert_mode", "0644")),
        (key_path(state_dir, domain),         inst.get("key"),  inst.get("key_mode",  "0640")),
        (issuer_cert_path(state_dir, domain), inst.get("ca"),   inst.get("ca_mode",   "0644")),
    ]

    for src, target, mode in sources_and_targets:
        if target is None:
            continue
        if not src.is_file():
            raise RuntimeError(f"expected lego output missing: {src}")

        target_path = Path(target)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        tmp = target_path.with_suffix(target_path.suffix + ".tmp")
        shutil.copyfile(src, tmp)
        os.chmod(tmp, int(mode, 8))
        if owner_id is not None or group_id is not None:
            os.chown(
                tmp,
                owner_id if owner_id is not None else -1,
                group_id if group_id is not None else -1,
            )
        os.replace(tmp, target_path)
        log.info("installed %s", target_path)


def run_hooks(hooks: list[str], label: str) -> list[str]:
    """
    Execute a list of shell-string hooks sequentially.

    :returns: List of failure descriptions. Empty list = all succeeded.
    """
    failures: list[str] = []
    for cmd in hooks:
        log.debug("%s: %s", label, cmd)
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except Exception as exc:                  # noqa: BLE001
            failures.append(f"{label} {cmd!r}: {exc}")
            continue
        if proc.returncode != 0:
            failures.append(
                f"{label} {cmd!r} exited {proc.returncode}: "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
    return failures


# ---------------------------------------------------------------------------
# Per-domain orchestration
# ---------------------------------------------------------------------------

def process_domain(
    config: dict[str, Any],
    domain: Domain,
    issuer: Issuer,
    dry_run: bool,
) -> RenewalResult:
    """Handle one domain from check-status to post-hook."""
    log.info("=== %s (issuer=%s) ===", domain.domain, issuer.name)
    state_dir = Path(config["state_dir"])

    not_after_before = read_not_after(cert_path(state_dir, domain))
    mode = "run" if not_after_before is None else "renew"
    log.debug("mode=%s not_after_before=%s", mode, not_after_before)

    argv = build_lego_argv(config, issuer, domain, mode)
    env = build_lego_env(issuer)

    if dry_run:
        log.info("[dry-run] would exec: %s", " ".join(argv))
        return RenewalResult(domain.domain, "skipped", False)

    if issuer.ca_certificate and not Path(issuer.ca_certificate).is_file():
        return RenewalResult(
            domain.domain, "failed", False,
            error=f"ca_certificate not found: {issuer.ca_certificate}",
        )

    rc, stdout, stderr = run_lego(argv, env)
    if stdout:
        log.debug("lego stdout: %s", stdout.strip())
    if stderr:
        log.debug("lego stderr: %s", stderr.strip())

    if rc != 0:
        log.error("%s: lego failed (rc=%d): %s", domain.domain, rc, stderr.strip())
        return RenewalResult(
            domain.domain, "failed", False,
            error=f"lego rc={rc}: {stderr.strip() or stdout.strip()}",
        )

    not_after_after = read_not_after(cert_path(state_dir, domain))
    cert_changed = (
        not_after_before is None
        or (not_after_after is not None and not_after_after != not_after_before)
    )
    action = "issued" if not_after_before is None else (
        "renewed" if cert_changed else "skipped"
    )

    if not cert_changed:
        log.info("%s: no change (notAfter=%s)", domain.domain, not_after_after)
        return RenewalResult(domain.domain, action, False)

    # ---- cert changed → run hooks + install ------------------------------
    hook_failures: list[str] = []
    hook_failures += run_hooks(domain.pre_hook, "pre_hook")

    try:
        install_cert(state_dir, domain)
    except Exception as exc:                       # noqa: BLE001
        log.error("%s: install failed: %s", domain.domain, exc)
        return RenewalResult(
            domain.domain, "failed", True,
            hook_failures=hook_failures,
            error=f"install: {exc}",
        )

    hook_failures += run_hooks(domain.post_hook, "post_hook")

    if hook_failures:
        for f in hook_failures:
            log.error("%s: %s", domain.domain, f)

    log.info("%s: %s (notAfter=%s)", domain.domain, action, not_after_after)
    return RenewalResult(domain.domain, action, True, hook_failures=hook_failures)


# ---------------------------------------------------------------------------
# --list
# ---------------------------------------------------------------------------

def cmd_list(
    config: dict[str, Any],
    domains: list[Domain],
    as_json: bool,
) -> int:
    """Print the current status of every declared cert."""
    state_dir = Path(config["state_dir"])
    renewal_days = config["renewal_days"]
    now = dt.datetime.now(dt.timezone.utc)
    rows = []
    for d in domains:
        na = read_not_after(cert_path(state_dir, d))
        if na is None:
            status, days, na_str = "not-issued", None, "—"
        else:
            days = (na - now).days
            na_str = na.strftime("%Y-%m-%d %H:%M UTC")
            if days < 0:
                status = "EXPIRED"
            elif days < renewal_days:
                status = "renew-soon"
            else:
                status = "ok"
        rows.append({
            "domain":    d.domain,
            "issuer":    d.issuer,
            "not_after": na.isoformat() if na else None,
            "days_left": days,
            "status":    status,
        })

    if as_json:
        json.dump(rows, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0

    if not rows:
        print("No domains configured.")
        return 0

    fmt = "{domain:<35} {issuer:<20} {not_after:<22} {days_left:>9}  {status}"
    print(fmt.format(
        domain="DOMAIN", issuer="ISSUER", not_after="NOT_AFTER",
        days_left="DAYS_LEFT", status="STATUS",
    ))
    print("-" * 100)
    for r in rows:
        print(fmt.format(
            domain=r["domain"],
            issuer=r["issuer"],
            not_after=(r["not_after"] or "—")[:22],
            days_left=("—" if r["days_left"] is None else r["days_left"]),
            status=r["status"],
        ))
    return 0


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(level: str, silent: bool, logfile: Optional[str]) -> None:
    """
    Configure the package logger.

    * Console handler attached unless ``silent``.
    * File handler attached if ``logfile`` is given.
    * Level applied to both handlers.
    """
    log.setLevel(level)
    for h in list(log.handlers):
        log.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if not silent:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        log.addHandler(sh)

    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setFormatter(fmt)
        log.addHandler(fh)


# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------

class _Lock:
    """Exclusive flock on the lock-file path, releases on context exit."""

    def __init__(self, path: str):
        self.path = path
        self.fd: Optional[int] = None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            raise RuntimeError(
                f"another lego-renew run holds {self.path}"
            )
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lego-renew",
        description="Issue and renew TLS certificates via lego.",
    )
    p.add_argument("--config",
                   default="/etc/lego/renew.yml",
                   help="Path to the configuration file (default: %(default)s).")

    # Config-file overrides — None means "not given, leave config alone".
    p.add_argument("--lego-binary",
                   help="Path to the lego binary (overrides config).")
    p.add_argument("--state-dir",
                   help="Lego state directory (overrides config).")
    p.add_argument("--issuers-dir",
                   help="Directory containing issuer YAML files (overrides config).")
    p.add_argument("--domains-dir",
                   help="Directory containing domain YAML files (overrides config).")
    p.add_argument("--renewal-days", type=int,
                   help="Renew if cert expires within this many days (overrides config).")

    # Operations
    p.add_argument("--domain",
                   help="Process only this domain (default: all).")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would be done, perform no lego calls or hooks.")
    p.add_argument("--list", action="store_true",
                   help="List configured domains with cert status and exit.")
    p.add_argument("--json", action="store_true",
                   help="JSON output for --list.")

    # Logging
    p.add_argument("--log-level",
                   default="INFO",
                   choices=["DEBUG", "INFO", "WARN", "WARNING", "ERROR"],
                   help="Logger level (default: %(default)s).")
    p.add_argument("--logfile",
                   help="Append log records to this file in addition to stderr.")
    p.add_argument("--silent", action="store_true",
                   help="Do not log to stderr (file logging unaffected).")

    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    level = "WARNING" if args.log_level == "WARN" else args.log_level
    setup_logging(level, args.silent, args.logfile)

    try:
        config = load_config(Path(args.config) if args.config else None)
        config = apply_cli_overrides(config, args)
    except Exception as exc:                       # noqa: BLE001
        log.error("Configuration error: %s", exc)
        return 2

    log.debug("effective config: %s", config)

    try:
        issuers = load_issuers(Path(config["issuers_dir"]))
        domains = load_domains(Path(config["domains_dir"]))
    except Exception as exc:                       # noqa: BLE001
        log.error("Failed to load configuration: %s", exc)
        return 2

    if args.list:
        return cmd_list(config, domains, as_json=args.json)

    if args.domain:
        domains = [d for d in domains if d.domain == args.domain]
        if not domains:
            log.error("Domain %r not found in %s", args.domain, config["domains_dir"])
            return 2

    if not domains:
        log.info("No domains configured — nothing to do.")
        return 0

    try:
        lock = _Lock(config["lock_file"]).__enter__()
    except RuntimeError as exc:
        log.error("%s", exc)
        return 1

    try:
        results: list[RenewalResult] = []
        for d in domains:
            issuer = issuers.get(d.issuer)
            if issuer is None:
                log.error("%s: issuer %r not found", d.domain, d.issuer)
                results.append(RenewalResult(
                    d.domain, "failed", False,
                    error=f"unknown issuer {d.issuer!r}",
                ))
                continue
            try:
                results.append(process_domain(config, d, issuer, args.dry_run))
            except Exception as exc:               # noqa: BLE001
                log.exception("%s: unexpected error", d.domain)
                results.append(RenewalResult(
                    d.domain, "failed", False, error=str(exc),
                ))
    finally:
        lock.__exit__(None, None, None)

    return _summarise(results)


def _summarise(results: list[RenewalResult]) -> int:
    """Log a one-line summary, return 0 if everything ok else 1."""
    by_action: dict[str, int] = {}
    failed: list[str] = []
    for r in results:
        by_action[r.action] = by_action.get(r.action, 0) + 1
        if not r.ok:
            failed.append(r.domain)
    log.info(
        "summary: %s",
        " ".join(f"{k}={v}" for k, v in sorted(by_action.items())),
    )
    if failed:
        log.error("failures: %s", ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
