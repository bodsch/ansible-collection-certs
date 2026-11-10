# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Filter plugin: validate_certificates.

Validates a list of lego TLS certificate definitions against the
schema expected by the C(bodsch.certs.lego) role and returns a list
of human-readable error strings. An empty list means everything is
valid.

This replaces a per-item ``assert`` loop in tasks, gives a single
pass over the data (cross-item checks like duplicate-domain
detection become trivial), and reports all problems at once instead
of failing on the first.
"""

import re

_DOMAIN_RE = re.compile(r"^(\*\.)?[a-zA-Z0-9_][a-zA-Z0-9._-]*$")
_KEY_TYPES = ("rsa2048", "rsa3072", "rsa4096", "rsa8192", "ec256", "ec384")
_INSTALL_PATHS = ("cert", "fullchain", "leaf", "key", "ca", "combined")


def _is_string(value):
    """True iff *value* is a non-empty string."""
    return isinstance(value, str) and value != ""


def _is_list_or_none(value):
    """True iff *value* is a list, None, or absent."""
    return value is None or isinstance(value, list)


def _is_string_or_list(value):
    """True iff *value* is a string, a list, or None."""
    return value is None or isinstance(value, (str, list))


def _check_install(install, prefix, errors):
    """Validate the optional ``install`` sub-dict. Mutates *errors* in place."""
    if install is None:
        return
    if not isinstance(install, dict):
        errors.append(f"{prefix}: 'install' must be a mapping")
        return

    unknown = set(install) - set(_INSTALL_PATHS) - {
        "owner", "group", "cert_mode", "key_mode", "ca_mode"
    }
    if unknown:
        errors.append(f"{prefix}.install: unknown keys {sorted(unknown)}")

    for optional_str in _INSTALL_PATHS + ("owner", "group"):
        value = install.get(optional_str)
        if value is not None and not _is_string(value):
            errors.append(f"{prefix}.install: '{optional_str}' must be a string if set")

    if install.get("key") is None and any(install.get(k) for k in ("cert", "fullchain", "leaf")):
        errors.append(f"{prefix}.install: 'key' is required when a certificate path is set")

    for mode_key in ("cert_mode", "key_mode", "ca_mode"):
        value = install.get(mode_key)
        if value is None:
            continue
        if not (isinstance(value, str) and re.match(r"^[0-7]{3,4}$", value)):
            errors.append(
                f"{prefix}.install: '{mode_key}' must be an octal mode string "
                f"like '0644', got {value!r}"
            )


def _check_challenge(challenge, names, prefix, errors):
    """Validate the optional per-certificate ``challenge`` override."""
    if challenge is None:
        return
    if not isinstance(challenge, dict):
        errors.append(f"{prefix}: 'challenge' must be a mapping if set")
        return
    c_type = challenge.get("type")
    if c_type is not None and c_type not in ("dns", "http"):
        errors.append(f"{prefix}.challenge: 'type' must be 'dns' or 'http', got {c_type!r}")
    if c_type == "dns" and not _is_string(challenge.get("provider")):
        errors.append(f"{prefix}.challenge: 'provider' is required when type is 'dns'")
    if c_type == "http":
        wildcards = [n for n in names if isinstance(n, str) and n.startswith("*.")]
        if wildcards:
            errors.append(f"{prefix}.challenge: wildcards need the dns challenge: {wildcards}")
    env = challenge.get("env")
    if env is not None and not isinstance(env, dict):
        errors.append(f"{prefix}.challenge: 'env' must be a mapping if set")


def _check_restarts(restarts, prefix, errors):
    if restarts is None:
        return
    for idx, entry in enumerate(restarts if isinstance(restarts, list) else [restarts]):
        if isinstance(entry, str) and entry:
            continue
        if isinstance(entry, dict) and _is_string(entry.get("service")):
            if entry.get("action", "restart") not in ("restart", "reload"):
                errors.append(f"{prefix}.restarts[{idx}]: action must be 'restart' or 'reload'")
            continue
        errors.append(
            f"{prefix}.restarts[{idx}]: must be a service name or a mapping with 'service'"
        )


def validate_certificates(
    certificates, known_issuers=None, default_issuer=None, var_name="lego_tls_certificates"
):
    """
    Return a list of validation errors for the given certificate list.

    :param certificates: The user-supplied certificate list.
    :param known_issuers: Optional list of issuer dicts (each with a
        ``name`` key). Used to check that each certificate's ``issuer``
        references a defined issuer. Pass ``[]`` or ``None`` to skip
        that check.
    :param default_issuer: Issuer used for certificates without ``issuer``.
        If empty, every certificate must name an issuer.
    :param var_name: Variable name used as prefix in the error messages.
    :returns: List of human-readable error strings. Empty if valid.
    """
    errors = []

    if certificates is None:
        return errors
    if not isinstance(certificates, list):
        return [
            f"{var_name} must be a list, got {type(certificates).__name__}"
        ]

    known_issuer_names = {
        i.get("name") for i in (known_issuers or []) if isinstance(i, dict)
    }
    seen_domains = set()

    for idx, cert in enumerate(certificates):
        prefix = f"{var_name}[{idx}]"

        if not isinstance(cert, dict):
            errors.append(f"{prefix}: must be a mapping, got {type(cert).__name__}")
            continue

        # ---- domain -------------------------------------------------
        domain = cert.get("domain")
        if not _is_string(domain):
            errors.append(f"{prefix}: missing or non-string 'domain'")
            continue
        if not _DOMAIN_RE.match(domain):
            errors.append(
                f"{prefix}: domain {domain!r} contains invalid characters "
                "(allowed: optional '*.' prefix, then [a-zA-Z0-9._-])"
            )
        if domain in seen_domains:
            errors.append(f"{prefix}: duplicate domain {domain!r}")
        seen_domains.add(domain)

        # ---- issuer -------------------------------------------------
        issuer = cert.get("issuer")
        if issuer in (None, "") and _is_string(default_issuer):
            issuer = default_issuer
        if not _is_string(issuer):
            errors.append(f"{prefix}: missing or non-string 'issuer'")
        elif known_issuer_names and issuer not in known_issuer_names:
            errors.append(
                f"{prefix}: issuer {issuer!r} is not defined in the issuers "
                f"(known: {sorted(known_issuer_names)})"
            )

        # ---- subdomains --------------------------------------------
        subdomains = cert.get("subdomains")
        if isinstance(subdomains, str):
            subdomains = [subdomains]
        if not _is_list_or_none(subdomains):
            errors.append(
                f"{prefix}: 'subdomains' must be a list if set, got "
                f"{type(subdomains).__name__}"
            )
        elif isinstance(subdomains, list):
            for s_idx, sub in enumerate(subdomains):
                if sub is None:
                    continue  # tolerate null entries
                if not _is_string(sub):
                    errors.append(
                        f"{prefix}.subdomains[{s_idx}]: must be a string, got "
                        f"{type(sub).__name__}"
                    )
                elif not _DOMAIN_RE.match(sub):
                    errors.append(
                        f"{prefix}.subdomains[{s_idx}]: {sub!r} contains invalid "
                        "characters"
                    )

        # ---- key type / challenge / restarts ------------------------
        key_type = cert.get("key_type")
        if key_type not in (None, "") and key_type not in _KEY_TYPES:
            errors.append(f"{prefix}: key_type must be one of {list(_KEY_TYPES)}, got {key_type!r}")

        names = [domain] + (subdomains if isinstance(subdomains, list) else [])
        _check_challenge(cert.get("challenge"), names, prefix, errors)
        _check_restarts(cert.get("restarts"), prefix, errors)

        # ---- install -----------------------------------------------
        _check_install(cert.get("install"), prefix, errors)

        # ---- hooks --------------------------------------------------
        for hook_key in ("pre_hook", "post_hook", "cleanup_hook"):
            hook = cert.get(hook_key)
            if hook is None:
                continue
            if not _is_string_or_list(hook):
                errors.append(
                    f"{prefix}: '{hook_key}' must be a string or list of strings, "
                    f"got {type(hook).__name__}"
                )
                continue
            if isinstance(hook, list):
                for h_idx, entry in enumerate(hook):
                    if not _is_string(entry):
                        errors.append(
                            f"{prefix}.{hook_key}[{h_idx}]: must be a non-empty string"
                        )

    return errors


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self):
        return {
            "validate_lego_certificates": validate_certificates,
        }
