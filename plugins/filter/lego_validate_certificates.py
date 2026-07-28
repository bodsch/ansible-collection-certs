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

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


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
    """Validate the ``install`` sub-dict. Mutates *errors* in place."""
    if install is None or not isinstance(install, dict):
        errors.append(f"{prefix}: 'install' must be a mapping")
        return

    for required in ("cert", "key"):
        value = install.get(required)
        if not _is_string(value):
            errors.append(
                f"{prefix}.install: missing or non-string '{required}'"
            )

    for optional_str in ("ca", "owner", "group"):
        value = install.get(optional_str)
        if value is not None and not _is_string(value):
            errors.append(
                f"{prefix}.install: '{optional_str}' must be a string if set"
            )

    for mode_key in ("cert_mode", "key_mode", "ca_mode"):
        value = install.get(mode_key)
        if value is None:
            continue
        if not (isinstance(value, str) and re.match(r"^[0-7]{3,4}$", value)):
            errors.append(
                f"{prefix}.install: '{mode_key}' must be an octal mode string "
                f"like '0644', got {value!r}"
            )


def validate_certificates(certificates, known_issuers=None):
    """
    Return a list of validation errors for the given certificate list.

    :param certificates: The user-supplied ``lego_tls_certificates`` list.
    :param known_issuers: Optional list of issuer dicts (each with a
        ``name`` key). Used to check that each certificate's ``issuer``
        references a defined issuer. Pass ``[]`` or ``None`` to skip
        that check.
    :returns: List of human-readable error strings. Empty if valid.
    """
    errors = []

    if certificates is None:
        return errors
    if not isinstance(certificates, list):
        return [f"lego_tls_certificates must be a list, got {type(certificates).__name__}"]

    known_issuer_names = {
        i.get("name") for i in (known_issuers or []) if isinstance(i, dict)
    }
    seen_domains = set()

    for idx, cert in enumerate(certificates):
        prefix = f"lego_tls_certificates[{idx}]"

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
                "(allowed: [a-zA-Z0-9._-], must start with alphanumeric)"
            )
        if domain in seen_domains:
            errors.append(f"{prefix}: duplicate domain {domain!r}")
        seen_domains.add(domain)

        # ---- issuer -------------------------------------------------
        issuer = cert.get("issuer")
        if not _is_string(issuer):
            errors.append(f"{prefix}: missing or non-string 'issuer'")
        elif known_issuer_names and issuer not in known_issuer_names:
            errors.append(
                f"{prefix}: issuer {issuer!r} is not defined in lego_issuers "
                f"(known: {sorted(known_issuer_names)})"
            )

        # ---- subdomains --------------------------------------------
        subdomains = cert.get("subdomains")
        if not _is_list_or_none(subdomains):
            errors.append(
                f"{prefix}: 'subdomains' must be a list if set, got "
                f"{type(subdomains).__name__}"
            )
        elif isinstance(subdomains, list):
            for s_idx, sub in enumerate(subdomains):
                if sub is None:
                    continue                              # tolerate null entries
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

        # ---- install -----------------------------------------------
        _check_install(cert.get("install"), prefix, errors)

        # ---- hooks --------------------------------------------------
        for hook_key in ("pre_hook", "post_hook"):
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
