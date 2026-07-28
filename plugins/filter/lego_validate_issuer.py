# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Filter plugin: validate_issuers.

Validates a list of ACME issuer definitions and returns a list of
human-readable error strings. An empty list means everything is valid.
"""



import re

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_SERVER_RE = re.compile(r"^https://")


def _is_string(value):
    return isinstance(value, str) and value != ""


def _check_challenge(challenge, prefix, errors):
    """Validate the ``challenge`` sub-dict."""
    if challenge is None or not isinstance(challenge, dict):
        errors.append(f"{prefix}: 'challenge' must be a mapping")
        return

    c_type = challenge.get("type")
    if c_type not in ("dns", "http"):
        errors.append(
            f"{prefix}.challenge: 'type' must be 'dns' or 'http', "
            f"got {c_type!r}"
        )
        return

    if c_type == "dns":
        if not _is_string(challenge.get("provider")):
            errors.append(
                f"{prefix}.challenge: 'provider' is required when type is 'dns'"
            )
        env = challenge.get("env")
        if env is not None and not isinstance(env, dict):
            errors.append(
                f"{prefix}.challenge: 'env' must be a mapping if set"
            )
        resolvers = challenge.get("resolvers")
        if resolvers is not None and (
            not isinstance(resolvers, list)
            or not all(_is_string(r) for r in resolvers)
        ):
            errors.append(
                f"{prefix}.challenge: 'resolvers' must be a list of "
                f"non-empty strings if set"
            )
        _check_propagation(challenge.get("propagation"), prefix, errors)

    if c_type == "http":
        if not _is_string(challenge.get("webroot")):
            errors.append(
                f"{prefix}.challenge: 'webroot' is required when type is 'http'"
            )


def _check_propagation(propagation, prefix, errors):
    """Validate the optional ``challenge.propagation`` sub-dict."""
    if propagation is None:
        return
    if not isinstance(propagation, dict):
        errors.append(
            f"{prefix}.challenge: 'propagation' must be a mapping if set"
        )
        return
    for bool_key in ("disable_ans", "rns"):
        if bool_key in propagation and not isinstance(propagation[bool_key], bool):
            errors.append(
                f"{prefix}.challenge.propagation: '{bool_key}' must be a boolean"
            )
    if "wait" in propagation and not _is_string(propagation["wait"]):
        errors.append(
            f"{prefix}.challenge.propagation: 'wait' must be a non-empty "
            f"string (e.g. '15s')"
        )


def _check_eab(eab, prefix, errors):
    """Validate the optional ``eab`` sub-dict."""
    if eab is None:
        return
    if not isinstance(eab, dict):
        errors.append(f"{prefix}: 'eab' must be a mapping if set")
        return
    for required in ("kid", "hmac_key"):
        if not _is_string(eab.get(required)):
            errors.append(
                f"{prefix}.eab: missing or non-string '{required}'"
            )


def validate_issuers(issuers):
    """
    Return a list of validation errors for the given issuer list.

    :param issuers: The user-supplied ``lego_issuers`` list.
    :returns: List of human-readable error strings. Empty if valid.
    """
    errors = []

    if issuers is None:
        return errors
    if not isinstance(issuers, list):
        return [f"lego_issuers must be a list, got {type(issuers).__name__}"]

    seen_names = set()

    for idx, issuer in enumerate(issuers):
        prefix = f"lego_issuers[{idx}]"

        if not isinstance(issuer, dict):
            errors.append(f"{prefix}: must be a mapping, got {type(issuer).__name__}")
            continue

        name = issuer.get("name")
        if not _is_string(name):
            errors.append(f"{prefix}: missing or non-string 'name'")
        elif not _NAME_RE.match(name):
            errors.append(
                f"{prefix}: name {name!r} must match ^[a-z0-9][a-z0-9_-]*$"
            )
        elif name in seen_names:
            errors.append(f"{prefix}: duplicate name {name!r}")
        else:
            seen_names.add(name)

        server = issuer.get("server")
        if not _is_string(server):
            errors.append(f"{prefix}: missing or non-string 'server'")
        elif not _SERVER_RE.match(server):
            errors.append(
                f"{prefix}: server {server!r} must start with 'https://'"
            )

        if not _is_string(issuer.get("email")):
            errors.append(f"{prefix}: missing or non-string 'email'")

        ca_cert = issuer.get("ca_certificate")
        if ca_cert is not None and not _is_string(ca_cert):
            errors.append(
                f"{prefix}: 'ca_certificate' must be a string if set"
            )

        _check_challenge(issuer.get("challenge"), prefix, errors)
        _check_eab(issuer.get("eab"), prefix, errors)

    return errors


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self):
        return {
            "validate_lego_issuers": validate_issuers,
        }
