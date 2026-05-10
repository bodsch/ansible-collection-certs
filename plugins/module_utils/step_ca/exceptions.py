# -*- coding: utf-8 -*-
# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Exception hierarchy for the step_ca module utilities.

All exceptions raised by this collection's module_utils derive from
:class:`StepCAError`. Module entry points (the AnsibleModule classes)
catch :class:`StepCAError` once at the top level and translate it into
``module.fail_json`` so the user sees a clean, single-line error rather
than a Python traceback.

The hierarchy is intentionally shallow:

* :class:`StepCAError` — root, never raised directly.
* :class:`StepCAAuthError` — anything related to credential handling:
  reading the password file, decrypting the JWK, signing JWTs,
  obtaining the ephemeral admin certificate.
* :class:`StepCAAPIError` — non-2xx responses from the step-ca HTTPS API.
  Carries ``status_code`` and parsed ``payload`` so callers can branch
  on specific errors (most commonly 404 for "does not exist").
* :class:`StepCAConfigError` — missing or malformed CA-side data the
  collection depends on (root certificate file, expected JWK provisioner,
  unexpected JSON shape from a public endpoint).
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class StepCAError(Exception):
    """
    Base class for all step-ca module utility errors.

    Never raised directly — always one of the more specific subclasses.
    Used by callers to catch the entire family with a single ``except``.
    """


class StepCAAuthError(StepCAError):
    """
    Raised when admin authentication or token generation fails.

    Typical triggers:
        * Missing Python dependencies (``cryptography``, ``requests``).
        * Wrong provisioner password (AES key unwrap fails).
        * Unsupported JWK or JWE algorithm in the provisioner record.
        * Server rejecting the one-time token at ``/1.0/sign``.
    """


class StepCAAPIError(StepCAError):
    """
    Raised when the step-ca Admin API returns a non-2xx response.

    The HTTP status code and parsed JSON payload (if any) are stored on
    the exception instance so callers can react to specific cases —
    most notably HTTP 404 to detect "resource does not exist" without
    needing a separate "exists" probe.

    :ivar status_code: HTTP status code (int) or ``None`` if the request
        failed before a response was received.
    :ivar payload:     Parsed JSON body of the response (dict) or
        ``None``. May contain ``message`` and ``detail`` keys following
        step-ca's error envelope.
    """

    def __init__(self, message, status_code=None, payload=None):
        super(StepCAAPIError, self).__init__(message)
        self.status_code = status_code
        self.payload = payload


class StepCAConfigError(StepCAError):
    """
    Raised when CA-side data required by the module cannot be read or
    parsed.

    Typical triggers:
        * The root CA certificate file does not exist or is unreadable.
        * The named JWK admin provisioner is not registered with the CA.
        * A response from a public endpoint has an unexpected shape
          (e.g. missing ``encryptedKey`` for a JWK provisioner).
    """
