# -*- coding: utf-8 -*-
# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Admin token generation for the step-ca Admin API (x5c flow).

The Admin API authenticates clients with X5C bearer tokens — JWTs whose
JOSE header carries a certificate chain (`x5c`) signed by the CA's own
root. JWK provisioner tokens are not accepted on /admin/*.

Flow (mirrors step-cli internals):
    1. Pull the encrypted admin JWK from the public /provisioners endpoint.
    2. Decrypt it locally with the provisioner password (PBES2).
    3. Generate an ephemeral P-256 keypair and CSR for the admin subject.
    4. Sign a one-time token with the JWK and POST CSR+OTT to /1.0/sign.
       The CA returns leaf + intermediate (PEM).
    5. Sign admin JWTs with the ephemeral key, embedding the cert chain
       in the `x5c` JOSE header. Reuse the cert until shortly before it
       expires.

Implementation notes:
    * Both JWE decryption and JWS signing are done directly via the
      `cryptography` library — no JOSE wrapper. This avoids two real
      problems found during integration:
        - jwcrypto enforces a hard PBKDF2 iteration cap that step-ca's
          600_000 iterations exceed.
        - jwcrypto's high-level JWT API silently strips/rewrites custom
          header fields like `x5c`, producing a token that go-jose (which
          step-ca uses) cannot parse.
    * The ephemeral private key and cert chain live only in process memory.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import hashlib
import json
import os
import secrets
import time
from datetime import timezone

from ansible_collections.bodsch.certs.plugins.module_utils.step_ca.exceptions import (
    StepCAAuthError,
    StepCAConfigError,
)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    from cryptography.x509.oid import NameOID

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


SIGN_TOKEN_LIFETIME_SECONDS = 60
ADMIN_TOKEN_LIFETIME_SECONDS = 300
ADMIN_CERT_LIFETIME = "30m"
ADMIN_CERT_REFRESH_BUFFER = 60
PROVISIONERS_PAGE_LIMIT = 100
MIN_PBKDF2_ITERATIONS = 1000

# Map JWK curve names to cryptography curve objects.
_CURVE_MAP = {
    "P-256": (ec.SECP256R1, 32, "ES256"),
    "P-384": (ec.SECP384R1, 48, "ES384"),
    "P-521": (ec.SECP521R1, 66, "ES512"),
}

# Map alg → hash algorithm
_ALG_HASH = {
    "ES256": hashes.SHA256,
    "ES384": hashes.SHA384,
    "ES512": hashes.SHA512,
}


def _b64url_decode(data):
    """Base64url decode tolerant to missing padding."""
    if isinstance(data, str):
        data = data.encode("ascii")
    pad = b"=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_encode(data):
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class AdminTokenBuilder:
    """
    Build x5c-authenticated admin tokens for the step-ca Admin API.

    Stateful: caches the decrypted JWK private key, its public KID, the
    minted admin certificate chain, and the ephemeral private key for
    the lifetime of the instance. Reuse the same instance across multiple
    API calls in a single module run.
    """

    def __init__(
        self,
        ca_url,
        ca_root_path,
        provisioner_name,
        admin_subject,
        password,
        http_timeout=15,
    ):
        self._require_dependencies()

        self._ca_url = ca_url.rstrip("/")
        self._ca_root_path = ca_root_path
        self._provisioner_name = provisioner_name
        self._admin_subject = admin_subject
        self._password = (
            password if isinstance(password, bytes) else password.encode("utf-8")
        )
        self._http_timeout = http_timeout

        # JWK provisioner cache
        self._jwk_priv = None  # cryptography EC private key
        self._jwk_curve_size = 0  # bytes per coordinate (32 for P-256)
        self._jwk_alg = None  # "ES256" / "ES384" / "ES512"
        self._jwk_kid = None  # public KID from /provisioners

        # Ephemeral admin material cache
        self._admin_priv = None
        self._admin_x5c = None
        self._admin_cert_expiry = 0
        self._admin_cert_kid = None

    # ------------------------------------------------------------------ public

    def build(self, audience):
        """Return a compact-serialised x5c admin JWT for the given audience.

        The audience MUST be the exact request URL the token will be sent to —
        step-ca matches it against the Bearer-token's `aud` claim verbatim.
        Building a generic '/admin' audience and reusing it across endpoints
        fails because step-ca compares full paths.
        """
        self._ensure_admin_cert()
        return self._sign_admin_jwt(audience)

    # ------------------------------------------------------------ dependencies

    @staticmethod
    def _require_dependencies():
        missing = []
        if not HAS_CRYPTOGRAPHY:
            missing.append("cryptography")
        if not HAS_REQUESTS:
            missing.append("requests")
        if missing:
            raise StepCAAuthError(
                f"Missing Python dependencies: {', '.join(missing)}. "
                f"Install with: pip install {' '.join(missing)}"
            )

    # ------------------------------------------------------- admin cert flow

    def _ensure_admin_cert(self):
        now = int(time.time())
        if (
            self._admin_priv is not None
            and self._admin_cert_expiry > now + ADMIN_CERT_REFRESH_BUFFER
        ):
            return
        self._mint_admin_cert()

    def _mint_admin_cert(self):
        jwk_priv = self._get_jwk_signing_key()

        admin_priv = ec.generate_private_key(ec.SECP256R1())
        csr_pem = self._build_csr(admin_priv)
        ott = self._build_sign_token(jwk_priv)
        leaf_pem, intermediate_pem = self._post_sign(csr_pem, ott)

        self._admin_priv = admin_priv
        self._admin_x5c = [
            base64.b64encode(self._pem_to_der(leaf_pem)).decode("ascii"),
            base64.b64encode(self._pem_to_der(intermediate_pem)).decode("ascii"),
        ]

        leaf_cert = x509.load_pem_x509_certificate(leaf_pem.encode("utf-8"))

        # JWK thumbprint (RFC 7638) of the leaf's public key — same KID step-cli uses.
        self._admin_cert_kid = self._jwk_thumbprint(leaf_cert.public_key())

        if hasattr(leaf_cert, "not_valid_after_utc"):
            not_after = leaf_cert.not_valid_after_utc
        else:
            not_after = leaf_cert.not_valid_after.replace(tzinfo=timezone.utc)
        self._admin_cert_expiry = int(not_after.timestamp())

    @staticmethod
    def _jwk_thumbprint(public_key):
        """RFC 7638 JWK thumbprint of an EC public key."""
        numbers = public_key.public_numbers()
        curve_size = (public_key.curve.key_size + 7) // 8
        crv = {256: "P-256", 384: "P-384", 521: "P-521"}.get(
            public_key.curve.key_size, "P-256"
        )
        jwk_obj = {
            "crv": crv,
            "kty": "EC",
            "x": _b64url_encode(numbers.x.to_bytes(curve_size, "big")),
            "y": _b64url_encode(numbers.y.to_bytes(curve_size, "big")),
        }
        canonical = json.dumps(jwk_obj, separators=(",", ":"), sort_keys=True).encode()
        return _b64url_encode(hashlib.sha256(canonical).digest())

    def _build_csr(self, private_key):
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, self._admin_subject),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(self._admin_subject)]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def _build_sign_token(self, jwk_priv):
        now = int(time.time())
        claims = {
            "iss": self._provisioner_name,
            "aud": f"{self._ca_url}/1.0/sign",
            "sub": self._admin_subject,
            "sans": [self._admin_subject],
            "iat": now,
            "nbf": now,
            "exp": now + SIGN_TOKEN_LIFETIME_SECONDS,
            "jti": secrets.token_hex(16),
            "sha": self._root_fingerprint_hex(),
        }
        header = {
            "alg": self._jwk_alg,
            "kid": self._jwk_kid,
            "typ": "JWT",
        }
        return self._sign_jws(
            header, claims, jwk_priv, self._jwk_alg, self._jwk_curve_size
        )

    def _post_sign(self, csr_pem, ott):
        url = f"{self._ca_url}/1.0/sign"
        body = {"csr": csr_pem, "ott": ott, "notAfter": ADMIN_CERT_LIFETIME}
        try:
            resp = requests.post(
                url,
                json=body,
                verify=self._ca_root_path,
                timeout=self._http_timeout,
            )
        except requests.RequestException as exc:
            raise StepCAAuthError(f"POST {url} failed: {exc}") from exc

        if resp.status_code >= 400:
            raise StepCAAuthError(
                f"step-ca rejected sign request ({resp.status_code}): {resp.text}"
            )

        data = resp.json()
        leaf = data.get("crt")
        intermediate = data.get("ca")
        if not leaf or not intermediate:
            raise StepCAAuthError(f"/1.0/sign response missing crt/ca: {data}")
        return leaf, intermediate

    # ------------------------------------------------------------ JWK material

    def _get_jwk_signing_key(self):
        if self._jwk_priv is not None:
            return self._jwk_priv

        encrypted_key, public_kid = self._fetch_provisioner_material()
        plaintext = self._decrypt_jwe(encrypted_key)

        try:
            jwk_dict = json.loads(plaintext.decode("utf-8"))
        except ValueError as exc:
            raise StepCAAuthError(f"Decrypted payload is not JSON: {exc}") from exc

        self._jwk_priv, self._jwk_curve_size, self._jwk_alg = self._jwk_to_ec_key(
            jwk_dict
        )
        self._jwk_kid = public_kid
        return self._jwk_priv

    @staticmethod
    def _jwk_to_ec_key(jwk_dict):
        """Reconstruct a cryptography EC private key from a JWK dict."""
        if jwk_dict.get("kty") != "EC":
            raise StepCAAuthError(
                f"Unsupported JWK kty: {jwk_dict.get('kty')!r} (expected 'EC')"
            )
        crv = jwk_dict.get("crv")
        if crv not in _CURVE_MAP:
            raise StepCAAuthError(f"Unsupported JWK curve: {crv!r}")
        curve_cls, coord_size, default_alg = _CURVE_MAP[crv]
        alg = jwk_dict.get("alg", default_alg)

        try:
            x = int.from_bytes(_b64url_decode(jwk_dict["x"]), "big")
            y = int.from_bytes(_b64url_decode(jwk_dict["y"]), "big")
            d = int.from_bytes(_b64url_decode(jwk_dict["d"]), "big")
        except KeyError as exc:
            raise StepCAAuthError(f"JWK is missing required EC field: {exc}") from exc

        priv = ec.EllipticCurvePrivateNumbers(
            private_value=d,
            public_numbers=ec.EllipticCurvePublicNumbers(x, y, curve_cls()),
        ).private_key()
        return priv, coord_size, alg

    def _fetch_provisioner_material(self):
        url = f"{self._ca_url}/provisioners"
        cursor = ""
        while True:
            params = {"limit": PROVISIONERS_PAGE_LIMIT}
            if cursor:
                params["cursor"] = cursor
            try:
                resp = requests.get(
                    url,
                    params=params,
                    verify=self._ca_root_path,
                    timeout=self._http_timeout,
                )
                resp.raise_for_status()
            except requests.RequestException as exc:
                raise StepCAConfigError(f"Failed to query {url}: {exc}") from exc

            data = resp.json()
            for prov in data.get("provisioners", []):
                if (
                    prov.get("name") == self._provisioner_name
                    and prov.get("type", "").upper() == "JWK"
                ):
                    encrypted = prov.get("encryptedKey")
                    if not encrypted:
                        raise StepCAConfigError(
                            f"Provisioner '{self._provisioner_name}' has no encryptedKey"
                        )
                    public_kid = (prov.get("key") or {}).get("kid", "")
                    if not public_kid:
                        raise StepCAConfigError(
                            f"Provisioner '{self._provisioner_name}' has no public KID"
                        )
                    return encrypted, public_kid

            cursor = data.get("nextCursor") or ""
            if not cursor:
                break

        raise StepCAConfigError(
            f"No JWK provisioner named '{self._provisioner_name}' found via {url}"
        )

    def _decrypt_jwe(self, serialized):
        """
        Decrypt step-ca's encryptedKey JWE.

        Algorithms used by step-ca:
            alg = PBES2-HS256+A128KW   (RFC 7518 §4.8)
            enc = A256GCM              (RFC 7518 §5.3)
        """
        parts = serialized.split(".")
        if len(parts) != 5:
            raise StepCAAuthError("Invalid JWE compact serialization")

        header_b64, ek_b64, iv_b64, ct_b64, tag_b64 = parts
        try:
            header = json.loads(_b64url_decode(header_b64))
        except ValueError as exc:
            raise StepCAAuthError(f"Invalid JWE header: {exc}") from exc

        alg = header.get("alg")
        enc = header.get("enc")
        if alg != "PBES2-HS256+A128KW":
            raise StepCAAuthError(f"Unsupported JWE alg: {alg!r}")
        if enc != "A256GCM":
            raise StepCAAuthError(f"Unsupported JWE enc: {enc!r}")

        try:
            p2s_raw = _b64url_decode(header["p2s"])
            p2c = int(header["p2c"])
        except (KeyError, ValueError, TypeError) as exc:
            raise StepCAAuthError(f"Malformed PBES2 header: {exc}") from exc

        if p2c < MIN_PBKDF2_ITERATIONS:
            raise StepCAAuthError(f"PBKDF2 iteration count suspiciously low: {p2c}")

        salt = alg.encode("utf-8") + b"\x00" + p2s_raw
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            iterations=p2c,
        )
        kek = kdf.derive(self._password)

        try:
            cek = aes_key_unwrap(kek, _b64url_decode(ek_b64))
        except Exception as exc:
            raise StepCAAuthError(
                f"AES key unwrap failed — wrong provisioner password? ({exc})"
            ) from exc

        iv = _b64url_decode(iv_b64)
        ct = _b64url_decode(ct_b64)
        tag = _b64url_decode(tag_b64)
        aad = header_b64.encode("ascii")

        try:
            return AESGCM(cek).decrypt(iv, ct + tag, aad)
        except Exception as exc:
            raise StepCAAuthError(f"AES-GCM decryption failed: {exc}") from exc

    # -------------------------------------------------- final admin token

    def _sign_admin_jwt(self, audience):
        now = int(time.time())
        claims = {
            "iss": "step-admin-client/1.0",  # <-- step-cli's hard-coded issuer
            "aud": audience,  # <-- per-request full URL
            "sub": self._admin_subject,
            "iat": now,
            "nbf": now,
            "exp": now + ADMIN_TOKEN_LIFETIME_SECONDS,
            "jti": secrets.token_hex(32),  # step-cli uses 256-bit jti
        }
        header = {
            "alg": "ES256",
            "kid": self._admin_cert_kid,  # <-- public-key thumbprint of admin cert
            "typ": "JWT",
            "x5c": self._admin_x5c,
        }
        return self._sign_jws(header, claims, self._admin_priv, "ES256", 32)

    # ------------------------------------------------------------- JWS signing

    @staticmethod
    def _sign_jws(header, payload, private_key, alg, coord_size):
        """
        Produce a JWS Compact Serialization for an EC private key.

        RFC 7515 §3.1:
            BASE64URL(UTF8(JWS Protected Header)) || '.'
                || BASE64URL(JWS Payload) || '.'
                || BASE64URL(JWS Signature)

        For ECDSA, the signature is the concatenation of R and S as
        unsigned big-endian integers, each left-padded to the curve's
        coordinate size (P-256 → 32 bytes, RFC 7518 §3.4).
        """
        hash_cls = _ALG_HASH.get(alg)
        if hash_cls is None:
            raise StepCAAuthError(f"Unsupported JWS alg: {alg!r}")

        # Compact, deterministic JSON — no whitespace.
        header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
        payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        header_b64 = _b64url_encode(header_json)
        payload_b64 = _b64url_encode(payload_json)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        der_sig = private_key.sign(signing_input, ec.ECDSA(hash_cls()))
        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(coord_size, "big") + s.to_bytes(coord_size, "big")
        sig_b64 = _b64url_encode(raw_sig)

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    # ------------------------------------------------------------------ utils

    @staticmethod
    def _pem_to_der(pem_str):
        cert = x509.load_pem_x509_certificate(pem_str.encode("utf-8"))
        return cert.public_bytes(serialization.Encoding.DER)

    def _root_fingerprint_hex(self):
        if not os.path.exists(self._ca_root_path):
            raise StepCAConfigError(
                f"Root CA certificate not found: {self._ca_root_path}"
            )
        with open(self._ca_root_path, "rb") as f:
            data = f.read()
        try:
            cert = x509.load_pem_x509_certificate(data)
        except ValueError:
            cert = x509.load_der_x509_certificate(data)
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()
