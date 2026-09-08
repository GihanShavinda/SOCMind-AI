"""Minimal TOTP (RFC 6238) using only the standard library — no extra dependency
(FR-2 MFA). Compatible with Google Authenticator, Authy, Microsoft Authenticator.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def generate_secret() -> str:
    """Return a base32 secret suitable for authenticator apps."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    # Pad base32 back to a multiple of 8 for decoding.
    padded = secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify(secret_b32: str, code: str, window: int = 1, period: int = 30) -> bool:
    """Verify a TOTP code, allowing +/- `window` steps for clock drift."""
    if not code or not code.isdigit():
        return False
    counter = int(time.time() // period)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_b32, counter + drift), code):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str, issuer: str = "SOCMind AI") -> str:
    """otpauth:// URI to paste into (or QR-encode for) an authenticator app."""
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30")
