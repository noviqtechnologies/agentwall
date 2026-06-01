#!/usr/bin/env python3
"""
Mock OIDC Provider — FR-203 Developer Stack

Serves a minimal OpenID Connect provider for local development and CI:
  - GET /.well-known/openid-configuration   → OIDC discovery doc
  - GET /oauth2/default/v1/keys             → JWKS endpoint
  - GET /token?sub=<sub>&aud=<aud>          → Issues a signed JWT for testing

Usage:
    python3 mock_oidc.py [--port 8081]

The RSA key pair is generated fresh on each start. Use /token to obtain
valid Bearer tokens for manual and integration testing.
"""

import argparse
import base64
import json
import time
import struct
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# ──────────────────────────────────────────────────────────────────────────────
# Key generation using cryptography library (fallback to static demo key)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    import jwt as pyjwt

    _private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    _public_key = _private_key.public_key()

    _private_pem = _private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    pub_numbers = _public_key.public_key().public_numbers() if hasattr(_public_key, 'public_key') else _public_key.public_numbers()

    def _int_to_base64url(n):
        byte_len = (n.bit_length() + 7) // 8
        b = n.to_bytes(byte_len, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    _KID = "mock-key-001"
    _N_B64 = _int_to_base64url(pub_numbers.n)
    _E_B64 = _int_to_base64url(pub_numbers.e)
    _CRYPTO_AVAILABLE = True

except ImportError:
    _CRYPTO_AVAILABLE = False
    _KID = "mock-key-001"
    # Static demo key (2048-bit RSA, for testing only — NOT secret)
    _N_B64 = (
        "udhbe1QgN8OIKg2CTLUctcCzszFAtY19k04MNrqv_Bxz9EudGdRlFnRP62y6nj9_"
        "N0w7VGe3uHxwggBSR0lbTfN0AUzHkFn_tFS_B24wSYJZHqxxQ2LwlaaB52S9iZhf"
        "5edPBuUKkugLjMEusXY3CQQtPvITzFpEa0FzJgUQzIo0M4f4QX1QVe4ufIt-LxqP"
        "K8bBrSjoEs2wosUQEVd_Zua2Ho37gL7PUCXTxgrWwhrCNrl4NZcZQBBrC_jC_ArS"
        "TNbwkGOx7Mzv6BdfIGUlvEYTaYa-MfRRG7FAnBC9SqibsMj5uXRrsTCQ754eF9Kq"
        "pj_ZL6ZZaFLdT3BATCAnKw"
    )
    _E_B64 = "AQAB"
    print("WARNING: 'cryptography' and 'pyjwt' packages not found.", file=sys.stderr)
    print("  Install with: pip install cryptography pyjwt", file=sys.stderr)
    print("  Running in JWKS-only mode (token generation disabled).", file=sys.stderr)


PORT = 8081
ISSUER = f"http://localhost:{PORT}"
AUDIENCE = "agentwall"


def build_jwks():
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": _KID,
                "n": _N_B64,
                "e": _E_B64,
            }
        ]
    }


def build_oidc_config():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth2/default/v1/authorize",
        "token_endpoint": f"{ISSUER}/oauth2/default/v1/token",
        "jwks_uri": f"{ISSUER}/oauth2/default/v1/keys",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def issue_token(sub: str, aud: str, exp_seconds: int = 3600) -> str:
    if not _CRYPTO_AVAILABLE:
        return "ERROR: cryptography/pyjwt not installed. Run: pip install cryptography pyjwt"
    now = int(time.time())
    payload = {
        "sub": sub,
        "aud": aud,
        "iss": ISSUER,
        "iat": now,
        "exp": now + exp_seconds,
    }
    token = pyjwt.encode(
        payload,
        _private_pem,
        algorithm="RS256",
        headers={"kid": _KID},
    )
    return token


class OIDCHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[mock-oidc] {self.address_string()} - {format % args}")

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/.well-known/openid-configuration":
            self.send_json(build_oidc_config())

        elif path == "/oauth2/default/v1/keys":
            self.send_json(build_jwks())

        elif path == "/token":
            sub = params.get("sub", ["agent-dev"])[0]
            aud = params.get("aud", [AUDIENCE])[0]
            exp = int(params.get("exp", ["3600"])[0])
            token = issue_token(sub, aud, exp)
            self.send_json({"access_token": token, "token_type": "Bearer", "expires_in": exp})

        elif path == "/health":
            self.send_json({"status": "ok", "issuer": ISSUER})

        else:
            self.send_json({"error": "not_found"}, status=404)


def main():
    global PORT, ISSUER, AUDIENCE
    parser = argparse.ArgumentParser(description="Mock OIDC Provider for AgentWall local development")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--audience", default="agentwall")
    args = parser.parse_args()

    PORT = args.port
    ISSUER = f"http://localhost:{PORT}"
    AUDIENCE = args.audience

    server = HTTPServer(("0.0.0.0", PORT), OIDCHandler)
    print(f"[mock-oidc] Listening on http://0.0.0.0:{PORT}")
    print(f"[mock-oidc] Issuer:   {ISSUER}")
    print(f"[mock-oidc] Audience: {AUDIENCE}")
    print(f"[mock-oidc] JWKS:     {ISSUER}/oauth2/default/v1/keys")
    print(f"[mock-oidc] Token:    GET {ISSUER}/token?sub=my-agent&aud={AUDIENCE}")
    print(f"[mock-oidc] KID:      {_KID}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock-oidc] Stopped.")


if __name__ == "__main__":
    main()
