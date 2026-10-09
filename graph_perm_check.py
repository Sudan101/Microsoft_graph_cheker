#!/usr/bin/env python3
"""
graph_perm_check.py

Authenticate to Microsoft Graph using the OAuth2 client-credentials flow
(tenant ID + client ID + client secret) and report which application
permissions ("roles") the resulting access token actually carries.

This is a pure-Python / cross-platform reimplementation of the
"what Graph permissions does this app registration grant" check that
tools like GraphRunner's Get-AzureAppTokens + Invoke-CheckAccess, or
GraphRobber's "App Secret Auth", perform on Windows.

Only needs `requests` (stdlib does the JWT decode, no PyJWT required).

Usage:
    python3 graph_perm_check.py -t <tenant_id_or_domain> -c <client_id> -s <client_secret>
    python3 graph_perm_check.py -t <tenant> -c <client_id> -s <client_secret> --whoami
    python3 graph_perm_check.py -t <tenant> -c <client_id> --cert mycert.pem --key mykey.pem

Exit codes:
    0 = token acquired (permissions printed)
    1 = auth failed (bad creds, AADSTS error, etc.)
    2 = usage / local error
"""

import argparse
import base64
import json
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("This script needs the 'requests' library: pip install requests")

TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
DEFAULT_SCOPE = "https://graph.microsoft.com/.default"

# A handful of common Graph endpoints mapped to the permission that would
# let you read them, used for an optional live "effective access" probe.
PROBE_ENDPOINTS = {
    "User.Read.All / Directory.Read.All": "https://graph.microsoft.com/v1.0/users?$top=1",
    "Group.Read.All / Directory.Read.All": "https://graph.microsoft.com/v1.0/groups?$top=1",
    "Application.Read.All": "https://graph.microsoft.com/v1.0/applications?$top=1",
    "Device.Read.All": "https://graph.microsoft.com/v1.0/devices?$top=1",
    "Mail.Read": "https://graph.microsoft.com/v1.0/users?$top=1&$select=mail",  # just a canary
    "RoleManagement.Read.Directory": "https://graph.microsoft.com/v1.0/directoryRoles?$top=1",
    "Policy.Read.All": "https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies?$top=1",
}


def b64url_decode(segment: str) -> bytes:
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        payload = json.loads(b64url_decode(parts[1]))
        return payload
    except Exception as e:
        print(f"[!] Could not decode token payload: {e}")
        return {}


def get_token_client_secret(tenant: str, client_id: str, client_secret: str, scope: str):
    url = TOKEN_URL_TMPL.format(tenant=tenant)
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=data, timeout=20)
    return resp


def get_token_client_cert(tenant: str, client_id: str, cert_path: str, key_path: str, scope: str):
    """
    Certificate-based client credentials flow (JWT client assertion).
    Needs cryptography + PyJWT installed (pip install pyjwt cryptography).
    """
    try:
        import jwt  # PyJWT
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        sys.exit("Certificate auth needs: pip install pyjwt cryptography")

    with open(cert_path, "rb") as f:
        cert_data = f.read()
    with open(key_path, "rb") as f:
        key_data = f.read()

    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    thumbprint = cert.fingerprint(hashes.SHA1())
    x5t = base64.urlsafe_b64encode(thumbprint).decode().rstrip("=")

    private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

    now = int(time.time())
    token_url = TOKEN_URL_TMPL.format(tenant=tenant)
    claims = {
        "aud": token_url,
        "iss": client_id,
        "sub": client_id,
        "jti": str(now),
        "nbf": now,
        "exp": now + 300,
    }
    assertion = jwt.encode(claims, private_key, algorithm="RS256", headers={"x5t": x5t})

    data = {
        "client_id": client_id,
        "scope": scope,
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    resp = requests.post(token_url, data=data, timeout=20)
    return resp


def print_header(text):
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def main():
    ap = argparse.ArgumentParser(description="Check Microsoft Graph app permissions via client credentials")
    ap.add_argument("-t", "--tenant", required=True, help="Tenant ID (GUID) or domain (contoso.onmicrosoft.com)")
    ap.add_argument("-c", "--client-id", required=True, help="Application (client) ID")
    ap.add_argument("-s", "--secret", help="Client secret")
    ap.add_argument("--cert", help="Path to client certificate (PEM)")
    ap.add_argument("--key", help="Path to private key (PEM)")
    ap.add_argument("--scope", default=DEFAULT_SCOPE, help=f"Scope to request (default: {DEFAULT_SCOPE})")
    ap.add_argument("--whoami", action="store_true", help="Also print raw decoded JWT claims")
    ap.add_argument("--probe", action="store_true", help="Make live test calls against common Graph endpoints to confirm effective access")
    ap.add_argument("--save-token", metavar="FILE", help="Write the raw access token to FILE")
    args = ap.parse_args()

    if not args.secret and not (args.cert and args.key):
        ap.error("Provide either --secret, or both --cert and --key")

    print_header(f"Requesting token | tenant={args.tenant} client_id={args.client_id}")

    if args.secret:
        resp = get_token_client_secret(args.tenant, args.client_id, args.secret, args.scope)
    else:
        resp = get_token_client_cert(args.tenant, args.client_id, args.cert, args.key, args.scope)

    if resp.status_code != 200:
        print(f"[!] Auth failed: HTTP {resp.status_code}")
        try:
            err = resp.json()
            print(f"    error: {err.get('error')}")
            print(f"    error_description: {err.get('error_description', '').splitlines()[0]}")
        except Exception:
            print(f"    raw: {resp.text[:500]}")
        sys.exit(1)

    tok = resp.json()
    access_token = tok.get("access_token")
    if not access_token:
        print("[!] No access_token in response:")
        print(json.dumps(tok, indent=2))
        sys.exit(1)

    print(f"[+] Token acquired. Expires in {tok.get('expires_in')}s (token_type={tok.get('token_type')})")

    if args.save_token:
        with open(args.save_token, "w") as f:
            f.write(access_token)
        print(f"[+] Raw token saved to {args.save_token}")

    claims = decode_jwt_payload(access_token)

    print_header("Token identity")
    print(f"  App (azp/appid):   {claims.get('azp') or claims.get('appid')}")
    print(f"  App display name:  {claims.get('app_displayname', '(not present)')}")
    print(f"  Tenant (tid):      {claims.get('tid')}")
    print(f"  Issuer (iss):      {claims.get('iss')}")
    exp = claims.get("exp")
    if exp:
        print(f"  Expires:           {datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()}")

    print_header("Granted application permissions (roles)")
    roles = claims.get("roles", [])
    if roles:
        for r in sorted(roles):
            print(f"  [+] {r}")
    else:
        # Delegated tokens use 'scp' instead of 'roles'
        scp = claims.get("scp")
        if scp:
            print("  (This looks like a delegated token, not app-only. Scopes:)")
            for s in scp.split():
                print(f"  [+] {s}")
        else:
            print("  (none found in token — app likely has no application permissions, or consent wasn't granted)")

    if args.whoami:
        print_header("Full decoded claims")
        print(json.dumps(claims, indent=2, default=str))

    if args.probe:
        print_header("Live endpoint probe (confirms *effective* access, not just the token claim)")
        headers = {"Authorization": f"Bearer {access_token}"}
        for perm_label, url in PROBE_ENDPOINTS.items():
            try:
                r = requests.get(url, headers=headers, timeout=15)
                if r.status_code == 200:
                    print(f"  [+] OK   ({perm_label}) -> {url}")
                elif r.status_code == 403:
                    print(f"  [-] 403  ({perm_label}) -> denied")
                elif r.status_code == 401:
                    print(f"  [-] 401  ({perm_label}) -> unauthorized")
                else:
                    print(f"  [?] {r.status_code}  ({perm_label})")
            except Exception as e:
                print(f"  [!] error probing {perm_label}: {e}")

    print()


if __name__ == "__main__":
    main()
