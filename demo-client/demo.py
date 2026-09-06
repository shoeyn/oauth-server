#!/usr/bin/env python3
import os
import sys
import time
import json
import base64
import hashlib
import secrets
import urllib.parse
from pathlib import Path
import requests
import jwt

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://localhost:9000")
RAILS_URL = os.environ.get("RAILS_URL", "http://localhost:3000")
CLIENT_ID = "demo-client"
REDIRECT_URI = "http://127.0.0.1:8080/callback"

KEYS_DIR = Path(__file__).parent / "keys"
PRIVATE_KEY_PATH = os.environ.get("CLIENT_PRIVATE_KEY_PATH", str(KEYS_DIR / "client_private_key.pem"))

def load_private_key():
    with open(PRIVATE_KEY_PATH, "r") as f:
        return f.read()

def generate_pkce():
    code_verifier = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(hashed).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge

def create_client_assertion(aud, private_key_pem):
    now = int(time.time())
    payload = {
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": aud,
        "jti": secrets.token_hex(16),
        "iat": now,
        "exp": now + 300
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")

def decode_unverified_jwt(token_str):
    try:
        header = jwt.get_unverified_header(token_str)
        payload = jwt.decode(token_str, options={"verify_signature": False})
        return header, payload
    except Exception as e:
        return {}, {"error": str(e)}

def print_banner(title):
    print("\n" + "=" * 70)
    print(f" {title.center(68)} ")
    print("=" * 70)

def run_oauth_flow(use_par=True, username="alice_smith"):
    mode_str = "PAR (Pushed Authorization Requests)" if use_par else "Direct /authorize (Non-PAR)"
    print_banner(f"RUNNING OAUTH 2.1 FLOW: {mode_str}")

    private_key_pem = load_private_key()
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    session = requests.Session()

    print(f"[*] Step 1: Generated PKCE & State/Nonce")
    print(f"    - code_verifier: {code_verifier[:16]}... (length: {len(code_verifier)})")
    print(f"    - code_challenge (S256): {code_challenge}")
    print(f"    - state: {state}")
    print(f"    - nonce: {nonce}")

    if use_par:
        print(f"\n[*] Step 2 (PAR): Pushing authorization parameters to {AUTH_SERVER_URL}/oauth2/par")
        client_assertion = create_client_assertion(f"{AUTH_SERVER_URL}/oauth2/par", private_key_pem)

        par_payload = {
            "client_id": CLIENT_ID,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email user.read",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "nonce": nonce
        }

        par_resp = session.post(f"{AUTH_SERVER_URL}/oauth2/par", data=par_payload)
        print(f"    - PAR Response Status: {par_resp.status_code}")
        if par_resp.status_code != 201:
            print(f"[!] PAR failed: {par_resp.text}")
            sys.exit(1)

        par_data = par_resp.json()
        request_uri = par_data.get("request_uri")
        print(f"    - Obtained request_uri: {request_uri} (expires in: {par_data.get('expires_in')}s)")

        authorize_url = f"{AUTH_SERVER_URL}/oauth2/authorize?client_id={CLIENT_ID}&request_uri={urllib.parse.quote(request_uri)}"
    else:
        print(f"\n[*] Step 2 (Non-PAR): Direct authorization request to {AUTH_SERVER_URL}/oauth2/authorize")
        authorize_params = {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email user.read",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "nonce": nonce
        }
        authorize_url = f"{AUTH_SERVER_URL}/oauth2/authorize?{urllib.parse.urlencode(authorize_params)}"

    print(f"\n[*] Step 3: Accessing /oauth2/authorize (Unauthenticated)")
    print(f"    - Target URL: {authorize_url}")
    auth_resp = session.get(authorize_url, allow_redirects=False)
    print(f"    - Response Status: {auth_resp.status_code}")

    if auth_resp.status_code != 302:
        print(f"[!] Expected 302 redirect to Rails login, got: {auth_resp.status_code}")
        sys.exit(1)

    login_redirect_url = auth_resp.headers.get("Location")
    print(f"    - Redirect Location: {login_redirect_url}")
    assert "/login" in login_redirect_url, "Redirect should point to Rails /login"

    # Step 4: Login at Ruby on Rails app
    print(f"\n[*] Step 4: Interacting with Ruby on Rails login app to authenticate user and populate Redis session")
    login_page_resp = session.get(login_redirect_url)
    print(f"    - Rendered Rails Login page: {login_page_resp.status_code}")

    # Extract Rails CSRF authenticity token from the form
    import re
    csrf_match = re.search(r'name="authenticity_token"\s+value="([^"]+)"', login_page_resp.text)
    authenticity_token = csrf_match.group(1) if csrf_match else None
    if authenticity_token:
        print(f"    - Extracted Rails CSRF token: {authenticity_token[:16]}...")

    parsed_login_url = urllib.parse.urlparse(login_redirect_url)
    login_query_params = urllib.parse.parse_qs(parsed_login_url.query)
    return_to = login_query_params.get("return_to", [None])[0]
    print(f"    - return_to extracted: {return_to}")

    # Determine post URL (accounting for container vs localhost hostnames)
    rails_login_post_url = f"{RAILS_URL}/login"
    login_form_data = {
        "username": username,
        "password": "valid_password",
        "return_to": return_to
    }
    if authenticity_token:
        login_form_data["authenticity_token"] = authenticity_token

    rails_resp = session.post(rails_login_post_url, data=login_form_data, allow_redirects=False)
    print(f"    - Rails Login Status: {rails_resp.status_code}")
    post_login_redirect = rails_resp.headers.get("Location")
    print(f"    - Rails Redirect: {post_login_redirect}")
    print(f"    - Cookies set by Rails: {session.cookies.get_dict()}")

    assert rails_resp.status_code in [302, 303], "Rails login should redirect back to Spring"
    assert "SHARED_SESSION_ID" in session.cookies, "HttpOnly SHARED_SESSION_ID cookie must be set"

    # Step 5: Resume OAuth authorization at Spring with the shared session
    print(f"\n[*] Step 5: Returning to Spring OAuth Server with shared Redis session")
    resume_target = post_login_redirect
    if AUTH_SERVER_URL != "http://localhost:9000":
        parsed_spring = urllib.parse.urlparse(post_login_redirect)
        resume_target = f"{AUTH_SERVER_URL}{parsed_spring.path}"
        if parsed_spring.query:
            resume_target += f"?{parsed_spring.query}"

    spring_resume_resp = session.get(resume_target, allow_redirects=False)
    print(f"    - Spring Resume Status: {spring_resume_resp.status_code}")
    callback_redirect = spring_resume_resp.headers.get("Location")
    print(f"    - Callback Redirect: {callback_redirect}")

    assert spring_resume_resp.status_code == 302, "Spring should issue redirect with authorization code"
    assert callback_redirect.startswith(REDIRECT_URI), f"Should redirect to callback URI: {REDIRECT_URI}"

    parsed_callback = urllib.parse.urlparse(callback_redirect)
    callback_params = urllib.parse.parse_qs(parsed_callback.query)

    auth_code = callback_params.get("code", [None])[0]
    returned_state = callback_params.get("state", [None])[0]

    assert auth_code is not None, "Authorization code must be present"
    assert returned_state == state, "Returned state must match original state"
    print(f"    - Successfully obtained authorization code: {auth_code[:16]}...")
    print(f"    - State validated successfully: {returned_state}")

    # Step 6: Token Exchange using private_key_jwt and PKCE code_verifier
    print(f"\n[*] Step 6: Exchanging authorization code at {AUTH_SERVER_URL}/oauth2/token with private_key_jwt & PKCE")
    token_assertion = create_client_assertion(f"{AUTH_SERVER_URL}/oauth2/token", private_key_pem)

    token_payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": token_assertion
    }

    token_resp = session.post(f"{AUTH_SERVER_URL}/oauth2/token", data=token_payload)
    print(f"    - Token Response Status: {token_resp.status_code}")
    if token_resp.status_code != 200:
        print(f"[!] Token exchange failed: {token_resp.text}")
        sys.exit(1)

    tokens = token_resp.json()
    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")
    token_type = tokens.get("token_type")

    print(f"\n[+] OAuth 2.1 Token Response Received Successfully:")
    print(f"    - token_type: {token_type}")
    print(f"    - expires_in: {tokens.get('expires_in')}s")
    print(f"    - scope: {tokens.get('scope')}")

    # Inspect id_token
    id_hdr, id_claims = decode_unverified_jwt(id_token)
    print("\n" + "-" * 70)
    print(" ID TOKEN (OIDC Identity Assertion):")
    print(f" Header: {json.dumps(id_hdr)}")
    print(f" Claims: {json.dumps(id_claims, indent=2)}")

    # Inspect access_token / user_token
    at_hdr, at_claims = decode_unverified_jwt(access_token)
    print("\n" + "-" * 70)
    print(" ACCESS TOKEN (Customized user_token):")
    print(f" Header: {json.dumps(at_hdr)}")
    print(f" Claims: {json.dumps(at_claims, indent=2)}")
    print("-" * 70)

    # Verification assertions
    assert id_claims.get("nonce") == nonce, "ID token nonce must match original nonce"
    assert at_claims.get("token_type_category") == "user_token", "Access token must be customized as user_token"
    assert id_claims.get("token_type_category") == "id_token", "ID token must be designated as id_token"
    assert at_claims.get("user_id") == username, "Access token user_id must match authenticated user"

    print(f"\n>>> SUCCESS: {mode_str} completed and verified all requirements!")

if __name__ == "__main__":
    time.sleep(1)
    print("\nStarting OAuth 2.1 Demo Suite...")

    # Test 1: PAR Flow
    run_oauth_flow(use_par=True, username="alice_in_wonderland")

    # Test 2: Non-PAR Direct /authorize Flow
    run_oauth_flow(use_par=False, username="bob_marley")

    print_banner("ALL OAUTH 2.1 PROOF-OF-CONCEPT FLOWS PASSED SUCCESSFULLY!")
