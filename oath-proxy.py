#!/usr/bin/python3
import os
import uuid
import json
import jwt
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.exceptions import HTTPException
from ldap3 import Server, Connection, SUBTREE
from dotenv import load_dotenv
from urllib.parse import urlencode, unquote
from typing import Dict, Any
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import hashlib

# Laad omgevingsvariabelen vanuit het .env bestand
load_dotenv()

# --- Configuratie vanuit Omgevingsvariabelen ---
SERVER_NAME = os.getenv('SERVER_NAME', 'auth.yetanotherprojecttosavetheworld.org')
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
DISCORD_SCOPE = os.getenv("DISCORD_SCOPE", "identify email")

LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")

# Laad client naar OU mapping vanuit JSON bestand
CLIENT_OU_MAPPING_FILE = os.getenv("CLIENT_OU_MAPPING_FILE", "client_ou_mapping.json")

# Genereer RSA sleutel voor ondertekening (eenmalig uitvoeren en opslaan)
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# Verkrijg of genereer RSA sleutel
try:
    with open("private_key.pem", "rb") as key_file:
        PRIVATE_KEY = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
except FileNotFoundError:
    PRIVATE_KEY = generate_rsa_key()
    with open("private_key.pem", "wb") as key_file:
        key_file.write(PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

# Verkrijg publieke sleutel voor JWKS
public_key = PRIVATE_KEY.public_key()
public_numbers = public_key.public_numbers()

def load_client_ou_mapping():
    try:
        with open(CLIENT_OU_MAPPING_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Waarschuwing: Client OU mapping bestand '{CLIENT_OU_MAPPING_FILE}' niet gevonden. Lege mapping wordt gebruikt.")
        return {}
    except json.JSONDecodeError as e:
        print(f"Fout: Ongeldige JSON in client OU mapping bestand: {e}")
        return {}

CLIENT_OU_MAPPING = load_client_ou_mapping()

PROXY_HOST = os.getenv("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("PROXY_PORT", "4180"))
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key")

# --- In-memory Sessie Opslag ---
SESSIONS: Dict[str, Dict[str, Any]] = {}

app = FastAPI()

# Aangepaste 404 handler
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: HTTPException):
    now = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    cli_output = f"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Niet Gevonden</title>
</head><body>
<h1>Niet Gevonden</h1>
<p>De gevraagde URL {request.url.path} is niet gevonden op deze server.</p>
<hr>
<address>Python FastAPI Server op {request.url.hostname} Poort {request.url.port}</address>
</body></html>"""
    
    return HTMLResponse(content=cli_output, status_code=404)

# Root endpoint
@app.get("/")
async def root():
    """Behandel verzoeken naar de root URL"""
    return {"message": "OpenID Connect Proxy Server", "status": "draait"}

# Redirect voor de typefout route /openidorize -> /openid/authorize
@app.get("/openidorize")
async def redirect_openidorize(request: Request):
    """Herleid /openidorize naar /openid/authorize"""
    params = dict(request.query_params)
    redirect_url = f"/openid/authorize?{urlencode(params)}"
    return RedirectResponse(redirect_url)
    
# Nieuw eindpunt voor Apache redirect_uri, stuurt door naar de common authorize endpoint
@app.get("/redirect_apache")
async def apache_redirect(request: Request):
    """
    Dit eindpunt vangt de redirect van Apache en stuurt het door naar het
    algemene OIDC-autorisatie-eindpunt.
    """
    params = dict(request.query_params)
    redirect_url = f"/openid/authorize?{urlencode(params)}"
    return RedirectResponse(redirect_url)


# OpenID Connect well-known configuratie
@app.get("/.well-known/openid-configuration")
async def well_known_openid_config():
    base = f"https://{SERVER_NAME}"
    return {
        "issuer": f"{base}/",
        "authorization_endpoint": f"{base}/openid/authorize",
        "token_endpoint": f"{base}/openid/token",
        "userinfo_endpoint": f"{base}/openid/userinfo",
        "jwks_uri": f"{base}/openid/jwks",
        "response_types_supported": ["code", "id_token", "token id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "claims_supported": ["sub", "preferred_username", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "grant_types_supported": ["authorization_code", "implicit"]
    }

# OpenID Connect well-known configuratie (voor Home Assistant)
@app.get("/auth/.well-known/openid-configuration")
async def auth_well_known_openid_config():
    base = f"https://{SERVER_NAME}/auth/openid"
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "userinfo_endpoint": f"{base}/userinfo",
        "jwks_uri": f"{base}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "claims_supported": ["sub", "preferred_username", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "grant_types_supported": ["authorization_code"]
    }

# OpenID Connect autorisatie endpoint (voor Apache mod_auth_openidc)
@app.get("/openid/authorize")
async def openid_authorize(request: Request):
    return await authorize_common(request, "openid")

# OpenID Connect autorisatie endpoint (voor Home Assistant)
@app.get("/auth/openid/authorize")
async def auth_openid_authorize(request: Request):
    return await authorize_common(request, "auth/openid")

async def authorize_common(request: Request, prefix: str):
    ha_redirect_uri = request.query_params.get("redirect_uri")
    ha_state = request.query_params.get("state")
    client_id = request.query_params.get("client_id")
    nonce = request.query_params.get("nonce")
    code_challenge = request.query_params.get("code_challenge")
    code_challenge_method = request.query_params.get("code_challenge_method")

    if not ha_redirect_uri or not ha_state or not client_id:
        return JSONResponse({"error": "missing redirect_uri, state, or client_id"}, status_code=400)
    
    session_id = str(uuid.uuid4())
    SESSIONS[session_id] = {
        "ha_state": ha_state,
        "ha_redirect_uri": ha_redirect_uri,
        "user_email": None,
        "client_id": client_id,
        "prefix": prefix,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method
    }

    discord_url = (
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={DISCORD_SCOPE}"
        f"&state={session_id}"
    )
    return RedirectResponse(discord_url)

# Discord OAuth2 callback
# Discord OAuth2 callback
@app.get("/proxy/callback")
async def proxy_callback(request: Request):
    discord_code = request.query_params.get("code")
    session_id = request.query_params.get("state")

    if not session_id:
        return JSONResponse({"error": "missing session state from Discord"}, status_code=400)
    if not discord_code:
        return JSONResponse({"error": "missing Discord code"}, status_code=400)
    if session_id not in SESSIONS:
        return JSONResponse({"error": "invalid session state or session expired"}, status_code=400)

    client_id = SESSIONS[session_id].get("client_id")
    if not client_id:
        return JSONResponse({"error": "client_id not found in session"}, status_code=400)

    allowed_ous = CLIENT_OU_MAPPING.get(client_id, [])
    if not allowed_ous:
        return JSONResponse({"error": f"no OUs configured for client_id: {client_id}"}, status_code=403)

    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": discord_code,
                    "redirect_uri": REDIRECT_URI,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            r.raise_for_status()
            token_data = r.json()
            access_token = token_data.get("access_token")
            if not access_token:
                return JSONResponse({"error": "Discord token failed", "details": token_data}, status_code=400)

            r = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            r.raise_for_status()
            user = r.json()
    except httpx.HTTPStatusError as e:
        return JSONResponse({"error": f"HTTP error during Discord OAuth: {e}", "details": e.response.text}, status_code=e.response.status_code)

    user_uid = None  # Initialize UID variable

    if LDAP_SERVER:
        try:
            server = Server(LDAP_SERVER)
            with Connection(server, LDAP_BIND_DN, LDAP_BIND_PASSWORD, auto_bind=True) as conn:
                email = user.get("email")
                if not email:
                    return JSONResponse({"error": "no email from Discord"}, status_code=400)
                
                # Search for user and get UID attribute
                conn.search(LDAP_BASE_DN, f"(mail={email})", SUBTREE, attributes=["uid", "mail", "cn"])
                if not conn.entries:
                    return JSONResponse({"error": "unauthorized: email not found in LDAP"}, status_code=403)
                
                # Extract UID from LDAP entry
                user_entry = conn.entries[0]
                user_uid = user_entry.uid.value if hasattr(user_entry, 'uid') else None
                if not user_uid:
                    return JSONResponse({"error": "UID not found in LDAP entry"}, status_code=400)
                
                user_dn = user_entry.entry_dn
                
                is_member_of_any_group = False
                for group_dn in allowed_ous:
                    conn.search(group_dn, f"(&(objectClass=groupOfNames)(member={user_dn}))", SUBTREE)
                    if conn.entries:
                        is_member_of_any_group = True
                        break

                if not is_member_of_any_group:
                    return JSONResponse({"error": f"forbidden: not a member of any required groups for client {client_id}"}, status_code=403)
        except Exception as e:
            return JSONResponse({"error": f"LDAP error: {e}"}, status_code=500)
    else:
        # Fallback to email if no LDAP (for testing)
        user_uid = user.get("email")

    if not user_uid:
        return JSONResponse({"error": "User UID not found"}, status_code=400)
    
    # Store UID instead of email in session
    SESSIONS[session_id]["user_uid"] = user_uid

    ha_redirect_uri = SESSIONS[session_id]["ha_redirect_uri"]
    ha_state = SESSIONS[session_id]["ha_state"]

    redirect_url = f"{ha_redirect_uri}?code={session_id}&state={ha_state}"
    
    # Voeg een print statement toe voor debugging
    print(f"Debug: Omleiden naar {redirect_url}")
    
    return RedirectResponse(redirect_url)

# JWKS endpoint
@app.get("/openid/jwks")
async def openid_jwks():
    # Converteer modulus en exponent naar base64
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, byteorder='big')).decode('utf-8').rstrip('=')
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes(4, byteorder='big')).decode('utf-8').rstrip('=')
    
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "1",
                "n": n,
                "e": e,
                "alg": "RS256"
            }
        ]
    }

# JWKS endpoint voor Home Assistant
@app.get("/auth/openid/jwks")
async def auth_openid_jwks():
    return await openid_jwks()

# Token endpoint (voor Apache mod_auth_openidc)
@app.post("/openid/token")
async def openid_token(request: Request):
    return await token_common(request)

# Token endpoint (voor Home Assistant)
@app.post("/auth/openid/token")
async def auth_openid_token(request: Request):
    return await token_common(request)

async def token_common(request: Request):
    form = await request.form()
    session_id = form.get("code")
    client_id = form.get("client_id", "webaccess")  # Verkrijg client_id uit verzoek of gebruik standaardwaarde
    code_verifier = form.get("code_verifier")

    if session_id not in SESSIONS:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    user_info = SESSIONS.pop(session_id)
    user_uid = user_info.get("user_uid")  # Changed from user_email to user_uid
    if not user_uid:
        return JSONResponse({"error": "user UID not found for this code"}, status_code=400)
        
    # PKCE validatie
    code_challenge = user_info.get("code_challenge")
    code_challenge_method = user_info.get("code_challenge_method")
    if code_challenge and code_challenge_method == "S256":
        sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        hashed_verifier = base64.urlsafe_b64encode(sha256).decode('utf-8').rstrip('=')
        if hashed_verifier != code_challenge:
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE code_verifier mismatch"}, status_code=400)

    # Genereer zowel access token als id_token
    access_token = jwt.encode({"sub": user_uid}, JWT_SECRET, algorithm="HS256")  # Changed to user_uid
    
    # Maak id_token met de juiste OIDC claims met RS256
    id_token_payload = {
        "sub": user_uid,  # Changed to user_uid
        "email": user_info.get("user_email", ""),  # Keep email if available for compatibility
        "preferred_username": user_uid,  # Changed to user_uid
        "iss": f"https://{SERVER_NAME}/",
        "aud": client_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iat": datetime.datetime.utcnow(),
        "nonce": user_info.get("nonce")
    }
    
    # Gebruik RS256 voor id_token met de private sleutel
    id_token = jwt.encode(id_token_payload, PRIVATE_KEY, algorithm="RS256")
    
    return {
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "bearer",
        "expires_in": 3600
    }

# Userinfo endpoint (voor Apache mod_auth_openidc)
@app.get("/openid/userinfo")
async def openid_userinfo(request: Request):
    return await userinfo_common(request)

# Userinfo endpoint (voor Home Assistant)
async def userinfo_common(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return JSONResponse({"error": "missing token"}, status_code=401)
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_uid = payload.get("sub")  # Changed to user_uid
        
        # Remove @auth.yetanotherprojecttosavetheworld.org/ part if present
        if user_uid and '@auth.yetanotherprojecttosavetheworld.org/' in user_uid:
            user_uid = user_uid.split('@auth.yetanotherprojecttosavetheworld.org/')[0]
            
    except jwt.InvalidTokenError:
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    
    return {"sub": user_uid, "preferred_username": user_uid}  # Changed to user_uid

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("proxy:app", host=PROXY_HOST, port=PROXY_PORT, reload=False)





