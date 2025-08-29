#!/usr/bin/python3
import os
import uuid
import jwt
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from ldap3 import Server, Connection, SUBTREE
from dotenv import load_dotenv
from urllib.parse import urlencode, unquote
from typing import Dict, Any

# Laad omgevingsvariabelen vanuit het .env bestand
load_dotenv()

# --- Configuratie vanuit Omgevingsvariabelen ---
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI") 
DISCORD_SCOPE = os.getenv("DISCORD_SCOPE", "identify email")

LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")
LDAP_GROUPS_DN_STR = os.getenv("LDAP_GROUPS_DN")
LDAP_GROUPS_DN = LDAP_GROUPS_DN_STR.split(';') if LDAP_GROUPS_DN_STR else []

PROXY_HOST = os.getenv("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("PROXY_PORT", "4180"))
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key")

# --- In-memory Sessie Opslag ---
# We gebruiken een woordenboek om tijdelijke sessiegegevens op te slaan.
# De sleutels zijn unieke ID's die we genereren (proxy_code),
# en de waarden bevatten de Home Assistant state, redirect_uri en gebruikersinformatie.
SESSIONS: Dict[str, Dict[str, Any]] = {}

app = FastAPI()

# --- OpenID Connect Endpoints voor Home Assistant ---

# Dient de OpenID configuratie metadata.
# Home Assistant zal dit lezen om onze endpoints te ontdekken.
@app.get("/auth/.well-known/openid-configuration")
async def openid_config():
    """Biedt OpenID Connect metadata."""
    base = f"https://{os.getenv('SERVER_NAME', 'hass.example.org')}/auth/openid"
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "userinfo_endpoint": f"{base}/userinfo",
        "jwks_uri": f"{base}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
    }

# Dit is het endpoint waar Home Assistant de gebruiker naar doorverwijst.
# Het initieert onze proxy-stroom.
@app.get("/auth/openid/authorize")
async def authorize(request: Request):
    """
    Start de OIDC autorisatiestroom door door te verwijzen naar Discord's OAuth2.
    Het slaat de HA state en redirect_uri op in een sessie.
    """
    ha_redirect_uri = request.query_params.get("redirect_uri")
    ha_state = request.query_params.get("state")
    client_id = request.query_params.get("client_id")

    if not ha_redirect_uri or not ha_state or not client_id:
        return JSONResponse({"error": "missing redirect_uri, state, or client_id"}, status_code=400)
    
    # We genereren een unieke ID voor deze sessie. Dit is onze "proxy code".
    session_id = str(uuid.uuid4())
    SESSIONS[session_id] = {
        "ha_state": ha_state,
        "ha_redirect_uri": ha_redirect_uri,
        "user_email": None # We slaan het emailadres hier op
    }

    # Verwijs de gebruiker door naar Discord. We gebruiken onze eigen session_id als de state
    # om de context te behouden.
    discord_url = (
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={DISCORD_SCOPE}"
        f"&state={session_id}"
    )
    return RedirectResponse(discord_url)

# --- Discord OAuth2 Callback ---

# Dit endpoint is waar Discord de gebruiker naar doorverwijst na authenticatie.
@app.get("/proxy/callback")
async def proxy_callback(request: Request):
    """
    Verwerkt de callback van Discord. Het wisselt de Discord-code in voor een token,
    voert de LDAP-check uit en verwijst dan terug naar Home Assistant.
    """
    discord_code = request.query_params.get("code")
    session_id = request.query_params.get("state")

    # Deze check is cruciaal. Discord moet de state teruggeven die we hebben verstuurd.
    if not session_id:
        return JSONResponse({"error": "missing session state from Discord"}, status_code=400)

    if not discord_code:
        return JSONResponse({"error": "missing Discord code"}, status_code=400)
    
    if session_id not in SESSIONS:
        # Deze fout wordt getriggerd wanneer de session_id van Discord niet overeenkomt
        # met een van onze actieve sessies.
        return JSONResponse({"error": "invalid session state or session expired"}, status_code=400)

    # Wissel de Discord-code in voor een access token
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

            # Haal de gebruikersinformatie op van Discord
            r = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            r.raise_for_status()
            user = r.json()
    except httpx.HTTPStatusError as e:
        return JSONResponse({"error": f"HTTP error during Discord OAuth: {e}", "details": e.response.text}, status_code=e.response.status_code)

    # Voer de lokale LDAP-check uit voor autorisatie
    if LDAP_SERVER:
        try:
            server = Server(LDAP_SERVER)
            with Connection(server, LDAP_BIND_DN, LDAP_BIND_PASSWORD, auto_bind=True) as conn:
                email = user.get("email")
                if not email:
                    return JSONResponse({"error": "no email from Discord"}, status_code=400)
                
                # Controleer of de gebruiker bestaat via email in LDAP
                conn.search(LDAP_BASE_DN, f"(mail={email})", SUBTREE, attributes=["uid", "mail", "cn"])
                if not conn.entries:
                    return JSONResponse({"error": "unauthorized: email not found in LDAP"}, status_code=403)
                
                user_dn = conn.entries[0].entry_dn
                
                # Controleer of de gebruiker lid is van een van de vereiste groepen
                is_member_of_any_group = False
                for group_dn in LDAP_GROUPS_DN:
                    conn.search(group_dn, f"(&(objectClass=groupOfNames)(member={user_dn}))", SUBTREE)
                    if conn.entries:
                        is_member_of_any_group = True
                        break  # Verlaat de lus zodra een lidmaatschap is gevonden

                if not is_member_of_any_group:
                    return JSONResponse({"error": "forbidden: not a member of any of the required groups"}, status_code=403)
        except Exception as e:
            return JSONResponse({"error": f"LDAP error: {e}"}, status_code=500)

    # Sla het emailadres van de gebruiker op in onze sessie. Dit is het ID dat Home Assistant zal gebruiken.
    user_email = user.get("email")
    if not user_email:
        return JSONResponse({"error": "User email not provided by Discord. Ensure 'email' scope is enabled."}, status_code=400)
    SESSIONS[session_id]["user_email"] = user_email

    # Verwijs terug naar Home Assistant met onze sessie ID als de code
    ha_redirect_uri = SESSIONS[session_id]["ha_redirect_uri"]
    ha_state = SESSIONS[session_id]["ha_state"]
    redirect_url = f"{ha_redirect_uri}?code={session_id}&state={ha_state}"
    return RedirectResponse(redirect_url)

# --- OpenID Connect Endpoints voor Home Assistant ---

# Dit endpoint verwerkt de token-uitwisseling, aangevraagd door Home Assistant.
@app.post("/auth/openid/token")
async def token(request: Request):
    """
    Wisselt onze sessie ID (proxy-code) in voor een OIDC-token.
    Dit wordt aangeroepen door Home Assistant.
    """
    form = await request.form()
    session_id = form.get("code")
    
    # Valideer de sessie ID
    if session_id not in SESSIONS:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    user_info = SESSIONS.pop(session_id)
    
    user_email = user_info.get("user_email")
    if not user_email:
        return JSONResponse({"error": "user email not found for this code"}, status_code=400)
        
    # Genereer een JWT (die fungeert als een OIDC ID-token) met het emailadres als 'sub'
    access_token = jwt.encode({"sub": user_email}, JWT_SECRET, algorithm="HS256")
    return {"access_token": access_token, "token_type": "bearer", "expires_in": 3600}

# Dit endpoint biedt gebruikersinformatie.
@app.get("/auth/openid/userinfo")
async def userinfo(request: Request):
    """Biedt gebruikersinformatie op basis van het OIDC-token."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return JSONResponse({"error": "missing token"}, status_code=401)
    
    try:
        # Decodeer de token en gebruik het emailadres dat we als 'sub' hebben opgeslagen.
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_email = payload.get("sub")
    except jwt.InvalidTokenError:
        return JSONResponse({"error": "invalid_token"}, status_code=401)
        
    # Retourneer het emailadres als 'sub' en 'preferred_username'.
    return {"sub": user_email, "preferred_username": user_email}

# Dit endpoint biedt de publieke sleutel om de JWT te verifiëren.
@app.get("/auth/openid/jwks")
async def jwks():
    """Biedt de publieke sleutel voor JWT-verificatie."""
    return {"keys": []}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("proxy:app", host=PROXY_HOST, port=PROXY_PORT, reload=False)

