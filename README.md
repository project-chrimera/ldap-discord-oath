# Discord OAuth2 + LDAP Proxy for Home Assistant

This project provides an OpenID Connect (OIDC) proxy for Home Assistant using Discord OAuth2 for authentication and optional LDAP for authorization. It allows Home Assistant to authenticate users via Discord while optionally validating their group membership in LDAP.

## Features

- Discord OAuth2 authentication
- Optional LDAP authorization
- Acts as an OpenID Connect provider for Home Assistant
- JWT-based ID token generation
- Simple session management in memory
- Configurable via `.env` file

## Requirements

- Python 3.11+
- FastAPI
- uvicorn
- httpx
- python-dotenv
- PyJWT
- ldap3

## Installation

1. Clone the repository:

```bash
git clone https://github.com/project-chrimera/ldap-discord-oath
cd discord-ldap-proxy
pip install -r requirements.txt
```

edit the env example and rename it to .env

run the bot `python3 ./oath-proxy.py`

