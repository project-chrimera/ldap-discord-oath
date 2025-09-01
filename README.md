# Discord OAuth2 + LDAP Proxy for Home Assistant

This project provides an OpenID Connect (OIDC) proxy for Home Assistant using Discord OAuth2 for authentication and optional LDAP for authorization. 
It allows Home Assistant to authenticate users via Discord while optionally validating their group membership in LDAP.



## Features

- Discord OAuth2 authentication
- LDAP authorization
- Acts as an OpenID Connect provider for Home Assistant
- JWT-based ID token generation
- Simple session management in memory
- Configurable via `.env` and `client_ou_mapping.json` file

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

## apache proxy 

use this to forward the proxy using apache2
```
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName auth.yetanotherprojecttosavetheworld.org

    ProxyPreserveHost On
    ProxyRequests Off

    # Alles doorsturen naar de proxy
    ProxyPass        /  http://127.0.0.1:4180/
    ProxyPassReverse /  http://127.0.0.1:4180/

    # Logs
    ErrorLog ${APACHE_LOG_DIR}/auth_error.log
    CustomLog ${APACHE_LOG_DIR}/auth_access.log combined

    # SSL-certificaten (voorbeeldpaden)
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/privkey.pem
    SSLCertificateChainFile /path/to/chain.pem
</VirtualHost>
</IfModule>
```

## Home assistant usage

install openid from hacks.
use this from the example.
client_id is for the set LDAP scope in `client_ou_mapping.json` 
```
openid:
  client_id: hass
  client_secret: dummy
  configure_url: "https://auth.yetanotherprojecttosavetheworld.org/auth/.well-known/openid-configuration"
  username_field: "preferred_username"
  scope: "openid email profile"
  block_login: false
  openid_text: "Login with Discord"
```

## Apache auth

```
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName apache-test.yetanotherprojecttosavetheworld.org

    # Correcte metadata URL
    OIDCProviderMetadataURL https://auth.yetanotherprojecttosavetheworld.org/.well-known/openid-configuration

    OIDCClientID webaccess
    OIDCClientSecret dummy

    OIDCRedirectURI https://apache-test.yetanotherprojecttosavetheworld.org/redirect_apache
    OIDCCryptoPassphrase "iets_norm44ls_hier"
    OIDCResponseType code

    # CORRECTE endpoints
    OIDCProviderIssuer https://auth.yetanotherprojecttosavetheworld.org/
    OIDCProviderAuthorizationEndpoint https://auth.yetanotherprojecttosavetheworld.org/openid/authorize
    OIDCProviderTokenEndpoint https://auth.yetanotherprojecttosavetheworld.org/openid/token
    OIDCProviderUserInfoEndpoint https://auth.yetanotherprojecttosavetheworld.org/openid/userinfo
    OIDCProviderJwksUri https://auth.yetanotherprojecttosavetheworld.org/openid/jwks

    <Location />
        AuthType openid-connect
        Require valid-user
    </Location>

    # Proxy de redirect URI direct naar de Python-proxy
    <Location /redirect_apache>
        ProxyPass           http://127.0.0.1:4180/redirect_apache
        ProxyPassReverse http://127.0.0.1:4180/redirect_apache
    </Location>

    DocumentRoot /home/yap2stw/apache-test/

    <Directory /home/yap2stw/apache-test/>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Logging voor debugging
    LogLevel info
    ErrorLog ${APACHE_LOG_DIR}/apache-test-error.log
    CustomLog ${APACHE_LOG_DIR}/apache-test-access.log combined

    # SSL-certificaten (voorbeeldpaden)
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/privkey.pem
    SSLCertificateChainFile /path/to/chain.pem
</VirtualHost>
</IfModule>


```
