"""
EVE SSO OAuth2 authentication helpers.

Flow:
  1. build_auth_url()       → redirect user to EVE SSO
  2. exchange_code()        → swap auth code for tokens
  3. verify_token()         → decode JWT, get character info
  4. refresh_access_token() → keep tokens fresh
"""
import base64
import hashlib
import secrets
import time
from typing import Optional

import httpx

from config import settings


# ---------------------------------------------------------------------------
# Token encryption (Fernet)
# ---------------------------------------------------------------------------

def _get_fernet():
    from cryptography.fernet import Fernet
    key = settings.fernet_key.encode()
    return Fernet(key)


def encrypt_token(token: str) -> str:
    """Encrypt an OAuth token for safe DB storage."""
    f = _get_fernet()
    return f.encrypt(token.encode()).decode()


def decrypt_token(encrypted: str) -> str:
    """Decrypt a stored OAuth token."""
    f = _get_fernet()
    return f.decrypt(encrypted.encode()).decode()


# ---------------------------------------------------------------------------
# PKCE helpers (not required by EVE SSO v2 but good practice)
# ---------------------------------------------------------------------------

def _generate_state() -> str:
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# Auth URL construction
# ---------------------------------------------------------------------------

def build_auth_url(
    role: str,
    extra_state: Optional[str] = None,
) -> tuple[str, str]:
    """
    Build an EVE SSO authorization URL.

    Args:
        role: "recruiter" or "applicant"
        extra_state: Extra data to encode in state (e.g. invite token)

    Returns:
        (url, state) — state must be stored in session for CSRF verification
    """
    state_data = _generate_state()
    if extra_state:
        state_data = f"{state_data}:{extra_state}"

    scopes = (
        settings.service_account_scopes
        if role == "service_account"
        else settings.recruiter_scopes
        if role == "recruiter"
        else settings.applicant_scopes
    )

    params = {
        "response_type": "code",
        "redirect_uri": settings.eve_callback_url,
        "client_id": settings.eve_client_id,
        "scope": scopes,
        "state": state_data,
    }

    from urllib.parse import urlencode
    url = f"{settings.eve_sso_authorize_url}?{urlencode(params)}"
    return url, state_data


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------

async def exchange_code(code: str) -> dict:
    """
    Exchange an authorization code for access + refresh tokens.

    Returns raw token response dict:
      access_token, refresh_token, expires_in, token_type
    """
    credentials = base64.b64encode(
        f"{settings.eve_client_id}:{settings.eve_client_secret}".encode()
    ).decode()

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            settings.eve_sso_token_url,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Token verification — decode EVE SSO JWT
# ---------------------------------------------------------------------------

async def verify_token(access_token: str) -> dict:
    """
    Verify an EVE SSO access token by hitting the verify endpoint.

    Returns character info:
      CharacterID, CharacterName, CharacterOwnerHash,
      ExpiresOn, Scopes, TokenType
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            settings.eve_sso_verify_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------

async def refresh_access_token(refresh_token: str) -> dict:
    """
    Use a refresh token to obtain a new access token.

    Returns: {access_token, refresh_token, expires_in, token_type}
    """
    credentials = base64.b64encode(
        f"{settings.eve_client_id}:{settings.eve_client_secret}".encode()
    ).decode()

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            settings.eve_sso_token_url,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def token_expires_at(expires_in: int) -> int:
    """Return Unix timestamp when the token will expire."""
    return int(time.time()) + expires_in - 30  # 30-second buffer
