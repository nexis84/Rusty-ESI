"""
Async ESI HTTP client with automatic token refresh and rate-limit handling.
"""
import asyncio
import time
from typing import Optional

import httpx

from config import settings
from auth.eve_sso import decrypt_token, encrypt_token, refresh_access_token, token_expires_at


class EsiClient:
    """
    Thin async wrapper around the EVE ESI REST API.

    Usage:
        async with EsiClient(access_token, refresh_token, expires_at) as client:
            data = await client.get("/characters/{id}/")
    """

    _ESI_BASE = settings.esi_base_url

    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        expires_at: int,
        on_token_refresh: Optional[callable] = None,
    ):
        """
        Args:
            access_token:      Plaintext (decrypted) access token
            refresh_token:     Plaintext (decrypted) refresh token
            expires_at:        Unix timestamp when access_token expires
            on_token_refresh:  Async callback(new_access, new_refresh, new_expires_at)
                               so caller can persist updated tokens
        """
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at = expires_at
        self._on_token_refresh = on_token_refresh
        self._http: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._http = httpx.AsyncClient(
            base_url=self._ESI_BASE,
            headers={"Accept": "application/json", "User-Agent": "ESI-Checker/1.0"},
            timeout=15.0,
        )
        return self

    async def __aexit__(self, *_):
        if self._http:
            await self._http.aclose()

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    async def _ensure_valid_token(self):
        if time.time() >= self._expires_at:
            token_data = await refresh_access_token(self._refresh_token)
            self._access_token = token_data["access_token"]
            self._refresh_token = token_data.get("refresh_token", self._refresh_token)
            self._expires_at = token_expires_at(token_data["expires_in"])

            if self._on_token_refresh:
                await self._on_token_refresh(
                    self._access_token,
                    self._refresh_token,
                    self._expires_at,
                )

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._access_token}"}

    # ------------------------------------------------------------------
    # Core request methods
    # ------------------------------------------------------------------

    async def get(self, path: str, params: Optional[dict] = None) -> dict | list:
        """Perform a GET request against ESI, refreshing token if needed."""
        await self._ensure_valid_token()

        resp = await self._http.get(
            path,
            params=params or {},
            headers=self._auth_headers(),
        )

        # ESI rate limit handling
        remaining = int(resp.headers.get("X-ESI-Error-Limit-Remain", 100))
        if remaining < 10:
            reset_seconds = int(resp.headers.get("X-ESI-Error-Limit-Reset", 1))
            await asyncio.sleep(reset_seconds)

        if resp.status_code == 304:
            return {}  # Not modified (cached)

        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Public (no auth) helper — for public endpoints
    # ------------------------------------------------------------------

    @staticmethod
    async def public_get(path: str, params: Optional[dict] = None) -> dict | list:
        """Fetch a public ESI endpoint (no auth required)."""
        url = f"{settings.esi_base_url}{path}"
        async with httpx.AsyncClient(
            headers={"Accept": "application/json", "User-Agent": "ESI-Checker/1.0"},
            timeout=15.0,
        ) as http:
            resp = await http.get(url, params=params or {})
            resp.raise_for_status()
            return resp.json()
