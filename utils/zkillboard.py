"""
zKillboard API integration.

Fetches killmail details to enriched the basic ESI killmail hashes.
zKillboard is rate-limited — be polite (1 req/s).
"""
import asyncio
from typing import Optional

import httpx

_ZKB_BASE = "https://zkillboard.com/api"
_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "ESI-Checker/1.0 (EVE recruitment tool)",
}


async def get_character_kills(character_id: int, limit: int = 50) -> list[dict]:
    """
    Fetch recent kills and losses for a character from zKillboard.

    Returns list of killmail metadata dicts including victim/attacker info
    and ISK value.
    """
    url = f"{_ZKB_BASE}/kills/characterID/{character_id}/limit/{limit}/"
    async with httpx.AsyncClient(headers=_HEADERS, timeout=20.0) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, list) else []
            return []
        except Exception:
            return []


async def get_character_losses(character_id: int, limit: int = 50) -> list[dict]:
    """Fetch recent losses for a character."""
    url = f"{_ZKB_BASE}/losses/characterID/{character_id}/limit/{limit}/"
    async with httpx.AsyncClient(headers=_HEADERS, timeout=20.0) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, list) else []
            return []
        except Exception:
            return []


async def get_killmail_detail(killmail_id: int, killmail_hash: str) -> Optional[dict]:
    """
    Fetch full killmail detail from zKillboard.

    Note: zKillboard redirects to ESI killmail endpoint.
    Returns the zKillboard wrapper (includes ISK value, points, etc.)
    """
    url = f"{_ZKB_BASE}/killID/{killmail_id}/"
    async with httpx.AsyncClient(headers=_HEADERS, timeout=15.0) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                return data[0] if data else None
            return None
        except Exception:
            return None


async def fetch_enriched_killmails(
    character_id: int,
    esi_killmails: list[dict],
    max_fetch: int = 25,
) -> list[dict]:
    """
    Fetch enriched killmail data from zKillboard for analysis.

    Args:
        character_id:   The applicant's character ID
        esi_killmails:  Raw ESI killmail list [{killmail_id, killmail_hash}]
        max_fetch:      Maximum killmails to enrich (to avoid rate limits)

    Returns list of enriched killmail dicts with victim/attacker details.
    """
    # Prefer the character-level zKillboard endpoint (faster, single call)
    zkb_kills = await get_character_kills(character_id, limit=max_fetch)
    await asyncio.sleep(1)  # Be polite to zKillboard
    zkb_losses = await get_character_losses(character_id, limit=max_fetch)

    return zkb_kills + zkb_losses


async def get_corp_kill_summary(corporation_id: int) -> dict:
    """
    Get basic kill/loss statistics for a corporation from zKillboard.

    Useful for cross-referencing watchlist corps.
    """
    url = f"{_ZKB_BASE}/corporationID/{corporation_id}/limit/10/"
    async with httpx.AsyncClient(headers=_HEADERS, timeout=15.0) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                kills = resp.json()
                return {"recent_activity": len(kills), "sample": kills[:3]}
            return {}
        except Exception:
            return {}
