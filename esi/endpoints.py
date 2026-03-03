"""
ESI endpoint fetchers — one function per data type needed for analysis.
Each function takes an EsiClient (authenticated) and a character_id.
"""
import asyncio
from typing import Optional

from esi.client import EsiClient


# ---------------------------------------------------------------------------
# Public endpoints (no EsiClient needed)
# ---------------------------------------------------------------------------

async def get_character_public(character_id: int) -> dict:
    """Character name, corp, alliance, birthday, security status."""
    return await EsiClient.public_get(f"/characters/{character_id}/")


async def get_corporation_public(corporation_id: int) -> dict:
    """Corporation name, alliance, ticker, member count."""
    return await EsiClient.public_get(f"/corporations/{corporation_id}/")


async def get_alliance_public(alliance_id: int) -> dict:
    """Alliance name, ticker, executor corp."""
    return await EsiClient.public_get(f"/alliances/{alliance_id}/")


async def get_corp_history(character_id: int) -> list:
    """
    Full corporation history (public).
    Returns list of {corporation_id, is_deleted, record_id, start_date}
    """
    return await EsiClient.public_get(
        f"/characters/{character_id}/corporationhistory/"
    )


async def get_corp_alliance_history(corporation_id: int) -> list:
    """
    Alliance history for a corporation (public).
    Returns list of {alliance_id, is_deleted, record_id, start_date}
    """
    result = await EsiClient.public_get(
        f"/corporations/{corporation_id}/alliancehistory/"
    )
    return result if isinstance(result, list) else []


# ---------------------------------------------------------------------------
# Authenticated endpoints
# ---------------------------------------------------------------------------

async def get_skills(client: EsiClient, character_id: int) -> dict:
    """Total skill points and individual skills."""
    return await client.get(f"/characters/{character_id}/skills/")


async def get_wallet_balance(client: EsiClient, character_id: int) -> float:
    """Current ISK wallet balance."""
    return await client.get(f"/characters/{character_id}/wallet/")


async def get_wallet_journal(
    client: EsiClient, character_id: int, page: int = 1
) -> list:
    """Wallet journal entries (transactions, transfers)."""
    return await client.get(
        f"/characters/{character_id}/wallet/journal/",
        params={"page": page},
    )


async def get_wallet_transactions(
    client: EsiClient, character_id: int
) -> list:
    """Market transaction history."""
    return await client.get(
        f"/characters/{character_id}/wallet/transactions/"
    )


async def get_contacts(client: EsiClient, character_id: int) -> list:
    """
    Character contact list with standings.
    Returns [{contact_id, contact_type, is_blocked, is_watched, standing}]
    """
    return await client.get(f"/characters/{character_id}/contacts/")


async def get_assets(client: EsiClient, character_id: int, page: int = 1) -> list:
    """All character assets across all locations."""
    return await client.get(
        f"/characters/{character_id}/assets/",
        params={"page": page},
    )


async def get_clones(client: EsiClient, character_id: int) -> dict:
    """Home clone and jump clone locations."""
    return await client.get(f"/characters/{character_id}/clones/")


async def get_killmails(client: EsiClient, character_id: int) -> list:
    """Recent killmail hashes (last ~1000)."""
    return await client.get(f"/characters/{character_id}/killmails/recent/")


async def get_location(client: EsiClient, character_id: int) -> dict:
    """Current solar system and station/structure."""
    return await client.get(f"/characters/{character_id}/location/")


async def get_mail_headers(
    client: EsiClient, character_id: int, labels: Optional[list] = None
) -> list:
    """Mail headers (subject, from, to, timestamp — NOT body)."""
    params = {}
    if labels:
        params["labels"] = ",".join(str(l) for l in labels)
    return await client.get(
        f"/characters/{character_id}/mail/",
        params=params,
    )


async def get_ship_type(client: EsiClient, character_id: int) -> dict:
    """Currently boarded ship — type ID, item ID, and custom name."""
    return await client.get(f"/characters/{character_id}/ship/")


async def get_corporation_contacts(client: EsiClient, corporation_id: int, page: int = 1) -> list:
    """
    Corporation contact list with standings (requires director role +
    esi-corporations.read_contacts.v1).
    Returns [{contact_id, contact_type, standing}]
    """
    return await client.get(
        f"/corporations/{corporation_id}/contacts/",
        params={"page": page},
    )


async def get_alliance_contacts(client: EsiClient, alliance_id: int, page: int = 1) -> list:
    """
    Alliance contact list with standings (requires executor director role +
    esi-alliances.read_contacts.v1).
    Returns [{contact_id, contact_type, standing}]
    """
    return await client.get(
        f"/alliances/{alliance_id}/contacts/",
        params={"page": page},
    )


async def fetch_all_contacts_paged(
    client: EsiClient,
    fetch_fn,
    entity_id: int,
) -> list:
    """Fetch all pages of contacts for a corp or alliance."""
    import asyncio
    page = 1
    all_contacts = []
    while True:
        page_data = await fetch_fn(client, entity_id, page=page)
        if not isinstance(page_data, list) or not page_data:
            break
        all_contacts.extend(page_data)
        if len(page_data) < 1000:
            break
        page += 1
    return all_contacts


async def get_system_public(system_id: int) -> dict:
    """Solar system name and security status."""
    return await EsiClient.public_get(f"/universe/systems/{system_id}/")


async def get_station_public(station_id: int) -> dict:
    """Station name and system."""
    return await EsiClient.public_get(f"/universe/stations/{station_id}/")


async def resolve_ids(ids: list[int]) -> dict:
    """Bulk-resolve EVE IDs to categories (character, corporation, etc.)."""
    if not ids:
        return {}
    async with __import__("httpx").AsyncClient(timeout=15.0) as http:
        resp = await http.post(
            f"{__import__('config').settings.esi_base_url}/universe/names/",
            json=ids[:1000],  # ESI limit: 1000 per request
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        return {item["id"]: item for item in resp.json()}


# ---------------------------------------------------------------------------
# Aggregate fetcher — collects all data for one applicant in parallel
# ---------------------------------------------------------------------------

async def fetch_all_applicant_data(
    client: EsiClient, character_id: int
) -> dict:
    """
    Fetch all ESI data needed for analysis in parallel.

    Returns a dict with keys matching each data category.
    Individual failures are caught and stored as None so one
    bad scope doesn't block the whole report.
    """

    async def safe(coro, key: str) -> tuple[str, any]:
        try:
            return key, await coro
        except Exception as exc:
            return key, {"error": str(exc)}

    tasks = [
        safe(get_character_public(character_id), "character_public"),
        safe(get_corp_history(character_id), "corp_history"),
        safe(get_skills(client, character_id), "skills"),
        safe(get_wallet_balance(client, character_id), "wallet_balance"),
        safe(get_wallet_journal(client, character_id), "wallet_journal"),
        safe(get_contacts(client, character_id), "contacts"),
        safe(get_assets(client, character_id), "assets"),
        safe(get_clones(client, character_id), "clones"),
        safe(get_killmails(client, character_id), "killmails"),
        safe(get_location(client, character_id), "location"),
        safe(get_mail_headers(client, character_id), "mail_headers"),
        safe(get_ship_type(client, character_id), "ship"),
    ]

    results = await asyncio.gather(*tasks)
    data = dict(results)

    # Enrich public character data with corp/alliance names
    pub = data.get("character_public", {})
    if isinstance(pub, dict) and "corporation_id" in pub:
        corp_id = pub["corporation_id"]
        alliance_id = pub.get("alliance_id")
        corp_tasks = [safe(get_corporation_public(corp_id), "corp_public")]
        if alliance_id:
            corp_tasks.append(safe(get_alliance_public(alliance_id), "alliance_public"))
        extra = await asyncio.gather(*corp_tasks)
        data.update(dict(extra))

    # Enrich corp history entries with corp names
    corp_history = data.get("corp_history", [])
    if isinstance(corp_history, list) and corp_history:
        corp_ids = list({entry.get("corporation_id") for entry in corp_history if entry.get("corporation_id")})
        try:
            id_map = await resolve_ids(corp_ids)
            for entry in corp_history:
                cid = entry.get("corporation_id")
                if cid and cid in id_map:
                    entry["corp_name"] = id_map[cid].get("name", "")
        except Exception:
            pass

    return data
