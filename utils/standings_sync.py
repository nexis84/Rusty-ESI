"""
Standings sync — pulls corp/alliance contacts from a director service account
and caches them in the standings_cache table.

Called:
  • Manually via POST /admin/service-account/sync
  • Every hour via the background asyncio task started in app lifespan
"""
import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from database.db import SessionLocal
from database.models import ServiceAccount, StandingCache
from auth.eve_sso import decrypt_token, encrypt_token, refresh_access_token, token_expires_at
from esi.client import EsiClient
from esi.endpoints import (
    get_alliance_contacts,
    fetch_all_contacts_paged, resolve_ids, get_character_public,
)

log = logging.getLogger(__name__)


async def _refresh_service_account(sa: ServiceAccount, db: Session) -> tuple[str, str, int]:
    """Return (access_token, refresh_token, expires_at), refreshing if stale."""
    import time
    access = decrypt_token(sa.access_token_enc)
    refresh = decrypt_token(sa.refresh_token_enc)
    expires = sa.token_expires_at

    if time.time() >= expires:
        token_data = await refresh_access_token(refresh)
        access = token_data["access_token"]
        refresh = token_data.get("refresh_token", refresh)
        expires = token_expires_at(token_data["expires_in"])
        sa.access_token_enc = encrypt_token(access)
        sa.refresh_token_enc = encrypt_token(refresh)
        sa.token_expires_at = expires
        db.commit()

    return access, refresh, expires


async def sync_standings(db: Session | None = None) -> str:
    """
    Fetch corp & alliance contacts for the registered service account and
    upsert them into standings_cache.

    Returns a human-readable status string.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        sa = db.query(ServiceAccount).first()
        if not sa:
            return "No service account registered."

        access, refresh, expires = await _refresh_service_account(sa, db)

        async def on_refresh(new_access, new_refresh, new_expires):
            sa.access_token_enc = encrypt_token(new_access)
            sa.refresh_token_enc = encrypt_token(new_refresh)
            sa.token_expires_at = new_expires
            db.commit()

        contacts: list[dict] = []

        async with EsiClient(access, refresh, expires, on_token_refresh=on_refresh) as client:
            if not sa.alliance_id:
                msg = "No alliance ID on service account — cannot sync alliance contacts."
                sa.sync_status = msg
                sa.last_sync = datetime.now(timezone.utc)
                db.commit()
                return msg
            try:
                alliance_contacts = await fetch_all_contacts_paged(
                    client, get_alliance_contacts, sa.alliance_id
                )
                for c in alliance_contacts:
                    c["_source"] = "alliance"
                contacts.extend(alliance_contacts)
                log.info("Fetched %d alliance contacts", len(alliance_contacts))
            except Exception as exc:
                msg = f"Alliance contacts ESI error: {exc}"
                log.warning(msg)
                sa.sync_status = msg[:2000]  # guard against oversized messages
                sa.last_sync = datetime.now(timezone.utc)
                db.commit()
                return msg

        if not contacts:
            msg = "Sync ran but no contacts returned (check director roles/scopes)."
            sa.sync_status = msg
            sa.last_sync = datetime.now(timezone.utc)
            db.commit()
            return msg

        # Deduplicate by entity_id (alliance entry wins over corp if duplicate)
        seen: dict[int, dict] = {}
        for c in contacts:
            eid = c.get("contact_id")
            if eid:
                seen[eid] = c

        # Clear the entire cache before repopulating so stale entries are removed
        db.query(StandingCache).delete()
        db.commit()

        # Bulk-resolve names (1000 at a time)
        all_ids = list(seen.keys())
        name_map: dict[int, str] = {}
        for i in range(0, len(all_ids), 1000):
            chunk = all_ids[i:i + 1000]
            try:
                resolved = await resolve_ids(chunk)
                for eid, info in resolved.items():
                    name_map[eid] = info.get("name", "")
            except Exception as exc:
                log.warning("Name resolution failed for chunk: %s", exc)

        # Insert fresh alliance contacts into standings_cache
        upserted = 0
        for eid, c in seen.items():
            standing = c.get("standing", 0.0)
            entity_type = c.get("contact_type", "unknown")
            source = c.get("_source", "alliance")
            name = name_map.get(eid, "")
            db.add(StandingCache(
                entity_id=eid,
                entity_type=entity_type,
                entity_name=name,
                standing=standing,
                source=source,
            ))
            upserted += 1

        sa.last_sync = datetime.now(timezone.utc)
        sa.sync_status = f"OK — {upserted} entities cached"
        db.commit()
        log.info("Standings sync complete: %d entities", upserted)
        return sa.sync_status

    except Exception as exc:
        log.exception("Standings sync error")
        msg = f"Error: {exc}"
        try:
            sa = db.query(ServiceAccount).first()
            if sa:
                sa.sync_status = msg
                sa.last_sync = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
        return msg
    finally:
        if close_db:
            db.close()


# ---------------------------------------------------------------------------
# Background hourly task
# ---------------------------------------------------------------------------

async def standings_sync_loop():
    """Runs indefinitely, syncing standings every hour."""
    while True:
        await asyncio.sleep(3600)
        try:
            result = await sync_standings()
            log.info("Hourly standings sync: %s", result)
        except Exception as exc:
            log.exception("Hourly standings sync failed: %s", exc)
