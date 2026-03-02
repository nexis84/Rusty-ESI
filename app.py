"""
Main FastAPI application — routes, session management, and background tasks.

Run with:
    python app.py
or:
    uvicorn app:app --reload
"""
import json
import os
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from contextlib import asynccontextmanager

from fastapi import (
    BackgroundTasks, Depends, FastAPI, Form, HTTPException,
    Request, Response,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from config import settings
from database.db import get_db, init_db
from database.models import (
    Application, AuditLog, InviteLink, Recruiter, WatchlistEntry,
)
from auth.eve_sso import (
    build_auth_url, decrypt_token, encrypt_token,
    exchange_code, refresh_access_token, token_expires_at, verify_token,
)
from esi.client import EsiClient
from esi.endpoints import fetch_all_applicant_data
from analysis.scorer import calculate_trust_score, WEIGHTS
from utils.zkillboard import fetch_enriched_killmails


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="ESI Checker", docs_url=None, redoc_url=None, lifespan=lifespan)

# Detect production environments (Render sets RENDER, HF Spaces sets SPACE_ID)
_on_render = os.environ.get("RENDER", "") != "" or os.environ.get("SPACE_ID", "") != ""

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie="esi_checker_session",
    https_only=_on_render,   # True on Render (HTTPS), False locally
    same_site="lax",
)

app.mount("/static", StaticFiles(directory="web/static"), name="static")
templates = Jinja2Templates(directory="web/templates")


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _render(request: Request, template: str, ctx: dict = None) -> HTMLResponse:
    context = {
        "request": request,
        "session_char": request.session.get("character_name"),
        "flash_error": request.session.pop("flash_error", None),
        "flash_success": request.session.pop("flash_success", None),
        "csrf_token": request.session.get("csrf_token", ""),
        "now": datetime.now(timezone.utc),
        "weights": WEIGHTS,
    }
    if ctx:
        context.update(ctx)
    return templates.TemplateResponse(template, context)


def _require_recruiter(request: Request) -> int:
    """Return recruiter character_id from session, or redirect to login."""
    char_id = request.session.get("character_id")
    if not char_id:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return char_id


def _csrf_ok(request: Request, token: str) -> bool:
    return secrets.compare_digest(
        request.session.get("csrf_token", ""), token or ""
    )


# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return RedirectResponse("/login")


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    url, state = build_auth_url("recruiter")
    request.session["oauth_state"] = state
    request.session["oauth_role"] = "recruiter"
    # Fresh CSRF token on every login page load
    request.session["csrf_token"] = secrets.token_hex(32)
    return _render(request, "login.html", {"login_url": url, "error": error})


@app.get("/auth/callback")
async def auth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if error:
        return RedirectResponse(f"/login?error={error}")

    if not code or not state:
        return RedirectResponse("/login?error=missing_code")

    # --- CSRF / state verification ---
    role = request.session.get("oauth_role", "recruiter")
    stored_state = request.session.get("oauth_state", "")

    # State may have extra data after ':'
    base_state = state.split(":")[0]
    stored_base = stored_state.split(":")[0]

    if not secrets.compare_digest(base_state, stored_base):
        return RedirectResponse("/login?error=state_mismatch")

    # --- Exchange code for tokens ---
    try:
        tokens = await exchange_code(code)
    except Exception as exc:
        return RedirectResponse(f"/login?error=token_exchange_failed")

    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token", "")
    expires_at = token_expires_at(tokens.get("expires_in", 1200))

    # --- Verify token and get character info ---
    try:
        char_info = await verify_token(access_token)
    except Exception:
        return RedirectResponse("/login?error=verification_failed")

    character_id = char_info.get("CharacterID")
    character_name = char_info.get("CharacterName", "Unknown")

    if role == "recruiter":
        return await _handle_recruiter_callback(
            request, db, character_id, character_name,
            access_token, refresh_token, expires_at,
        )
    else:
        # Applicant callback — state encodes the invite token
        invite_token = state.split(":", 1)[1] if ":" in state else ""
        return await _handle_applicant_callback(
            request, db, character_id, character_name,
            access_token, refresh_token, expires_at, invite_token,
        )


async def _handle_recruiter_callback(
    request, db, character_id, character_name,
    access_token, refresh_token, expires_at,
):
    """Verify recruiter is in the corp, create/update DB record, set session."""
    # Check corp membership via ESI
    from esi.endpoints import get_character_public
    try:
        pub = await get_character_public(character_id)
        corp_id = pub.get("corporation_id", 0)
    except Exception:
        corp_id = 0

    if settings.your_corp_id != 0 and corp_id != settings.your_corp_id:
        request.session["flash_error"] = (
            f"Character '{character_name}' is not in the configured corporation. "
            "Only corp members can access this tool."
        )
        return RedirectResponse("/login")

    # Upsert recruiter
    recruiter = db.query(Recruiter).filter_by(character_id=character_id).first()
    if not recruiter:
        recruiter = Recruiter(
            character_id=character_id,
            character_name=character_name,
            corporation_id=corp_id,
        )
        db.add(recruiter)
    else:
        recruiter.last_login = datetime.now(timezone.utc)
        recruiter.character_name = character_name

    db.commit()

    request.session["character_id"] = character_id
    request.session["character_name"] = character_name
    request.session["recruiter_id"] = recruiter.id
    request.session["csrf_token"] = secrets.token_hex(32)

    return RedirectResponse("/dashboard")


async def _handle_applicant_callback(
    request, db, character_id, character_name,
    access_token, refresh_token, expires_at, invite_token,
):
    """Store applicant tokens, trigger ESI fetch, redirect to done page."""
    invite = db.query(InviteLink).filter_by(token=invite_token).first()
    if not invite or invite.is_used or invite.expires_at < datetime.now(timezone.utc):
        return _render(request, "application.html", {"expired": True})

    # Create application record
    app_record = Application(
        invite_id=invite.id,
        character_id=character_id,
        character_name=character_name,
        access_token_enc=encrypt_token(access_token),
        refresh_token_enc=encrypt_token(refresh_token),
        token_expires_at=expires_at,
        status="fetching",
    )
    db.add(app_record)
    invite.is_used = True
    db.commit()
    db.refresh(app_record)

    # Kick off background ESI fetch (non-blocking)
    # We do a manual background task via FastAPI's BackgroundTasks elsewhere;
    # here we use asyncio to schedule it without blocking the response.
    import asyncio
    asyncio.create_task(_fetch_and_score(app_record.id))

    return _render(request, "application.html", {"completed": True})


# ---------------------------------------------------------------------------
# Background ESI fetch + scoring
# ---------------------------------------------------------------------------

async def _fetch_and_score(application_id: int):
    """
    Background coroutine: fetch ESI data for an applicant and run analysis.
    Runs after the applicant completes OAuth.
    """
    from database.db import SessionLocal
    db = SessionLocal()
    try:
        app_rec = db.query(Application).filter_by(id=application_id).first()
        if not app_rec:
            return

        access_token = decrypt_token(app_rec.access_token_enc)
        refresh_token = decrypt_token(app_rec.refresh_token_enc)
        expires_at = app_rec.token_expires_at

        async def on_refresh(new_access, new_refresh, new_expires):
            app_rec.access_token_enc = encrypt_token(new_access)
            app_rec.refresh_token_enc = encrypt_token(new_refresh)
            app_rec.token_expires_at = new_expires
            db.commit()

        async with EsiClient(access_token, refresh_token, expires_at, on_refresh) as client:
            esi_data = await fetch_all_applicant_data(client, app_rec.character_id)

        # Fetch zKillboard data
        zkb_data = await fetch_enriched_killmails(
            app_rec.character_id,
            esi_data.get("killmails", []),
        )

        # Load watchlist
        watchlist = db.query(WatchlistEntry).all()
        hostile_ids = {w.entity_id for w in watchlist}
        watchlist_names = {w.entity_id: w.entity_name for w in watchlist}

        # Run analysis
        report = calculate_trust_score(
            esi_data=esi_data,
            hostile_ids=hostile_ids,
            watchlist_names=watchlist_names,
            hostile_system_ids=set(),       # Can be populated from a config file
            hostile_structure_ids=set(),    # Can be populated from a config file
            corp_member_ids=set(),          # Can be populated from ESI corp roster
            zkb_data=zkb_data,
        )

        # Persist results
        app_rec.set_esi_data(esi_data)
        app_rec.set_red_flags(report.red_flags)
        app_rec.set_score_breakdown(report.score_breakdown)
        app_rec.zkb_data_json = json.dumps(zkb_data[:20])  # Store sample
        app_rec.trust_score = report.score
        app_rec.score_band = report.band
        app_rec.recommendation = report.recommendation
        app_rec.status = "scored"
        app_rec.scored_at = datetime.now(timezone.utc)
        db.commit()

    except Exception as exc:
        if db:
            app_rec = db.query(Application).filter_by(id=application_id).first()
            if app_rec:
                app_rec.status = "pending"
                app_rec.recommendation = f"Analysis error: {exc}"
                db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Recruiter routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if request.session.get("character_id"):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    status: Optional[str] = "all",
    db: Session = Depends(get_db),
):
    _require_recruiter(request)

    query = db.query(Application)
    if status and status != "all":
        query = query.filter(Application.status == status)
    applications = query.order_by(Application.submitted_at.desc()).all()

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    stats = {
        "pending": db.query(Application).filter(Application.status.in_(["pending", "fetching", "scored"])).count(),
        "approved": db.query(Application).filter(
            Application.decision == "approved",
            Application.decided_at >= thirty_days_ago,
        ).count(),
        "denied": db.query(Application).filter(
            Application.decision == "denied",
            Application.decided_at >= thirty_days_ago,
        ).count(),
    }

    return _render(request, "dashboard.html", {
        "applications": applications,
        "current_status": status,
        "stats": stats,
    })


@app.get("/applications/{app_id}", response_class=HTMLResponse)
async def review_application(
    request: Request,
    app_id: int,
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    app_rec = db.query(Application).filter_by(id=app_id).first()
    if not app_rec:
        raise HTTPException(404)

    esi_data = app_rec.get_esi_data()
    flags_raw = app_rec.get_red_flags()
    breakdown = app_rec.get_score_breakdown()

    # Enrich corp history with names if not already present
    corp_history = esi_data.get("corp_history", []) if isinstance(esi_data, dict) else []
    if isinstance(corp_history, list) and corp_history:
        missing = [e["corporation_id"] for e in corp_history if isinstance(e, dict) and not e.get("corp_name")]
        if missing:
            try:
                from esi.endpoints import resolve_ids
                id_map = await resolve_ids(list(set(missing)))
                for entry in corp_history:
                    cid = entry.get("corporation_id")
                    if cid and cid in id_map and not entry.get("corp_name"):
                        entry["corp_name"] = id_map[cid].get("name", "")
            except Exception:
                pass

    # Convert flag dicts back to objects for template
    from analysis.red_flags import RedFlag
    flags = [RedFlag(**f) for f in flags_raw]

    # Classify skills into PVP / Industry / Support buckets
    from utils.skills_profile import classify_skills
    skills_list = []
    if isinstance(esi_data, dict):
        skills_raw = esi_data.get("skills") or {}
        if isinstance(skills_raw, dict):
            skills_list = skills_raw.get("skills", []) or []
    skill_profile = await classify_skills(skills_list, settings.esi_base_url)

    # Resolve ship type name for the current ship
    if isinstance(esi_data, dict):
        ship = esi_data.get("ship") or {}
        if isinstance(ship, dict) and ship.get("ship_type_id") and not ship.get("error"):
            try:
                ship_type = await EsiClient.public_get(
                    f"/universe/types/{ship['ship_type_id']}/"
                )
                ship["ship_type_name"] = ship_type.get("name", "Unknown")
            except Exception:
                ship["ship_type_name"] = "Unknown"

    # Resolve location names (system + station if applicable)
    location_display = None
    if isinstance(esi_data, dict):
        loc = esi_data.get("location") or {}
        if isinstance(loc, dict) and not loc.get("error"):
            system_id = loc.get("solar_system_id")
            station_id = loc.get("station_id")
            if system_id:
                try:
                    from esi.endpoints import get_system_public, get_station_public
                    sys_data = await get_system_public(system_id)
                    system_name = sys_data.get("name", f"System #{system_id}")
                    sec = sys_data.get("security_status", 0.0)
                    sec_str = f"{sec:.1f}"
                    station_name = None
                    if station_id and station_id < 64_000_000:  # NPC station
                        try:
                            sta_data = await get_station_public(station_id)
                            station_name = sta_data.get("name")
                        except Exception:
                            pass
                    location_display = {
                        "system": system_name,
                        "station": station_name,
                        "sec": sec_str,
                        "sec_float": sec,
                    }
                except Exception:
                    pass

    return _render(request, "review.html", {
        "app": app_rec,
        "esi": esi_data,
        "flags": flags,
        "breakdown": breakdown,
        "skill_profile": skill_profile,
        "location_display": location_display,
    })


@app.post("/applications/{app_id}/decide")
async def decide_application(
    request: Request,
    app_id: int,
    decision: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    if not _csrf_ok(request, csrf_token):
        raise HTTPException(403, "Invalid CSRF token")
    if decision not in ("approved", "denied", "hold"):
        raise HTTPException(400)

    app_rec = db.query(Application).filter_by(id=app_id).first()
    if not app_rec:
        raise HTTPException(404)

    recruiter_id = request.session.get("recruiter_id")
    app_rec.decision = decision
    app_rec.decision_by = recruiter_id
    app_rec.decided_at = datetime.now(timezone.utc)
    app_rec.status = decision

    log = AuditLog(
        recruiter_id=recruiter_id,
        application_id=app_id,
        action=decision,
        detail=f"{request.session.get('character_name')} marked application as {decision}",
    )
    db.add(log)
    db.commit()

    request.session["flash_success"] = f"Application {decision}."
    return RedirectResponse(f"/applications/{app_id}", status_code=303)


@app.post("/applications/{app_id}/notes")
async def save_notes(
    request: Request,
    app_id: int,
    notes: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    if not _csrf_ok(request, csrf_token):
        raise HTTPException(403)

    app_rec = db.query(Application).filter_by(id=app_id).first()
    if not app_rec:
        raise HTTPException(404)

    app_rec.recruiter_notes = notes[:5000]  # Cap length
    db.commit()
    request.session["flash_success"] = "Notes saved."
    return RedirectResponse(f"/applications/{app_id}", status_code=303)


@app.post("/applications/{app_id}/reanalyze")
async def reanalyze_application(
    request: Request,
    app_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    if not _csrf_ok(request, csrf_token):
        raise HTTPException(403, "Invalid CSRF token")

    app_rec = db.query(Application).filter_by(id=app_id).first()
    if not app_rec:
        raise HTTPException(404)

    # Reset state so the background task overwrites the old error
    app_rec.status = "fetching"
    app_rec.recommendation = None
    db.commit()

    import asyncio
    asyncio.create_task(_fetch_and_score(app_id))

    request.session["flash_success"] = "Re-analysis started — refresh in a moment."
    return RedirectResponse(f"/applications/{app_id}", status_code=303)


@app.post("/applications/{app_id}/delete")
async def delete_application(
    request: Request,
    app_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    if not _csrf_ok(request, csrf_token):
        raise HTTPException(403, "Invalid CSRF token")

    app_rec = db.query(Application).filter_by(id=app_id).first()
    if not app_rec:
        raise HTTPException(404)

    char_name = app_rec.character_name
    recruiter_id = request.session.get("recruiter_id")

    # Null out FK references in audit log so the DELETE doesn't violate the constraint
    db.query(AuditLog).filter(AuditLog.application_id == app_id).update({"application_id": None})

    db.delete(app_rec)
    db.flush()  # ensure the DELETE is sent before the INSERT

    log = AuditLog(
        recruiter_id=recruiter_id,
        application_id=None,
        action="deleted",
        detail=f"{request.session.get('character_name')} deleted application for {char_name}",
    )
    db.add(log)
    db.commit()

    request.session["flash_success"] = f"Application for {char_name} deleted."
    return RedirectResponse("/dashboard", status_code=303)


# ---------------------------------------------------------------------------
# Invite link routes
# ---------------------------------------------------------------------------

@app.get("/invites", response_class=HTMLResponse)
async def invites_page(request: Request, db: Session = Depends(get_db)):
    _require_recruiter(request)
    invites = db.query(InviteLink).order_by(InviteLink.created_at.desc()).limit(50).all()
    return _render(request, "invites.html", {
        "invites": invites,
        "new_invite_url": request.session.pop("new_invite_url", None),
    })


@app.get("/invites/new", response_class=HTMLResponse)
async def invites_new_get(request: Request, db: Session = Depends(get_db)):
    _require_recruiter(request)
    invites = db.query(InviteLink).order_by(InviteLink.created_at.desc()).limit(50).all()
    return _render(request, "invites.html", {
        "invites": invites,
        "new_invite_url": request.session.pop("new_invite_url", None),
    })


@app.post("/invites/{invite_id}/delete")
async def delete_invite(
    request: Request,
    invite_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    if not _csrf_ok(request, csrf_token):
        raise HTTPException(403)
    invite = db.query(InviteLink).filter_by(id=invite_id).first()
    if not invite:
        raise HTTPException(404)

    # Delete the child application first (it has a non-nullable FK back to this invite)
    if invite.application:
        child_app_id = invite.application.id
        db.query(AuditLog).filter(AuditLog.application_id == child_app_id).update({"application_id": None})
        db.delete(invite.application)
        db.flush()

    db.delete(invite)
    db.commit()
    request.session["flash_success"] = "Invite link deleted."
    return RedirectResponse("/invites", status_code=303)


@app.post("/invites/new")
async def create_invite(
    request: Request,
    note: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    if not _csrf_ok(request, csrf_token):
        raise HTTPException(403)

    token = secrets.token_urlsafe(32)
    recruiter_id = request.session.get("recruiter_id")
    invite = InviteLink(
        token=token,
        created_by=recruiter_id,
        note=note[:200],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=72),
    )
    db.add(invite)
    db.commit()

    base_url = str(request.base_url).rstrip("/")
    invite_url = f"{base_url}/apply/{token}"
    request.session["new_invite_url"] = invite_url
    return RedirectResponse("/invites", status_code=303)


# ---------------------------------------------------------------------------
# Applicant-facing routes
# ---------------------------------------------------------------------------

@app.get("/apply/{token}", response_class=HTMLResponse)
async def apply_page(
    request: Request,
    token: str,
    db: Session = Depends(get_db),
):
    invite = db.query(InviteLink).filter_by(token=token).first()
    if not invite or invite.is_used or invite.expires_at < datetime.now(timezone.utc):
        return _render(request, "application.html", {"expired": True})

    # Build applicant auth URL encoding the invite token in state
    auth_url, state = build_auth_url("applicant", extra_state=token)
    request.session["oauth_state"] = state
    request.session["oauth_role"] = "applicant"

    return _render(request, "application.html", {
        "note": invite.note,
        "auth_url": auth_url,
    })


# ---------------------------------------------------------------------------
# Watchlist routes
# ---------------------------------------------------------------------------

@app.get("/watchlist", response_class=HTMLResponse)
async def watchlist_page(request: Request, db: Session = Depends(get_db)):
    _require_recruiter(request)
    entries = db.query(WatchlistEntry).order_by(WatchlistEntry.added_at.desc()).all()
    return _render(request, "watchlist.html", {"entries": entries})


@app.post("/watchlist/add")
async def watchlist_add(
    request: Request,
    entity_id: int = Form(...),
    entity_name: str = Form(...),
    entity_type: str = Form(...),
    reason: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    if not _csrf_ok(request, csrf_token):
        raise HTTPException(403)
    if entity_type not in ("corporation", "alliance"):
        raise HTTPException(400)

    existing = db.query(WatchlistEntry).filter_by(entity_id=entity_id).first()
    if existing:
        request.session["flash_error"] = "Entity already in watchlist."
        return RedirectResponse("/watchlist", status_code=303)

    entry = WatchlistEntry(
        entity_id=entity_id,
        entity_type=entity_type,
        entity_name=entity_name[:100],
        reason=reason[:200],
        added_by=request.session.get("recruiter_id", 1),
    )
    db.add(entry)
    db.commit()
    request.session["flash_success"] = f"Added {entity_name} to watchlist."
    return RedirectResponse("/watchlist", status_code=303)


@app.post("/watchlist/{entry_id}/remove")
async def watchlist_remove(
    request: Request,
    entry_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_recruiter(request)
    if not _csrf_ok(request, csrf_token):
        raise HTTPException(403)

    entry = db.query(WatchlistEntry).filter_by(id=entry_id).first()
    if entry:
        db.delete(entry)
        db.commit()
        request.session["flash_success"] = "Removed from watchlist."
    return RedirectResponse("/watchlist", status_code=303)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@app.get("/audit", response_class=HTMLResponse)
async def audit_log(request: Request, db: Session = Depends(get_db)):
    _require_recruiter(request)
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200).all()
    return _render(request, "audit.html", {"logs": logs})


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", settings.app_port))
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=port,
        reload=settings.debug and not _on_render,
    )
