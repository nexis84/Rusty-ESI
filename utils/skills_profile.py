"""
Classify EVE character skills into PVP / Industry / Support / General buckets.

Uses ESI /universe/types/{skill_id}/ to resolve group_id per skill type,
then maps group_id to a role category.  Results are cached module-level so
the first review page load populates the cache and all subsequent loads are
instant (EVE type data is static).
"""

import asyncio
import httpx

# ---------------------------------------------------------------------------
# EVE SDE group_id → broad role mapping
# ---------------------------------------------------------------------------
_GROUP_ROLE: dict[int, str] = {
    255: "pvp",       # Gunnery
    256: "pvp",       # Missile Launcher Operation
    257: "pvp",       # Spaceship Command (racial ship skills)
    258: "support",   # Leadership
    266: "support",   # Corp Management
    268: "industry",  # Trade
    269: "pvp",       # Navigation (AB, MWD, jump drive)
    270: "industry",  # Science
    272: "pvp",       # Electronic Systems (ECM, targeting, etc.)
    273: "pvp",       # Drones
    274: "support",   # Engineering (cap, CPU, power grid)
    275: "support",   # Shields (shield tank / regen)
    1209: "support",  # Shield Compensation skills
    1210: "support",  # Armor
    1211: "support",  # Rigging
    1212: "support",  # Subsystems (T3 cruisers)
    1213: "pvp",      # Turrets & Bays (turret specs)
    1214: "pvp",      # Targeting
    1215: "support",  # Fleet Support
    1216: "support",  # Neural Enhancement (implant / biology skills)
    1217: "pvp",      # Scanning / Exploration
    1218: "industry", # Resource Processing (ore / reprocessing)
    1219: "support",  # Structure Management
    1220: "industry", # Planet Management (PI)
    1241: "support",  # Social
    1322: "industry", # Manufacturing Experience
}

# Module-level cache: skill_id (typeID) → group_id  (static EVE data)
_skill_group_cache: dict[int, int] = {}

_ROLE_LABELS = {
    "pvp": "PVP",
    "industry": "Industry",
    "support": "Support / Core",
    "general": "General",
}


# ---------------------------------------------------------------------------
# Internal helper: resolve group_id via ESI with concurrency cap
# ---------------------------------------------------------------------------

async def _fetch_group_id(
    skill_id: int, esi_base: str, sem: asyncio.Semaphore
) -> tuple[int, int]:
    if skill_id in _skill_group_cache:
        return skill_id, _skill_group_cache[skill_id]
    async with sem:
        if skill_id in _skill_group_cache:          # re-check after acquiring
            return skill_id, _skill_group_cache[skill_id]
        try:
            async with httpx.AsyncClient(timeout=10.0) as http:
                resp = await http.get(
                    f"{esi_base}/universe/types/{skill_id}/",
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                group_id = resp.json().get("group_id", 0)
        except Exception:
            group_id = 0
        _skill_group_cache[skill_id] = group_id
        return skill_id, group_id


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def classify_skills(skills: list[dict], esi_base: str) -> dict:
    """
    Given the raw ESI skills list, classify SP into role buckets.

    Args:
        skills:   list of {skill_id, skillpoints_in_skill, active_skill_level, …}
        esi_base: ESI base URL, e.g. 'https://esi.evetech.net/latest'

    Returns a dict with:
        pvp_sp, industry_sp, support_sp, general_sp  – raw SP totals
        pvp_pct, industry_pct, support_pct            – integer percentages
        primary_role                                  – dominant role label
        secondary_roles                               – list of roles with ≥ 20 % share
        top_pvp, top_industry, top_support            – top-5 skill dicts each
    """
    if not skills:
        return _empty_profile()

    skill_ids = list({s["skill_id"] for s in skills if isinstance(s, dict) and "skill_id" in s})
    sem = asyncio.Semaphore(20)
    results = await asyncio.gather(
        *[_fetch_group_id(sid, esi_base, sem) for sid in skill_ids]
    )
    id_to_group = dict(results)

    sp: dict[str, int] = {"pvp": 0, "industry": 0, "support": 0, "general": 0}
    buckets: dict[str, list] = {"pvp": [], "industry": [], "support": [], "general": []}

    for skill in skills:
        if not isinstance(skill, dict):
            continue
        sid = skill.get("skill_id", 0)
        skill_sp = skill.get("skillpoints_in_skill", 0) or 0
        level = skill.get("active_skill_level", 0) or 0
        group_id = id_to_group.get(sid, 0)
        role = _GROUP_ROLE.get(group_id, "general")
        sp[role] += skill_sp
        buckets[role].append({"skill_id": sid, "sp": skill_sp, "level": level})

    total = sum(sp.values()) or 1

    for role in buckets:
        buckets[role].sort(key=lambda x: x["sp"], reverse=True)
        buckets[role] = buckets[role][:5]

    dominant = max(("pvp", "industry", "support", "general"), key=lambda r: sp[r])
    secondary = [r for r in ("pvp", "industry", "support") if r != dominant and sp[r] / total >= 0.20]

    return {
        "pvp_sp": sp["pvp"],
        "industry_sp": sp["industry"],
        "support_sp": sp["support"],
        "general_sp": sp["general"],
        "pvp_pct": int(sp["pvp"] / total * 100),
        "industry_pct": int(sp["industry"] / total * 100),
        "support_pct": int(sp["support"] / total * 100),
        "primary_role": _ROLE_LABELS.get(dominant, "Unclassified"),
        "secondary_roles": [_ROLE_LABELS[r] for r in secondary],
        "top_pvp": buckets["pvp"],
        "top_industry": buckets["industry"],
        "top_support": buckets["support"],
    }


def _empty_profile() -> dict:
    return {
        "pvp_sp": 0, "industry_sp": 0, "support_sp": 0, "general_sp": 0,
        "pvp_pct": 0, "industry_pct": 0, "support_pct": 0,
        "primary_role": "Unknown", "secondary_roles": [],
        "top_pvp": [], "top_industry": [], "top_support": [],
    }
