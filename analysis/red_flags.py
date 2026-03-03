"""
Red flag detection rules.

Each rule is a function that takes the full ESI data dict and
a watchlist (hostile corp/alliance IDs) and returns a list of
RedFlag namedtuples: (category, severity, message, detail).

Severity: "critical" | "warning" | "info"
"""
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional


@dataclass
class RedFlag:
    category: str
    severity: str       # "critical" | "warning" | "info"
    message: str        # Short label shown in dashboard
    detail: str         # Explanation shown in full report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(s: str) -> datetime:
    """Parse ESI ISO8601 timestamp."""
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return _utcnow()


def _is_error(data) -> bool:
    return isinstance(data, dict) and "error" in data


# ---------------------------------------------------------------------------
# Rule: Corporation history — frequent hopping
# ---------------------------------------------------------------------------

def check_corp_history(
    corp_history: list,
    hostile_ids: set[int],
    watchlist_names: dict[int, str],
    standings: Optional[list[dict]] = None,
    corp_alliance_map: Optional[dict] = None,
) -> list[RedFlag]:
    flags = []
    if _is_error(corp_history) or not corp_history:
        return [RedFlag("Corp History", "warning", "Corp history unavailable", "ESI did not return corp history.")]

    # Sort by start date desc (most recent first)
    history = sorted(corp_history, key=lambda x: x.get("start_date", ""), reverse=True)

    # Count corps in last 6 months
    six_months_ago = _utcnow() - timedelta(days=180)
    recent_corps = [
        h for h in history
        if _parse_dt(h.get("start_date", "")) >= six_months_ago
    ]
    if len(recent_corps) >= 4:
        flags.append(RedFlag(
            "Corp History", "critical",
            f"Rapid corp hopping: {len(recent_corps)} corps in 6 months",
            f"Character has been in {len(recent_corps)} different corporations in the last 6 months. "
            "This is a common pattern for spies rotating cover identities.",
        ))
    elif len(recent_corps) >= 2:
        flags.append(RedFlag(
            "Corp History", "warning",
            f"{len(recent_corps)} corps in 6 months",
            "Moderate corp hopping — worth asking why they left their previous corp.",
        ))

    # Check for time in hostile corps/alliances (watchlist)
    for entry in history:
        corp_id = entry.get("corporation_id")
        if corp_id in hostile_ids:
            name = entry.get("corp_name") or watchlist_names.get(corp_id, f"Corp #{corp_id}")
            start = entry.get("start_date", "unknown")
            if isinstance(start, str) and len(start) >= 10:
                start = start[:10]
            flags.append(RedFlag(
                "Corp History", "critical",
                f"Previous member of hostile corp: {name}",
                f"This character was a member of {name} starting {start}. "
                "This corporation is on the hostile watchlist.",
            ))

    # Very short stints (under 7 days) suggest probing/spying
    for i in range(len(history) - 1):
        start = _parse_dt(history[i + 1].get("start_date", ""))
        end = _parse_dt(history[i].get("start_date", ""))
        days = (end - start).days
        entry = history[i + 1]
        corp_id = entry.get("corporation_id")
        corp_label = entry.get("corp_name") or f"Corp #{corp_id}"
        if 0 < days < 7 and corp_id != 1000006:  # Exclude Scope (NPC corp)
            flags.append(RedFlag(
                "Corp History", "warning",
                f"Very short corp tenure (<7 days)",
                f"Spent only {days} day(s) in {corp_label}. "
                "Short stints may indicate failed infiltration attempts.",
            ))
            break  # Only flag once

    # Flag historical alliances (via corp_alliance_map) that are on the watchlist
    if corp_alliance_map:
        seen_hostile_alliance_ids: set[int] = set()
        for entry in history:
            corp_id_h = entry.get("corporation_id")
            corp_name_h = entry.get("corp_name") or f"Corp #{corp_id_h}"
            for ally_entry in (corp_alliance_map.get(corp_id_h) or []):
                ally_id = ally_entry.get("alliance_id")
                if not ally_id or ally_id in seen_hostile_alliance_ids:
                    continue
                if ally_id in hostile_ids:
                    seen_hostile_alliance_ids.add(ally_id)
                    ally_name = ally_entry.get("alliance_name") or watchlist_names.get(ally_id, f"Alliance #{ally_id}")
                    ally_start = ally_entry.get("start_date", "")[:10]
                    flags.append(RedFlag(
                        "Corp History", "critical",
                        f"Historical corp in hostile alliance: {ally_name}",
                        f"{corp_name_h} was a member of {ally_name} from {ally_start}. "
                        "This alliance is on the hostile watchlist.",
                    ))

    return flags


# ---------------------------------------------------------------------------
# Rule: Contacts — standings toward hostiles
# ---------------------------------------------------------------------------

def check_contacts(contacts: list, hostile_ids: set[int]) -> list[RedFlag]:
    flags = []
    if _is_error(contacts) or not isinstance(contacts, list):
        return []

    high_standing_hostiles = [
        c for c in contacts
        if c.get("contact_id") in hostile_ids and c.get("standing", 0) >= 5.0
    ]
    if high_standing_hostiles:
        names = ", ".join(str(c["contact_id"]) for c in high_standing_hostiles)
        flags.append(RedFlag(
            "Contacts", "critical",
            f"High standings toward {len(high_standing_hostiles)} hostile entity(s)",
            f"Contacts with hostile standing ≥5.0: {names}. "
            "Maintaining high standings toward known enemies is a strong spy indicator.",
        ))

    mid_standing_hostiles = [
        c for c in contacts
        if c.get("contact_id") in hostile_ids and 0 < c.get("standing", 0) < 5.0
    ]
    if mid_standing_hostiles:
        flags.append(RedFlag(
            "Contacts", "warning",
            f"Positive standings toward {len(mid_standing_hostiles)} hostile entity(s)",
            "Character has positive (but below 5.0) standings toward entities on the watchlist.",
        ))

    return flags


# ---------------------------------------------------------------------------
# Rule: Wallet — suspicious large outflow
# ---------------------------------------------------------------------------

def check_wallet(wallet_balance: float, wallet_journal: list) -> list[RedFlag]:
    flags = []
    if _is_error(wallet_balance):
        return []
    if _is_error(wallet_journal) or not isinstance(wallet_journal, list):
        return flags

    thirty_days_ago = _utcnow() - timedelta(days=30)

    total_out = sum(
        abs(e.get("amount", 0))
        for e in wallet_journal
        if e.get("amount", 0) < 0
        and _parse_dt(e.get("date", "")) >= thirty_days_ago
        and e.get("ref_type") not in ("market_escrow", "market_transaction")
    )

    total_in = sum(
        e.get("amount", 0)
        for e in wallet_journal
        if e.get("amount", 0) > 0
        and _parse_dt(e.get("date", "")) >= thirty_days_ago
    )

    if total_out > 5_000_000_000 and total_in > 0 and (total_out / (total_in + 1)) > 0.8:
        flags.append(RedFlag(
            "Wallet", "warning",
            f"Large ISK outflow: {total_out/1e9:.1f}B ISK in 30 days",
            "More than 80% of incoming ISK was transferred out in the last 30 days. "
            "Could indicate ISK funnelling to another character.",
        ))
    elif total_out > 10_000_000_000:
        flags.append(RedFlag(
            "Wallet", "info",
            f"High ISK transfers out: {total_out/1e9:.1f}B ISK in 30 days",
            "Large outgoing transfers — may be normal trading, but worth asking about.",
        ))

    return flags


# ---------------------------------------------------------------------------
# Rule: Jump clones in hostile space
# ---------------------------------------------------------------------------

def check_clones(clones: dict, hostile_system_ids: set[int]) -> list[RedFlag]:
    flags = []
    if _is_error(clones) or not isinstance(clones, dict):
        return []

    jump_clones = clones.get("jump_clones", [])
    for clone in jump_clones:
        loc_id = clone.get("location_id")
        if loc_id in hostile_system_ids:
            flags.append(RedFlag(
                "Clones", "critical",
                "Jump clone in hostile space",
                f"Jump clone located at ID {loc_id}, which is in known hostile territory. "
                "Pre-positioned clones suggest planned infiltration.",
            ))
        elif clone.get("location_type") == "solar_system":
            # Null-sec clone outside known space — worth flagging generally
            flags.append(RedFlag(
                "Clones", "info",
                "Jump clone in null-sec",
                f"Clone at location {loc_id} in null-sec. "
                "Verify the owner of this space.",
            ))

    return flags


# ---------------------------------------------------------------------------
# Rule: Assets in hostile structures
# ---------------------------------------------------------------------------

def check_assets(assets: list, hostile_structure_ids: set[int]) -> list[RedFlag]:
    flags = []
    if _is_error(assets) or not isinstance(assets, list):
        return []

    staged = [a for a in assets if a.get("location_id") in hostile_structure_ids]
    if staged:
        total_items = len(staged)
        flags.append(RedFlag(
            "Assets", "critical",
            f"{total_items} item(s) staged in hostile structures",
            f"Character has {total_items} assets located inside known hostile player structures. "
            "Pre-staged assets are a strong indicator of planned infiltration.",
        ))

    return flags


# ---------------------------------------------------------------------------
# Rule: Killmails — friendly fire or kills vs corp members
# ---------------------------------------------------------------------------

def check_killmails(
    killmails: list,
    corp_member_ids: set[int],
    zkb_data: Optional[list] = None,
) -> list[RedFlag]:
    flags = []
    if _is_error(killmails) or not isinstance(killmails, list):
        return []

    if not zkb_data:
        return flags  # Need enriched killmail data for this check

    friendly_fire_count = 0
    for km in zkb_data:
        victim = km.get("victim", {})
        attackers = km.get("attackers", [])
        victim_id = victim.get("character_id")
        attacker_ids = {a.get("character_id") for a in attackers}

        # Check if applicant killed a corp member
        if victim_id in corp_member_ids and attacker_ids:
            friendly_fire_count += 1

    if friendly_fire_count > 0:
        flags.append(RedFlag(
            "Killmails", "critical",
            f"Friendly fire: killed {friendly_fire_count} corp member(s)",
            f"Killmail records show this character has killed {friendly_fire_count} "
            "member(s) of your corporation or alliance. This is an AWOXer pattern.",
        ))

    return flags


# ---------------------------------------------------------------------------
# Rule: In-game mail — communication with hostile entities
# ---------------------------------------------------------------------------

def check_mail(mail_headers: list, hostile_ids: set[int], watchlist_names: dict[int, str]) -> list[RedFlag]:
    flags = []
    if _is_error(mail_headers) or not isinstance(mail_headers, list) or not mail_headers:
        return []

    hostile_contacts: dict[int, int] = {}  # entity_id -> mail count

    for mail in mail_headers:
        # Check sender
        sender_id = mail.get("from")
        if sender_id and sender_id in hostile_ids:
            hostile_contacts[sender_id] = hostile_contacts.get(sender_id, 0) + 1

        # Check recipients
        for rec in mail.get("recipients", []):
            rec_id = rec.get("recipient_id")
            if rec_id and rec_id in hostile_ids:
                hostile_contacts[rec_id] = hostile_contacts.get(rec_id, 0) + 1

    if hostile_contacts:
        total_mails = sum(hostile_contacts.values())
        names = ", ".join(
            watchlist_names.get(eid) or f"Entity #{eid}"
            for eid in list(hostile_contacts)[:5]
        )
        severity = "critical" if total_mails >= 5 else "warning"
        flags.append(RedFlag(
            "Mail", severity,
            f"Mail contact with {len(hostile_contacts)} hostile entity(s)",
            f"Found {total_mails} mail(s) to/from entities on the hostile watchlist: {names}. "
            "Regular communication with known enemies is a strong spy indicator.",
        ))

    return flags


# ---------------------------------------------------------------------------
# Rule: Standing — character/corp/alliance flagged negative in standings cache
# ---------------------------------------------------------------------------

def check_standings(
    character_id: int,
    corp_id: int,
    alliance_id: int,
    corp_history: list,
    standings: list[dict],
    corp_alliance_map: Optional[dict] = None,
) -> list[RedFlag]:
    """
    Check character, current corp, current alliance, all historical corps,
    and all alliances those corps have been in against the standings cache.

    standings:         list of {entity_id, entity_type, entity_name, standing, source}
    corp_alliance_map: {corp_id: [{alliance_id, alliance_name, start_date}]}
    """
    flags = []
    if not standings:
        return []

    lookup: dict[int, dict] = {s["entity_id"]: s for s in standings}

    def _flag_entity(eid: int, label: str, context: str = "") -> list[RedFlag]:
        if not eid or eid not in lookup:
            return []
        s = lookup[eid]
        standing = s["standing"]
        name = s.get("entity_name") or f"{label} #{eid}"
        source = s.get("source", "alliance").title()
        detail_ctx = f" ({context})" if context else ""
        if standing <= -10.0:
            return [RedFlag(
                "Standings", "critical",
                f"{label} at -10 standing: {name}",
                f"{source} contacts list has {name} at {standing:+.1f} standing{detail_ctx}. "
                "A -10 standing is the strongest possible hostile designation.",
            )]
        elif standing <= -5.0:
            return [RedFlag(
                "Standings", "critical",
                f"{label} hostile standing: {name} ({standing:+.1f})",
                f"{source} contacts list has {name} at {standing:+.1f} standing{detail_ctx}. "
                "Standing at -5 or below indicates a known hostile entity.",
            )]
        elif standing < 0:
            return [RedFlag(
                "Standings", "warning",
                f"{label} negative standing: {name} ({standing:+.1f})",
                f"{source} contacts list has {name} at {standing:+.1f} standing{detail_ctx}. "
                "Verify whether this is significant.",
            )]
        return []

    # Current character, corp, alliance
    flags += _flag_entity(character_id, "Character")
    flags += _flag_entity(corp_id, "Corp")
    flags += _flag_entity(alliance_id, "Alliance")

    # All historical corps (deduplicated; skip current corp already checked)
    seen_corp_ids = {corp_id}
    for entry in (corp_history or []):
        hcorp_id = entry.get("corporation_id")
        if not hcorp_id or hcorp_id in seen_corp_ids:
            continue
        seen_corp_ids.add(hcorp_id)
        start = entry.get("start_date", "")[:10]
        corp_name = entry.get("corp_name") or f"Corp #{hcorp_id}"
        flags += _flag_entity(hcorp_id, "Historical corp", f"{corp_name}, joined {start}")

    # Alliances that historical corps have been in — skip current alliance (already checked)
    if corp_alliance_map:
        seen_alliance_ids: set[int] = {alliance_id} if alliance_id else set()
        for entry in (corp_history or []):
            hcorp_id = entry.get("corporation_id")
            if not hcorp_id:
                continue
            corp_name = entry.get("corp_name") or f"Corp #{hcorp_id}"
            for ally_entry in corp_alliance_map.get(hcorp_id, []):
                ally_id = ally_entry.get("alliance_id")
                if not ally_id or ally_id in seen_alliance_ids:
                    continue
                seen_alliance_ids.add(ally_id)
                ally_name = ally_entry.get("alliance_name") or f"Alliance #{ally_id}"
                ally_start = ally_entry.get("start_date", "")[:10]
                flags += _flag_entity(
                    ally_id,
                    "Alliance (corp history)",
                    f"{corp_name} was in {ally_name} from {ally_start}",
                )

    return flags


# ---------------------------------------------------------------------------
# Rule: Big losses on zKillboard (deliberate self-loss / ISK transfer)
# ---------------------------------------------------------------------------

def check_big_losses(zkb_data: list, character_id: int) -> list[RedFlag]:
    """Flag suspiciously expensive losses — used to pass ISK via kill."""
    flags = []
    if not zkb_data or not isinstance(zkb_data, list):
        return []

    BIG_LOSS_THRESHOLD = 5_000_000_000   # 5B ISK
    SUSPICIOUS_THRESHOLD = 20_000_000_000  # 20B ISK

    big_losses = []
    for km in zkb_data:
        victim = km.get("victim", {})
        if victim.get("character_id") != character_id:
            continue
        zkb = km.get("zkb", {})
        isk_value = zkb.get("totalValue", 0)
        if isk_value >= BIG_LOSS_THRESHOLD:
            big_losses.append(isk_value)

    if not big_losses:
        return []

    total_lost = sum(big_losses)
    biggest = max(big_losses)
    count = len(big_losses)

    if biggest >= SUSPICIOUS_THRESHOLD or count >= 3:
        flags.append(RedFlag(
            "Killmails", "warning",
            f"{count} large loss(es) totalling {total_lost/1e9:.1f}B ISK",
            f"Character has {count} loss(es) valued at 5B+ ISK each (largest: {biggest/1e9:.1f}B ISK). "
            "Expensive deliberate losses can be used to transfer ISK to enemies via kill bounty. "
            "Verify the circumstances of these losses.",
        ))
    elif total_lost >= BIG_LOSS_THRESHOLD:
        flags.append(RedFlag(
            "Killmails", "info",
            f"Large loss: {biggest/1e9:.1f}B ISK",
            f"Character has lost ships/assets worth {total_lost/1e9:.1f}B ISK total. "
            "May be normal PvP — check the killmail details.",
        ))

    return flags


# ---------------------------------------------------------------------------
# Rule: Character age vs skill points (SP farm / RMT detection)
# ---------------------------------------------------------------------------

def check_character_age(character_public: dict, skills: dict) -> list[RedFlag]:
    flags = []
    if _is_error(character_public) or _is_error(skills):
        return []

    birthday_str = character_public.get("birthday", "")
    if not birthday_str:
        return []

    birthday = _parse_dt(birthday_str)
    age_days = (_utcnow() - birthday).days
    total_sp = skills.get("total_sp", 0) if isinstance(skills, dict) else 0

    if age_days < 90 and total_sp > 5_000_000:
        flags.append(RedFlag(
            "Character Age", "warning",
            f"High SP ({total_sp/1e6:.1f}M) for young character ({age_days} days old)",
            "This character is less than 90 days old but has more than 5M SP. "
            "This may indicate an injected character or SP farm sold via RMT.",
        ))
    elif age_days < 30:
        flags.append(RedFlag(
            "Character Age", "info",
            f"Very new character ({age_days} days old)",
            "Character is less than 30 days old. Consider requiring a main character check.",
        ))

    return flags


# ---------------------------------------------------------------------------
# Aggregate: run all checks
# ---------------------------------------------------------------------------

def run_all_checks(
    esi_data: dict,
    hostile_ids: set[int],
    watchlist_names: dict[int, str],
    hostile_system_ids: set[int],
    hostile_structure_ids: set[int],
    corp_member_ids: set[int],
    zkb_data: Optional[list] = None,
    standings: Optional[list[dict]] = None,
    corp_alliance_map: Optional[dict] = None,
) -> list[RedFlag]:
    """Run every red flag check and return the combined list."""
    flags: list[RedFlag] = []

    flags += check_corp_history(
        esi_data.get("corp_history", []),
        hostile_ids,
        watchlist_names,
        standings=standings,
        corp_alliance_map=corp_alliance_map,
    )
    flags += check_contacts(esi_data.get("contacts", []), hostile_ids)
    flags += check_wallet(
        esi_data.get("wallet_balance", 0),
        esi_data.get("wallet_journal", []),
    )
    flags += check_clones(esi_data.get("clones", {}), hostile_system_ids)
    flags += check_assets(esi_data.get("assets", []), hostile_structure_ids)
    flags += check_killmails(
        esi_data.get("killmails", []),
        corp_member_ids,
        zkb_data,
    )
    flags += check_mail(
        esi_data.get("mail_headers", []),
        hostile_ids,
        watchlist_names,
    )
    character_id = esi_data.get("character_public", {}).get("id", 0)
    flags += check_big_losses(zkb_data or [], character_id)
    flags += check_character_age(
        esi_data.get("character_public", {}),
        esi_data.get("skills", {}),
    )

    # Standings check (character, corp, alliance + full corp history + alliance history)
    if standings:
        char_pub = esi_data.get("character_public", {})
        char_id = char_pub.get("id") or char_pub.get("character_id", 0)
        corp_id = char_pub.get("corporation_id", 0)
        alliance_id = char_pub.get("alliance_id", 0)
        flags += check_standings(
            char_id, corp_id, alliance_id,
            esi_data.get("corp_history", []),
            standings,
            corp_alliance_map=corp_alliance_map,
        )

    return flags
