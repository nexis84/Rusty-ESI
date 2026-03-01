"""
Trust score calculator.

Produces a 0–100 score based on ESI data and red flags found.
Also assigns a colour band and recommendation.
"""
from dataclasses import dataclass, field
from typing import Optional

from analysis.red_flags import RedFlag, run_all_checks


# ---------------------------------------------------------------------------
# Score result
# ---------------------------------------------------------------------------

@dataclass
class TrustReport:
    character_id: int
    character_name: str
    score: int                      # 0–100
    band: str                       # "green" | "yellow" | "orange" | "red"
    recommendation: str             # Human-readable summary
    red_flags: list[RedFlag] = field(default_factory=list)
    score_breakdown: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scoring weights (max points per category, must sum ≤ 100)
# ---------------------------------------------------------------------------

WEIGHTS = {
    "corp_stability":   25,   # Few corps, no rapid hopping
    "no_hostiles":      20,   # No time in blacklisted corps
    "clean_kills":      15,   # No friendly fire
    "wallet_integrity": 15,   # No suspicious outflows
    "contacts_clean":   10,   # No high standing toward enemies
    "assets_safe":      10,   # No assets in hostile space
    "char_age":          5,   # Account age / SP ratio looks organic
}

assert sum(WEIGHTS.values()) == 100, "Score weights must sum to 100"


# ---------------------------------------------------------------------------
# Individual category scorers
# ---------------------------------------------------------------------------

def _score_corp_stability(flags: list[RedFlag]) -> int:
    """25 points — deduct for hopping / hostile affiliations."""
    deduction = 0
    for f in flags:
        if f.category != "Corp History":
            continue
        if f.severity == "critical":
            deduction += 15
        elif f.severity == "warning":
            deduction += 8
        elif f.severity == "info":
            deduction += 3
    return max(0, WEIGHTS["corp_stability"] - deduction)


def _score_no_hostiles(flags: list[RedFlag]) -> int:
    """20 points — time in known enemy corps/alliances."""
    hostile_flags = [f for f in flags if "hostile corp" in f.message.lower()]
    deduction = len(hostile_flags) * 20  # Each hostile affiliation is severe
    return max(0, WEIGHTS["no_hostiles"] - deduction)


def _score_clean_kills(flags: list[RedFlag]) -> int:
    """15 points — friendly fire."""
    kill_flags = [f for f in flags if f.category == "Killmails"]
    if any(f.severity == "critical" for f in kill_flags):
        return 0
    return WEIGHTS["clean_kills"]


def _score_wallet(flags: list[RedFlag]) -> int:
    """15 points — wallet integrity."""
    wallet_flags = [f for f in flags if f.category == "Wallet"]
    deduction = 0
    for f in wallet_flags:
        if f.severity == "warning":
            deduction += 10
        elif f.severity == "info":
            deduction += 4
    return max(0, WEIGHTS["wallet_integrity"] - deduction)


def _score_contacts(flags: list[RedFlag]) -> int:
    """10 points — no high standings toward hostiles."""
    contact_flags = [f for f in flags if f.category == "Contacts"]
    if any(f.severity == "critical" for f in contact_flags):
        return 0
    if any(f.severity == "warning" for f in contact_flags):
        return WEIGHTS["contacts_clean"] // 2
    return WEIGHTS["contacts_clean"]


def _score_assets(flags: list[RedFlag]) -> int:
    """10 points — no assets in hostile space."""
    asset_flags = [f for f in flags if f.category in ("Assets", "Clones")]
    if any(f.severity == "critical" for f in asset_flags):
        return 0
    if any(f.severity == "warning" for f in asset_flags):
        return WEIGHTS["assets_safe"] // 2
    return WEIGHTS["assets_safe"]


def _score_char_age(flags: list[RedFlag]) -> int:
    """5 points — character age / SP ratio."""
    age_flags = [f for f in flags if f.category == "Character Age"]
    if any(f.severity == "warning" for f in age_flags):
        return WEIGHTS["char_age"] // 2
    return WEIGHTS["char_age"]


# ---------------------------------------------------------------------------
# Band assignment
# ---------------------------------------------------------------------------

def _band(score: int) -> tuple[str, str]:
    if score >= 85:
        return "green", "Clear to recruit. No significant concerns found."
    if score >= 65:
        return "yellow", "Minor concerns present. Interview recommended before recruiting."
    if score >= 40:
        return "orange", "Significant red flags found. Deep background interview required."
    return "red", "Do not recruit. Multiple critical flags — possible spy or hostile agent."


# ---------------------------------------------------------------------------
# Main scorer
# ---------------------------------------------------------------------------

def calculate_trust_score(
    esi_data: dict,
    hostile_ids: set[int],
    watchlist_names: dict[int, str],
    hostile_system_ids: set[int],
    hostile_structure_ids: set[int],
    corp_member_ids: set[int],
    zkb_data: Optional[list] = None,
) -> TrustReport:
    """
    Run all checks and produce a TrustReport.
    """
    character_public = esi_data.get("character_public", {})
    character_id = character_public.get("id", 0)
    character_name = character_public.get("name", "Unknown")

    flags = run_all_checks(
        esi_data=esi_data,
        hostile_ids=hostile_ids,
        watchlist_names=watchlist_names,
        hostile_system_ids=hostile_system_ids,
        hostile_structure_ids=hostile_structure_ids,
        corp_member_ids=corp_member_ids,
        zkb_data=zkb_data,
    )

    breakdown = {
        "corp_stability":   _score_corp_stability(flags),
        "no_hostiles":      _score_no_hostiles(flags),
        "clean_kills":      _score_clean_kills(flags),
        "wallet_integrity": _score_wallet(flags),
        "contacts_clean":   _score_contacts(flags),
        "assets_safe":      _score_assets(flags),
        "char_age":         _score_char_age(flags),
    }
    total = sum(breakdown.values())
    band, recommendation = _band(total)

    return TrustReport(
        character_id=character_id,
        character_name=character_name,
        score=total,
        band=band,
        recommendation=recommendation,
        red_flags=flags,
        score_breakdown=breakdown,
    )
