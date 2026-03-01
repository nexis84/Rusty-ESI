# EVE Online Corp Recruitment ESI Checker — Full Project Plan

## Overview

A corporation-level ESI (EVE Swagger Interface) platform to screen potential
recruits, detect spies/malicious players, and generate trust reports for corp
officers. Applicants authenticate via EVE SSO, the system fetches their ESI
data, runs automated analysis, and presents a scored report to recruiters.

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                        Web Browser                         │
│        (Recruiter Dashboard / Applicant Auth Page)         │
└──────────────────────┬─────────────────────────────────────┘
                       │ HTTP
┌──────────────────────▼─────────────────────────────────────┐
│               FastAPI Web Application (app.py)             │
│   ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌─────────┐  │
│   │  Auth    │  │  ESI     │  │ Analysis  │  │  Web    │  │
│   │  Module  │  │  Client  │  │  Engine   │  │ Routes  │  │
│   └──────────┘  └──────────┘  └───────────┘  └─────────┘  │
└──────────────────────┬─────────────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ SQLite   │  │ EVE ESI  │  │zKillboard│
   │    DB    │  │   API    │  │   API    │
   └──────────┘  └──────────┘  └──────────┘
```

---

## Directory Structure

```
ESI checker/
├── PLAN.md                     ← This file
├── README.md                   ← Setup & usage guide
├── requirements.txt            ← Python dependencies
├── .env.example                ← Environment variable template
├── config.py                   ← App configuration
├── app.py                      ← Main FastAPI app & routes
│
├── auth/
│   ├── __init__.py
│   └── eve_sso.py              ← EVE SSO OAuth2 flow
│
├── esi/
│   ├── __init__.py
│   ├── client.py               ← Async ESI HTTP client
│   └── endpoints.py            ← ESI endpoint definitions & fetchers
│
├── analysis/
│   ├── __init__.py
│   ├── scorer.py               ← Trust score calculation
│   └── red_flags.py            ← Red flag detection rules
│
├── database/
│   ├── __init__.py
│   ├── db.py                   ← DB engine & session
│   └── models.py               ← SQLAlchemy ORM models
│
├── utils/
│   ├── __init__.py
│   └── zkillboard.py           ← zKillboard API integration
│
└── web/
    ├── templates/
    │   ├── base.html           ← Base layout
    │   ├── dashboard.html      ← Recruiter dashboard
    │   ├── application.html    ← Applicant auth landing
    │   ├── review.html         ← Full applicant report
    │   └── login.html          ← Corp officer login
    └── static/
        ├── css/
        │   └── style.css
        └── js/
            └── dashboard.js
```

---

## Feature Breakdown

### 1. Authentication (Two Roles)

**Corp Officers (Recruiters)**
- Log in via EVE SSO using their character
- System verifies they belong to the configured corporation
- Session-based auth with secure cookie

**Applicants**
- Receive a unique invite link from a recruiter
- Authenticate via EVE SSO granting the required ESI scopes
- No account needed — link is single-use

**EVE SSO Scopes Requested from Applicants**
| Scope | Purpose |
|---|---|
| `esi-characters.read_corporation_history.v1` | Public, always available |
| `esi-skills.read_skills.v1` | Skill totals & suspicious training |
| `esi-wallet.read_character_wallet.v1` | Balance & recent transactions |
| `esi-contacts.read_contacts.v1` | Standings toward known enemies |
| `esi-assets.read_assets.v1` | Assets in enemy space/structures |
| `esi-clones.read_clones.v1` | Jump clones in suspicious locations |
| `esi-killmails.read_killmails.v1` | Friendly fire / kill history |
| `esi-location.read_location.v1` | Current location at time of check |
| `esi-mail.read_mail.v1` | (Optional) Mail headers for red flags |
| `esi-corporations.read_corporation_membership.v1` | Alt corp detection |

---

### 2. ESI Data Collection

All data is fetched asynchronously after the applicant authenticates.

| Data Point | Source | What We Check |
|---|---|---|
| Corporation history | ESI (public) | Frequency of moves, enemy corps |
| Skills | ESI (auth) | Suspicious skill gaps, SP farms |
| Wallet balance | ESI (auth) | Large outgoing transfers |
| Wallet transactions | ESI (auth) | ISK funneling patterns |
| Contacts | ESI (auth) | High standings toward enemies |
| Assets | ESI (auth) | Items staged in hostile space |
| Jump clones | ESI (auth) | Clones in enemy null-sec |
| Recent killmails | ESI (auth) | Friendly fire, killing corp members |
| Current location | ESI (auth) | Inside hostile territory |
| Character public info | ESI (public) | Age, corp, alliance |

---

### 3. Analysis Engine & Scoring

Each applicant receives a **Trust Score** from 0–100.

#### Scoring Categories

| Category | Max Points | Description |
|---|---|---|
| Corp History Stability | 25 | Penalises frequent corp hopping |
| No Known Enemy Affiliation | 20 | Time in known hostile corps/alliances |
| Clean Kill History | 15 | No friendly fire, no kills vs corp |
| Wallet Integrity | 15 | No suspicious large transfers out |
| Contact Standings | 10 | No high standings toward hostiles |
| Asset Location | 10 | No assets staged in enemy space |
| Character Age & Activity | 5 | Account age vs SP (farm detection) |

**Score Bands:**
- 85–100: **Green** — Recruit freely
- 65–84: **Yellow** — Minor concerns, interview recommended
- 40–64: **Orange** — Significant red flags, deep interview needed
- 0–39: **Red** — Deny or investigate further

#### Red Flag Rules (examples)

- More than 3 different corps in the last 6 months
- Any time spent in known hostile corps from the watchlist
- Positive standings (+5 or higher) toward known enemies
- Jump clones in hostile null-sec systems
- Recent large wallet drain (>50% of balance out in last 30 days)
- Killmails where the victim is a member of your corp or alliance
- Character created less than 90 days ago with high SP (potential RMT/farm)
- Multiple character tokens pointing to the same IP (alt detection)

---

### 4. Recruiter Dashboard

**Application List View**
- Pending / Reviewed tabs
- Quick score badge (Green/Yellow/Orange/Red)
- Character name, portrait, age, current corp/alliance
- Date applied

**Full Review Page**
- Character portrait + public details
- Trust score gauge
- Expandable sections for each data category
- Red flags listed with explanations
- Corp history timeline visualisation
- Recruiter notes field
- Approve / Deny / Hold buttons
- All raw ESI data available in collapsible panels

---

### 5. Admin & Config

- Configurable corp/alliance watchlist (hostile entities)
- Configurable scoring weights
- Invite link generator (time-limited, re-generatable)
- Export reports as PDF or JSON
- Audit log of all recruiter actions

---

## Data Flow

```
1. Recruiter generates invite link → stored in DB with expiry
2. Applicant clicks link → directed to EVE SSO
3. EVE SSO returns auth code → swapped for access + refresh tokens
4. Tokens stored encrypted in DB
5. Background task fetches all ESI scopes asynchronously
6. Analysis engine scores the character
7. Red flags calculated and stored
8. Recruiter notified → reviews dashboard
9. Recruiter adds notes, approves/denies → logged to DB
```

---

## Technology Stack

| Component | Technology | Reason |
|---|---|---|
| Web framework | FastAPI (Python) | Async, fast, auto docs |
| Database | SQLite + SQLAlchemy | Simple, no separate server |
| Templating | Jinja2 | Built into FastAPI |
| HTTP client | httpx (async) | Non-blocking ESI calls |
| Auth | EVE SSO OAuth2 | Official EVE Online |
| Token security | Fernet symmetric encryption | Safe token storage at rest |
| Session | Starlette sessions | Secure signed cookies |
| Server | Uvicorn | ASGI, async-native |
| Config | python-dotenv | Environment-based secrets |

---

## Security Considerations

- All ESI tokens encrypted at rest (Fernet)
- CSRF protection via OAuth `state` parameter
- Invite links are UUIDs with expiry timestamps
- Recruiter sessions use signed HTTP-only cookies
- Rate limiting on ESI calls (ESI has 150 req/s limit)
- ESI error caching (respect `X-ESI-Error-Limit-Remain`)
- No passwords stored — EVE SSO only
- Input validation on all form fields
- SQL injection prevention via ORM parameterisation
- Secrets loaded from `.env`, never hardcoded

---

## Development Phases

### Phase 1 — Foundation (Days 1–3)
- [x] Project structure
- [x] EVE SSO OAuth2 auth flow
- [x] Database models
- [x] Basic ESI client
- [x] Invite link generation

### Phase 2 — Data Collection (Days 4–6)
- [ ] All ESI endpoint fetchers
- [ ] zKillboard integration
- [ ] Background job queue for fetching
- [ ] Token refresh logic

### Phase 3 — Analysis Engine (Days 7–9)
- [ ] Scoring algorithm
- [ ] Red flag ruleset
- [ ] Hostile entity watchlist loader
- [ ] Corp history timeline

### Phase 4 — Dashboard (Days 10–14)
- [ ] Recruiter dashboard UI
- [ ] Full review page with all data
- [ ] Notes & decision workflow
- [ ] Invite link management UI

### Phase 5 — Polish & Ops (Days 15–18)
- [ ] Export to PDF/JSON
- [ ] Audit log viewer
- [ ] Rate limit handling & retry logic
- [ ] Docker deployment option
- [ ] Persistent hostile list (Dotlan/hand-curated)

---

## EVE ESI Reference

- ESI Base URL: `https://esi.evetech.net/latest/`
- EVE SSO: `https://login.eveonline.com/v2/oauth/`
- ESI Swagger UI: `https://esi.evetech.net/ui/`
- Register your app: `https://developers.eveonline.com/`

---

## Getting Started Checklist

1. Register application at https://developers.eveonline.com/
2. Note your `Client ID` and `Client Secret`
3. Set Callback URL to `http://localhost:8000/auth/callback`
4. Copy `.env.example` to `.env` and fill in values
5. Run `pip install -r requirements.txt`
6. Run `python app.py`
7. Open `http://localhost:8000`
8. Log in as a corp officer via EVE SSO
