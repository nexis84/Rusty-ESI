---
title: Rusty ESI Checker
emoji: 🔍
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# ESI Checker — EVE Online Recruitment Platform

A self-hosted corporation recruitment tool for EVE Online. Applicants
authenticate via EVE SSO, grant read-only ESI access, and the system
automatically analyses their character data, scores them for risk, and
presents a full report to your recruiters.

---

## Quick Start

### 1. Register your EVE application

Go to [https://developers.eveonline.com/](https://developers.eveonline.com/) and create a new application:

- **Connection Type**: Authentication & API Access
- **Permissions**: Add all the scopes listed below
- **Callback URL**: `http://localhost:8000/auth/callback`

Note your **Client ID** and **Client Secret**.

**Required ESI Scopes:**
```
esi-skills.read_skills.v1
esi-wallet.read_character_wallet.v1
esi-contacts.read_contacts.v1
esi-assets.read_assets.v1
esi-clones.read_clones.v1
esi-killmails.read_killmails.v1
esi-location.read_location.v1
esi-mail.read_mail_headers.v1
esi-characters.read_corporation_history.v1
```

---

### 2. Install Python dependencies

Requires **Python 3.11+**.

```powershell
cd "d:\coding project\ESI checker"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

### 3. Configure the application

```powershell
Copy-Item .env.example .env
```

Edit `.env` and fill in:

```env
EVE_CLIENT_ID=your_client_id
EVE_CLIENT_SECRET=your_client_secret
EVE_CALLBACK_URL=http://localhost:8000/auth/callback

# Generate a Fernet key:
# python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
FERNET_KEY=your_generated_fernet_key

# Generate a session secret:
# python -c "import secrets; print(secrets.token_hex(32))"
SESSION_SECRET=your_session_secret

YOUR_CORP_ID=your_corporation_eve_id   # Find at evewho.com
```

---

### 4. Run the server

```powershell
python app.py
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## Usage Workflow

### For Recruiters

1. **Log in** with your corp officer character via EVE SSO
2. Go to **Invite Links** → Generate a new link for your applicant
3. Copy the invite URL and send it to the applicant (Discord, in-game mail, etc.)
4. Wait for the applicant to authenticate — they'll appear in **Dashboard**
5. Click **Review** to see the full report, trust score, and red flags
6. Add notes, then click **Approve / Hold / Deny**

### For Applicants

1. Click the invite link you received
2. Read the data disclosure, then click **Authenticate with EVE Online**
3. Log in and grant the requested permissions
4. You're done — the recruiter will review your application

---

## Trust Score System

Applicants receive a score from **0 to 100**:

| Score | Band | Meaning |
|---|---|---|
| 85–100 | 🟢 Green | Clear to recruit |
| 65–84 | 🟡 Yellow | Minor concerns — interview recommended |
| 40–64 | 🟠 Orange | Significant flags — deep interview required |
| 0–39 | 🔴 Red | Do not recruit — possible spy/hostile |

### What we check

| Check | What it looks for |
|---|---|
| Corp History | Rapid corp hopping, time in hostile corps |
| Contacts | High standings (≥5.0) toward watchlisted entities |
| Wallet | Large unexplained ISK outflows |
| Jump Clones | Clones positioned in hostile/suspicious space |
| Assets | Items staged inside hostile player structures |
| Killmails | Friendly fire against corp/alliance members |
| Character Age | Young character with suspiciously high SP |

---

## Managing the Hostile Watchlist

Go to **Watchlist** in the nav bar. Add the EVE IDs of hostile corporations
and alliances your corp is at war with, known spy corps, or entities you
want to flag automatically.

Find corp/alliance IDs at:
- [https://evewho.com/](https://evewho.com/)
- [https://zkillboard.com/](https://zkillboard.com/)

---

## Project Structure

```
ESI checker/
├── app.py              Main FastAPI application & all routes
├── config.py           Settings loaded from .env
├── requirements.txt    Python dependencies
├── auth/
│   └── eve_sso.py      EVE SSO OAuth2 flow
├── esi/
│   ├── client.py       Async ESI HTTP client
│   └── endpoints.py    ESI data fetchers
├── analysis/
│   ├── scorer.py       Trust score calculator
│   └── red_flags.py    Red flag detection rules
├── database/
│   ├── db.py           SQLAlchemy engine & session
│   └── models.py       ORM models
├── utils/
│   └── zkillboard.py   zKillboard API integration
└── web/
    └── templates/      Jinja2 HTML templates
```

---

## Security Notes

- All EVE SSO tokens are **encrypted at rest** (Fernet symmetric encryption)
- CSRF protection on all form submissions
- Invite links are **single-use** and expire after 72 hours
- Recruiter sessions use **signed HTTP-only cookies**
- Uses EVE SSO only — no passwords ever stored
- For production, set `https_only=True` in `app.py` and serve behind HTTPS

---

## Extending the Platform

### Adding custom red flag rules

Edit `analysis/red_flags.py` and add a new function following the pattern
of the existing check functions. Then call it from `run_all_checks()`.

### Adjusting score weights

Edit the `WEIGHTS` dict in `analysis/scorer.py`. Values must sum to 100.

### Adding hostile system/structure IDs

In `app.py`, the `_fetch_and_score()` function passes empty sets for
`hostile_system_ids` and `hostile_structure_ids`. Populate these from your
own configuration (e.g. a JSON file listing hostile null-sec systems).

### Running in production

```powershell
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2
```

Or use a reverse proxy (nginx/Caddy) with HTTPS.

---

## EVE Online Third-Party Notice

This application uses the EVE Online ESI API. EVE Online and the EVE logo are
the registered trademarks of CCP hf. All rights are reserved worldwide. This
tool is not affiliated with or endorsed by CCP hf.
