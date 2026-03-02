"""
Central configuration — loaded from .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # EVE SSO
    eve_client_id: str = Field(default="")
    eve_client_secret: str = Field(default="")
    eve_callback_url: str = Field(default="http://localhost:8000/auth/callback")

    # Security
    fernet_key: str = Field(default="")
    session_secret: str = Field(default="changeme")

    # App
    app_port: int = Field(default=8000)
    debug: bool = Field(default=True)

    # Your corporation (primary)
    your_corp_id: int = Field(default=0)
    your_alliance_id: int = Field(default=0)

    # Additional corps allowed recruiter access (comma-separated IDs, e.g. "123,456")
    allowed_corp_ids: str = Field(default="")

    @property
    def allowed_corp_id_set(self) -> set[int]:
        """Returns the full set of corp IDs permitted recruiter login."""
        ids: set[int] = set()
        if self.your_corp_id != 0:
            ids.add(self.your_corp_id)
        for part in self.allowed_corp_ids.split(","):
            part = part.strip()
            if part.isdigit():
                ids.add(int(part))
        return ids

    # Database
    database_url: str = Field(default="sqlite:///./esi_checker.db")

    # EVE SSO endpoints
    eve_sso_authorize_url: str = "https://login.eveonline.com/v2/oauth/authorize"
    eve_sso_token_url: str = "https://login.eveonline.com/v2/oauth/token"
    eve_sso_verify_url: str = "https://login.eveonline.com/oauth/verify"
    eve_jwks_url: str = "https://login.eveonline.com/oauth/jwks"

    # ESI base
    esi_base_url: str = "https://esi.evetech.net/latest"

    # Applicant ESI scopes (space-separated)
    applicant_scopes: str = (
        "esi-skills.read_skills.v1 "
        "esi-wallet.read_character_wallet.v1 "
        "esi-characters.read_contacts.v1 "
        "esi-assets.read_assets.v1 "
        "esi-clones.read_clones.v1 "
        "esi-killmails.read_killmails.v1 "
        "esi-location.read_location.v1 "
        "esi-mail.read_mail.v1"
    )

    # Recruiter scopes (minimal — just to verify identity)
    # Corp history is a public ESI endpoint and needs no scope
    recruiter_scopes: str = "publicData"


settings = Settings()
