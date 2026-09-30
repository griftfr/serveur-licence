from fastapi import FastAPI, HTTPException, Form, Request, Cookie, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
from contextlib import contextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import create_engine, Column, String, DateTime, text
from sqlalchemy.orm import sessionmaker, declarative_base
import secrets
import os

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change-me")
SESSION_COOKIE_NAME = "admin_session"

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./keys_db.sqlite3")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class LicenseKey(Base):
    __tablename__ = "license_keys"

    key = Column(String, primary_key=True)
    product_id = Column(String, nullable=False)
    customer_email = Column(String, nullable=True)
    duration = Column(String, nullable=False)       # 1_week / 1_month / lifetime
    status = Column(String, nullable=False, default="unused")  # unused/active/expired/revoked
    hwid = Column(String, nullable=True)
    expires_at = Column(String, nullable=True)       # ISO string ou "lifetime"
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# App + rate limiting
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def is_authenticated(admin_session: str = Cookie(None)) -> bool:
    return admin_session == ADMIN_KEY


def mark_expired_if_needed(k: LicenseKey) -> None:
    if k.status == "active" and k.expires_at and k.expires_at != "lifetime":
        if datetime.utcnow() > datetime.fromisoformat(k.expires_at):
            k.status = "expired"


# Helper pour conserver le cookie sur les redirections
def redirect_with_session(url: str = "/admin") -> RedirectResponse:
    res = RedirectResponse(url=url, status_code=303)
    res.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=ADMIN_KEY,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 8,
    )
    return res


# ---------------------------------------------------------------------------
# Validation publique (appelée par le logiciel client)
# ---------------------------------------------------------------------------
class ValidateRequest(BaseModel):
    key: str
    hwid: str
    product_id: str


@app.post("/validate")
@limiter.limit("10/minute")
def validate_key(request: Request, req: ValidateRequest):
    with get_db() as db:
        info = db.get(LicenseKey, req.key)
        if not info:
            raise HTTPException(status_code=404, detail="Clé invalide")

        if info.product_id != req.product_id:
            raise HTTPException(status_code=403, detail="Cette clé n'est pas valide pour ce produit")

        if info.status == "revoked":
            raise HTTPException(status_code=403, detail="Accès révoqué par l'administrateur")

        now = datetime.utcnow()

        if info.status == "unused":
            info.hwid = req.hwid
            info.status = "active"
            if info.duration == "1_week":
                info.expires_at = (now + timedelta(days=7)).isoformat()
            elif info.duration == "1_month":
                info.expires_at = (now + timedelta(days=30)).isoformat()
            elif info.duration == "lifetime":
                info.expires_at = "lifetime"
            db.commit()

        if info.hwid != req.hwid:
            raise HTTPException(status_code=403, detail="Clé déjà associée à un autre appareil")

        if info.expires_at == "lifetime":
            return {"status": "valid", "time_left": "Accès illimité (à vie)"}

        exp_date = datetime.fromisoformat(info.expires_at)
        if now > exp_date:
            info.status = "expired"
            db.commit()
            raise HTTPException(status_code=403, detail="Licence expirée")

        remaining = exp_date - now
        return {
            "status": "valid",
            "time_left": f"{remaining.days} jours et {remaining.seconds // 3600} heures"
        }


# ---------------------------------------------------------------------------
# Pages HTML (login + panel admin)
# ---------------------------------------------------------------------------
def render_login_page(error: str = "") -> str:
    err_html = f'
