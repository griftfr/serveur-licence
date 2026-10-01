from fastapi import FastAPI, HTTPException, Form, Request, Cookie, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
from contextlib import contextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
import secrets
import os
import shutil

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ADMIN_KEY = os.environ.get("ADMIN_KEY", "HAP2Md&aTT71vTK")
SESSION_COOKIE_NAME = "admin_session"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./keys_db.sqlite3")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Répertoire pour stocker les fichiers du client
UPLOADS_DIR = "client_files"
os.makedirs(UPLOADS_DIR, exist_ok=True)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class LicenseKey(Base):
    __tablename__ = "license_keys"

    key = Column(String, primary_key=True)
    product_id = Column(String, nullable=False)
    customer_email = Column(String, nullable=True)
    duration = Column(String, nullable=False)
    status = Column(String, nullable=False, default="unused")
    hwid = Column(String, nullable=True)
    expires_at = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def is_authenticated(admin_session: str = Cookie(None)) -> bool:
    return admin_session is not None and admin_session == ADMIN_KEY


def mark_expired_if_needed(k: LicenseKey) -> None:
    if k.status == "active" and k.expires_at and k.expires_at != "lifetime":
        if datetime.utcnow() > datetime.fromisoformat(k.expires_at):
            k.status = "expired"


def set_session_cookie(response, value: str):
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=value,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        max_age=60 * 60 * 8,
        path="/",
    )


# ---------------------------------------------------------------------------
# Validation publique & Téléchargement (appelées par le launcher client)
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


@app.post("/client/download/{filename}")
@limiter.limit("10/minute")
def download_client_file(request: Request, filename: str, req: ValidateRequest):
    """Permet au launcher de télécharger le fichier uniquement si la clé est valide."""
    with get_db() as db:
        info = db.get(LicenseKey, req.key)
        if not info:
            raise HTTPException(status_code=404, detail="Clé invalide")

        if info.product_id != req.product_id or info.hwid != req.hwid:
            raise HTTPException(status_code=403, detail="Accès refusé")

        if info.status in ["revoked", "expired"]:
            raise HTTPException(status_code=403, detail="Licence révoquée ou expirée")

        file_path = os.path.join(UPLOADS_DIR, filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Fichier introuvable sur le serveur")

        return FileResponse(file_path)


# ---------------------------------------------------------------------------
# Design commun (CSS partagé)
# ---------------------------------------------------------------------------
BASE_CSS = """
:root {
    --bg: #0b0d12;
    --panel: #13161d;
    --panel-2: #191d26;
    --border: #262b36;
    --text: #e8eaed;
    --muted: #8b92a3;
    --accent: #6d5ef8;
    --accent-2: #9b8cff;
    --green: #34d399;
    --red: #f87171;
    --amber: #fbbf24;
    --blue: #60a5fa;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: radial-gradient(circle at 20% 0%, #1a1530 0%, var(--bg) 45%);
    color: var(--text);
    min-height: 100vh;
}
a { color: var(--accent-2); }
::selection { background: var(--accent); color: white; }
"""


def render_login_page(error: str = "") -> str:
    err_html = f'
