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
# Render fournit parfois une URL Postgres en "postgres://" -> SQLAlchemy veut "postgresql://"
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
    err_html = f'<p style="color:#ff6b6b;">{error}</p>' if error else ""
    return f"""
    <html><head><title>Connexion Admin</title>
    <style>
        body {{ background:#111; color:#eee; font-family:sans-serif; display:flex;
                justify-content:center; align-items:center; height:100vh; margin:0; }}
        form {{ background:#1c1c1c; padding:30px; border-radius:10px; width:300px; }}
        input {{ width:100%; padding:10px; margin:10px 0; border-radius:5px; border:none; box-sizing:border-box; }}
        button {{ width:100%; padding:10px; border-radius:5px; border:none; background:#4caf50; color:white; cursor:pointer; }}
    </style></head>
    <body>
        <form method="post" action="/admin/login">
            <h2>Connexion Admin</h2>
            {err_html}
            <input type="password" name="admin_key" placeholder="Mot de passe admin" required>
            <button type="submit">Se connecter</button>
        </form>
    </body></html>
    """


def render_admin_panel(db, message: str = "") -> str:
    keys = db.query(LicenseKey).order_by(LicenseKey.created_at.desc()).all()
    changed = False
    for k in keys:
        before = k.status
        mark_expired_if_needed(k)
        if k.status != before:
            changed = True
    if changed:
        db.commit()

    msg_html = f'<p style="color:#4caf50;">{message}</p>' if message else ""

    rows = ""
    for k in keys:
        revoke_btn = "" if k.status == "revoked" else f"""
            <form method="post" action="/admin/revoke" style="display:inline;">
                <input type="hidden" name="key" value="{k.key}">
                <button type="submit" style="background:#e53935;">Révoquer</button>
            </form>
        """
        rows += f"""
        <tr>
            <td>{k.key}</td>
            <td>{k.product_id}</td>
            <td>{k.customer_email or '-'}</td>
            <td>{k.duration}</td>
            <td>{k.status}</td>
            <td>{k.expires_at or '-'}</td>
            <td>{k.hwid or '-'}</td>
            <td>{revoke_btn}</td>
        </tr>
        """

    return f"""
    <html><head><title>Panel Admin</title>
    <style>
        body {{ background:#111; color:#eee; font-family:sans-serif; padding:30px; }}
        table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
        th, td {{ border:1px solid #333; padding:8px; text-align:left; font-size:13px; }}
        th {{ background:#1c1c1c; }}
        button {{ padding:6px 12px; border-radius:5px; border:none; background:#4caf50; color:white; cursor:pointer; }}
        select, input[type=text], input[type=email], input[type=number] {{
            padding:8px; border-radius:5px; border:none; margin-right:10px; margin-bottom:8px; }}
        .create-form {{ background:#1c1c1c; padding:20px; border-radius:10px; margin-top:20px; }}
        .logout {{ float:right; }}
    </style></head>
    <body>
        <form method="post" action="/admin/logout" class="logout">
            <button type="submit" style="background:#555;">Déconnexion</button>
        </form>
        <h1>Panel Admin — Gestion des clés</h1>
        {msg_html}

        <div class="create-form">
            <form method="post" action="/admin/create">
                <input type="text" name="product_id" placeholder="ID produit (ex: ebook-gestion-de-soi)" required>
                <input type="email" name="customer_email" placeholder="Email client (optionnel)">
                <select name="duration">
                    <option value="1_week">1 semaine</option>
                    <option value="1_month">1 mois</option>
                    <option value="lifetime">À vie</option>
                </select>
                <input type="number" name="quantity" value="1" min="1" max="200" style="width:80px;">
                <button type="submit">Générer</button>
            </form>
        </div>

        <table>
            <tr>
                <th>Clé</th><th>Produit</th><th>Client</th><th>Durée</th>
                <th>Statut</th><th>Expire le</th><th>Appareil</th><th>Action</th>
            </tr>
            {rows}
        </table>
    </body></html>
    """


@app.get("/admin", response_class=HTMLResponse)
def admin_panel(admin_session: str = Cookie(None)):
    if not is_authenticated(admin_session):
        return HTMLResponse(render_login_page())
    with get_db() as db:
        return HTMLResponse(render_admin_panel(db))


@app.post("/admin/login")
@limiter.limit("5/minute")
def admin_login(request: Request, admin_key: str = Form(...)):
    if admin_key != ADMIN_KEY:
        return HTMLResponse(render_login_page(error="Mot de passe incorrect"))
    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=ADMIN_KEY,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 8,
    )
    return response


@app.post("/admin/logout")
def admin_logout():
    response = RedirectResponse(url="/admin", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.post("/admin/create")
def create_key(
    admin_session: str = Cookie(None),
    duration: str = Form(...),
    product_id: str = Form(...),
    customer_email: str = Form(""),
    quantity: int = Form(1),
):
    if not is_authenticated(admin_session):
        raise HTTPException(status_code=403, detail="Accès refusé")

    quantity = max(1, min(quantity, 200))  # garde-fou anti-abus

    with get_db() as db:
        for _ in range(quantity):
            new_key = secrets.token_hex(8).upper()
            db.add(LicenseKey(
                key=new_key,
                product_id=product_id,
                customer_email=customer_email or None,
                duration=duration,
                status="unused",
            ))
        db.commit()

    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/revoke")
def revoke_key(admin_session: str = Cookie(None), key: str = Form(...)):
    if not is_authenticated(admin_session):
        raise HTTPException(status_code=403, detail="Accès refusé")

    with get_db() as db:
        info = db.get(LicenseKey, key)
        if info:
            info.status = "revoked"
            db.commit()

    return RedirectResponse(url="/admin", status_code=303)
