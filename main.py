from fastapi import FastAPI, HTTPException, Form, Request, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
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

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change-me")
SESSION_COOKIE_NAME = "admin_session"
# Laisse à False par défaut : certains proxys (dont Render en interne) peuvent faire perdre
# le cookie si le flag Secure est forcé alors que la requête interne n'est pas vue comme HTTPS.
# Tu peux passer COOKIE_SECURE=true en variable d'environnement si tu veux le forcer plus tard.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

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
    err_html = f'<div class="error">⚠ {error}</div>' if error else ""
    return f"""
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Connexion Admin</title>
        <style>
            {BASE_CSS}
            .wrap {{
                display: flex; align-items: center; justify-content: center;
                min-height: 100vh; padding: 20px;
            }}
            .card {{
                background: var(--panel);
                border: 1px solid var(--border);
                border-radius: 16px;
                padding: 40px 36px;
                width: 100%;
                max-width: 360px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.45);
            }}
            .icon {{
                width: 52px; height: 52px; border-radius: 14px;
                background: linear-gradient(135deg, var(--accent), var(--accent-2));
                display: flex; align-items: center; justify-content: center;
                font-size: 24px; margin-bottom: 18px;
            }}
            h2 {{ margin: 0 0 6px 0; font-size: 20px; }}
            p.sub {{ color: var(--muted); font-size: 13px; margin: 0 0 24px 0; }}
            .error {{
                background: rgba(248,113,113,0.12); border: 1px solid rgba(248,113,113,0.3);
                color: var(--red); padding: 10px 12px; border-radius: 10px;
                font-size: 13px; margin-bottom: 16px;
            }}
            input {{
                width: 100%; padding: 12px 14px; margin-bottom: 16px;
                border-radius: 10px; border: 1px solid var(--border);
                background: var(--panel-2); color: var(--text); font-size: 14px;
            }}
            input:focus {{ outline: none; border-color: var(--accent); }}
            button {{
                width: 100%; padding: 12px; border-radius: 10px; border: none;
                background: linear-gradient(135deg, var(--accent), var(--accent-2));
                color: white; font-weight: 600; font-size: 14px; cursor: pointer;
                transition: opacity 0.15s;
            }}
            button:hover {{ opacity: 0.9; }}
        </style>
    </head>
    <body>
        <div class="wrap">
            <form method="post" action="/admin/login" class="card">
                <div class="icon">🔐</div>
                <h2>Panel administrateur</h2>
                <p class="sub">Gestion des clés de licence</p>
                {err_html}
                <input type="password" name="admin_key" placeholder="Mot de passe admin" required autofocus>
                <button type="submit">Se connecter</button>
            </form>
        </div>
    </body>
    </html>
    """


STATUS_STYLES = {
    "active":  ("var(--green)", "rgba(52,211,153,0.12)", "Active"),
    "unused":  ("var(--blue)", "rgba(96,165,250,0.12)", "Non utilisée"),
    "expired": ("var(--amber)", "rgba(251,191,36,0.12)", "Expirée"),
    "revoked": ("var(--red)", "rgba(248,113,113,0.12)", "Révoquée"),
}


def status_badge(status: str) -> str:
    color, bg, label = STATUS_STYLES.get(status, ("var(--muted)", "rgba(139,146,163,0.12)", status))
    return f'<span class="badge" style="color:{color};background:{bg};">{label}</span>'


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

    msg_html = f'<div class="toast">✓ {message}</div>' if message else ""

    total = len(keys)
    active_count = sum(1 for k in keys if k.status == "active")
    unused_count = sum(1 for k in keys if k.status == "unused")

    rows = ""
    if not keys:
        rows = '<tr><td colspan="8" class="empty">Aucune clé pour le moment — génère la première ci-dessus.</td></tr>'
    for k in keys:
        revoke_btn = "" if k.status == "revoked" else f"""
            <form method="post" action="/admin/revoke" style="display:inline;">
                <input type="hidden" name="key" value="{k.key}">
                <button type="submit" class="btn-revoke">Révoquer</button>
            </form>
        """
        rows += f"""
        <tr>
            <td><code class="key-cell" onclick="navigator.clipboard.writeText('{k.key}')" title="Cliquer pour copier">{k.key}</code></td>
            <td>{k.product_id}</td>
            <td class="muted">{k.customer_email or '—'}</td>
            <td>{k.duration}</td>
            <td>{status_badge(k.status)}</td>
            <td class="muted">{(k.expires_at or '—')[:19].replace('T', ' ')}</td>
            <td class="muted">{k.hwid or '—'}</td>
            <td>{revoke_btn}</td>
        </tr>
        """

    return f"""
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Panel Admin</title>
        <style>
            {BASE_CSS}
            .topbar {{
                display: flex; justify-content: space-between; align-items: center;
                padding: 24px 32px; border-bottom: 1px solid var(--border);
            }}
            .topbar h1 {{ font-size: 18px; margin: 0; }}
            .topbar .brand {{ display:flex; align-items:center; gap:10px; }}
            .topbar .brand .dot {{
                width: 10px; height: 10px; border-radius: 50%;
                background: var(--green); box-shadow: 0 0 8px var(--green);
            }}
            .logout-btn {{
                background: var(--panel-2); border: 1px solid var(--border);
                color: var(--muted); padding: 8px 14px; border-radius: 8px;
                font-size: 13px; cursor: pointer;
            }}
            .logout-btn:hover {{ color: var(--text); }}
            .container {{ padding: 28px 32px; max-width: 1200px; margin: 0 auto; }}

            .stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
            .stat {{
                background: var(--panel); border: 1px solid var(--border);
                border-radius: 14px; padding: 18px 22px; min-width: 140px; flex: 1;
            }}
            .stat .num {{ font-size: 26px; font-weight: 700; }}
            .stat .label {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}

            .toast {{
                background: rgba(52,211,153,0.12); border: 1px solid rgba(52,211,153,0.3);
                color: var(--green); padding: 10px 14px; border-radius: 10px;
                font-size: 13px; margin-bottom: 18px;
            }}

            .create-card {{
                background: var(--panel); border: 1px solid var(--border);
                border-radius: 14px; padding: 20px; margin-bottom: 28px;
            }}
            .create-card h3 {{ margin: 0 0 14px 0; font-size: 14px; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }}
            .create-form {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
            .create-form input, .create-form select {{
                padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border);
                background: var(--panel-2); color: var(--text); font-size: 13px;
            }}
            .create-form input[name=product_id] {{ flex: 1; min-width: 200px; }}
            .create-form input[name=customer_email] {{ flex: 1; min-width: 180px; }}
            .create-form input[name=quantity] {{ width: 70px; }}
            .create-form button {{
                padding: 10px 20px; border-radius: 8px; border: none;
                background: linear-gradient(135deg, var(--accent), var(--accent-2));
                color: white; font-weight: 600; font-size: 13px; cursor: pointer;
            }}
            .create-form button:hover {{ opacity: 0.9; }}

            table {{ width: 100%; border-collapse: collapse; }}
            .table-card {{
                background: var(--panel); border: 1px solid var(--border);
                border-radius: 14px; overflow: hidden;
            }}
            th {{
                text-align: left; font-size: 11px; text-transform: uppercase;
                letter-spacing: 0.04em; color: var(--muted); font-weight: 600;
                padding: 14px 16px; border-bottom: 1px solid var(--border);
            }}
            td {{
                padding: 13px 16px; font-size: 13px; border-bottom: 1px solid var(--border);
            }}
            tr:last-child td {{ border-bottom: none; }}
            tr:hover td {{ background: rgba(255,255,255,0.015); }}
            .muted {{ color: var(--muted); }}
            .empty {{ text-align: center; color: var(--muted); padding: 40px !important; }}
            .key-cell {{
                cursor: pointer; background: var(--panel-2); padding: 3px 8px;
                border-radius: 6px; font-size: 12px; letter-spacing: 0.02em;
            }}
            .key-cell:hover {{ background: var(--border); }}
            .badge {{
                display: inline-block; padding: 3px 10px; border-radius: 20px;
                font-size: 11px; font-weight: 600;
            }}
            .btn-revoke {{
                background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.3);
                color: var(--red); padding: 6px 12px; border-radius: 7px;
                font-size: 12px; cursor: pointer; font-weight: 600;
            }}
            .btn-revoke:hover {{ background: rgba(248,113,113,0.2); }}
        </style>
    </head>
    <body>
        <div class="topbar">
            <div class="brand">
                <div class="dot"></div>
                <h1>Panel Admin — Licences</h1>
            </div>
            <form method="post" action="/admin/logout">
                <button type="submit" class="logout-btn">Déconnexion</button>
            </form>
        </div>

        <div class="container">
            {msg_html}

            <div class="stats">
                <div class="stat"><div class="num">{total}</div><div class="label">Clés totales</div></div>
                <div class="stat"><div class="num">{active_count}</div><div class="label">Actives</div></div>
                <div class="stat"><div class="num">{unused_count}</div><div class="label">Non utilisées</div></div>
            </div>

            <div class="create-card">
                <h3>Générer des clés</h3>
                <form method="post" action="/admin/create" class="create-form">
                    <input type="text" name="product_id" placeholder="ID produit (ex: ebook-gestion-de-soi)" required>
                    <input type="email" name="customer_email" placeholder="Email client (optionnel)">
                    <select name="duration">
                        <option value="1_week">1 semaine</option>
                        <option value="1_month">1 mois</option>
                        <option value="lifetime">À vie</option>
                    </select>
                    <input type="number" name="quantity" value="1" min="1" max="200">
                    <button type="submit">Générer</button>
                </form>
            </div>

            <div class="table-card">
                <table>
                    <tr>
                        <th>Clé</th><th>Produit</th><th>Client</th><th>Durée</th>
                        <th>Statut</th><th>Expire le</th><th>Appareil</th><th></th>
                    </tr>
                    {rows}
                </table>
            </div>
        </div>
    </body>
    </html>
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
    set_session_cookie(response, ADMIN_KEY)
    return response


@app.post("/admin/logout")
def admin_logout():
    response = RedirectResponse(url="/admin", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
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

    quantity = max(1, min(quantity, 200))

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

    response = RedirectResponse(url="/admin", status_code=303)
    # on réaffirme le cookie à chaque redirection pour éviter toute perte de session
    set_session_cookie(response, admin_session)
    return response


@app.post("/admin/revoke")
def revoke_key(admin_session: str = Cookie(None), key: str = Form(...)):
    if not is_authenticated(admin_session):
        raise HTTPException(status_code=403, detail="Accès refusé")

    with get_db() as db:
        info = db.get(LicenseKey, key)
        if info:
            info.status = "revoked"
            db.commit()

    response = RedirectResponse(url="/admin", status_code=303)
    set_session_cookie(response, admin_session)
    return response
