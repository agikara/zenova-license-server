import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text

# -------------------- Config --------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
APP_NAME = os.getenv("APP_NAME", "MyGoldBot_Pro").strip()

if not DATABASE_URL:
    # Render me DATABASE_URL env var set hota hai
    raise RuntimeError("DATABASE_URL env var missing")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

app = FastAPI(title="Zenova License Server", version="1.0.0")


# -------------------- DB init --------------------
def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS licenses (
            id BIGSERIAL PRIMARY KEY,
            license_key TEXT UNIQUE NOT NULL,
            plan TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',  -- active | blocked
            expires_at TIMESTAMPTZ NULL,            -- NULL = lifetime
            bind_login BIGINT NULL,
            bind_server TEXT NULL,
            product TEXT NOT NULL DEFAULT 'MyGoldBot_Pro',
            note TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """))
        conn.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
        """))

init_db()


# -------------------- Helpers --------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def require_admin(x_api_key: Optional[str]):
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="ADMIN_API_KEY not set on server")
    if not x_api_key or x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized (bad admin key)")

def gen_key(prefix="ZNV"):
    # Example: ZNV-AB12-CD34-EF56-GH78
    raw = secrets.token_hex(10).upper()  # 20 chars hex
    chunks = [raw[i:i+4] for i in range(0, len(raw), 4)]
    return f"{prefix}-" + "-".join(chunks[:5])


# -------------------- Models --------------------
class VerifyReq(BaseModel):
    key: str = Field(..., min_length=6)
    login: int
    server: str
    product: str = Field(default="MyGoldBot_Pro")
    version: str = Field(default="1.0.0")

class VerifyResp(BaseModel):
    ok: bool
    reason: Optional[str] = None
    plan: Optional[str] = None
    status: Optional[str] = None
    expires_at: Optional[str] = None
    now: str
    message: str

class CreateReq(BaseModel):
    plan: str  # 7d | 1m | 3m | lifetime
    bind_login: Optional[int] = None
    bind_server: Optional[str] = None
    product: str = Field(default="MyGoldBot_Pro")
    note: Optional[str] = None

class CreateResp(BaseModel):
    license_key: str
    plan: str
    expires_at: Optional[str]
    status: str
    bind_login: Optional[int]
    bind_server: Optional[str]
    product: str

class BlockReq(BaseModel):
    key: str
    reason: Optional[str] = None

class ExtendReq(BaseModel):
    key: str
    add_days: int = 0  # e.g. 30
    set_lifetime: bool = False


# -------------------- Public endpoints --------------------
@app.get("/health")
def health():
    return {"ok": True, "app": APP_NAME, "time": now_utc().isoformat()}

@app.post("/v1/verify", response_model=VerifyResp)
def verify(req: VerifyReq):
    tnow = now_utc()

    with engine.begin() as conn:
        row = conn.execute(
            text("""SELECT license_key, plan, status, expires_at, bind_login, bind_server, product
                    FROM licenses WHERE license_key=:k"""),
            {"k": req.key.strip()}
        ).mappings().first()

        if not row:
            return VerifyResp(ok=False, reason="not_found", now=tnow.isoformat(),
                              message="License key not found")

        # product match (optional strict)
        if row["product"] and row["product"] != req.product:
            return VerifyResp(ok=False, reason="product_mismatch", now=tnow.isoformat(),
                              message="License not for this product")

        if row["status"] != "active":
            return VerifyResp(ok=False, reason="blocked", plan=row["plan"], status=row["status"],
                              expires_at=(row["expires_at"].isoformat() if row["expires_at"] else None),
                              now=tnow.isoformat(), message="License is blocked")

        expires_at = row["expires_at"]
        if expires_at is not None and tnow >= expires_at:
            return VerifyResp(ok=False, reason="expired", plan=row["plan"], status=row["status"],
                              expires_at=expires_at.isoformat(), now=tnow.isoformat(),
                              message="License expired")

        # Binding rules (First activation bind if empty)
        bind_login = row["bind_login"]
        bind_server = row["bind_server"]

        # If server has no bind yet => bind on first activation
        if bind_login is None and bind_server is None:
            conn.execute(text("""
                UPDATE licenses
                SET bind_login=:l, bind_server=:s, updated_at=NOW()
                WHERE license_key=:k
            """), {"l": req.login, "s": req.server.strip(), "k": req.key.strip()})
            bind_login = req.login
            bind_server = req.server.strip()

        # If already bound, must match
        if bind_login is not None and int(bind_login) != int(req.login):
            return VerifyResp(ok=False, reason="login_mismatch", plan=row["plan"], status=row["status"],
                              expires_at=(expires_at.isoformat() if expires_at else None),
                              now=tnow.isoformat(), message="Account login mismatch")

        if bind_server is not None and bind_server != req.server.strip():
            return VerifyResp(ok=False, reason="server_mismatch", plan=row["plan"], status=row["status"],
                              expires_at=(expires_at.isoformat() if expires_at else None),
                              now=tnow.isoformat(), message="Broker server mismatch")

        # OK
        return VerifyResp(ok=True, plan=row["plan"], status=row["status"],
                          expires_at=(expires_at.isoformat() if expires_at else None),
                          now=tnow.isoformat(), message="License OK")


# -------------------- Admin endpoints --------------------
@app.post("/admin/create", response_model=CreateResp)
def admin_create(req: CreateReq, x_api_key: Optional[str] = Header(default=None)):
    require_admin(x_api_key)
    plan = req.plan.strip().lower()

    tnow = now_utc()
    expires_at = None
    if plan == "7d":
        expires_at = tnow + timedelta(days=7)
    elif plan == "1m":
        expires_at = tnow + timedelta(days=30)
    elif plan == "3m":
        expires_at = tnow + timedelta(days=90)
    elif plan == "lifetime":
        expires_at = None
    else:
        raise HTTPException(status_code=400, detail="Invalid plan. Use 7d, 1m, 3m, lifetime")

    key = gen_key()

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO licenses (license_key, plan, status, expires_at, bind_login, bind_server, product, note)
            VALUES (:k, :p, 'active', :e, :bl, :bs, :prod, :note)
        """), {
            "k": key,
            "p": plan,
            "e": expires_at,
            "bl": req.bind_login,
            "bs": (req.bind_server.strip() if req.bind_server else None),
            "prod": req.product.strip(),
            "note": req.note
        })

    return CreateResp(
        license_key=key, plan=plan, expires_at=(expires_at.isoformat() if expires_at else None),
        status="active", bind_login=req.bind_login,
        bind_server=(req.bind_server.strip() if req.bind_server else None),
        product=req.product.strip()
    )

@app.post("/admin/block")
def admin_block(req: BlockReq, x_api_key: Optional[str] = Header(default=None)):
    require_admin(x_api_key)
    with engine.begin() as conn:
        res = conn.execute(text("""
            UPDATE licenses SET status='blocked', note=COALESCE(note,'') || :r, updated_at=NOW()
            WHERE license_key=:k
        """), {"k": req.key.strip(), "r": f"\nBLOCK: {req.reason or ''}"})
        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "message": "blocked"}

@app.post("/admin/unblock")
def admin_unblock(req: BlockReq, x_api_key: Optional[str] = Header(default=None)):
    require_admin(x_api_key)
    with engine.begin() as conn:
        res = conn.execute(text("""
            UPDATE licenses SET status='active', note=COALESCE(note,'') || :r, updated_at=NOW()
            WHERE license_key=:k
        """), {"k": req.key.strip(), "r": f"\nUNBLOCK: {req.reason or ''}"})
        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "message": "active"}

@app.post("/admin/extend")
def admin_extend(req: ExtendReq, x_api_key: Optional[str] = Header(default=None)):
    require_admin(x_api_key)

    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT expires_at, plan FROM licenses WHERE license_key=:k
        """), {"k": req.key.strip()}).mappings().first()

        if not row:
            raise HTTPException(status_code=404, detail="Key not found")

        if req.set_lifetime:
            conn.execute(text("""
                UPDATE licenses SET plan='lifetime', expires_at=NULL, updated_at=NOW()
                WHERE license_key=:k
            """), {"k": req.key.strip()})
            return {"ok": True, "message": "set to lifetime"}

        add_days = int(req.add_days)
        if add_days <= 0:
            raise HTTPException(status_code=400, detail="add_days must be > 0")

        current = row["expires_at"]
        tnow = now_utc()
        if current is None:
            # lifetime already
            return {"ok": True, "message": "already lifetime (no expiry)"}

        # If expired already, extend from now; else extend from current expiry
        base = current if current > tnow else tnow
        new_exp = base + timedelta(days=add_days)

        conn.execute(text("""
            UPDATE licenses SET expires_at=:e, updated_at=NOW()
            WHERE license_key=:k
        """), {"e": new_exp, "k": req.key.strip()})

    return {"ok": True, "message": f"extended by {add_days} days", "new_expires_at": new_exp.isoformat()}