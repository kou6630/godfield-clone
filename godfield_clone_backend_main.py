# FastAPI + PostgreSQL + Session Cookie Auth (Minimal Working Skeleton)
# NOTE: This is a starter. Session storage is placeholder (needs session table) — good for boot check.

from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
import secrets

# ✅ Set to your local Postgres
DATABASE_URL = "postgresql://postgres:takoroido@localhost:6630/godfield_clone"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------
# Models (minimal)
# --------------------

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    coins = Column(Integer, default=40)
    hp_base = Column(Integer, default=40)
    mp_base = Column(Integer, default=40)


class Card(Base):
    __tablename__ = "cards"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    rarity = Column(String, nullable=False)  # N/R/SR/SSR
    type = Column(String, nullable=False)    # attack/defense/miracle/special
    element = Column(String, nullable=False) # fire/water/earth/wood/light/dark/none
    mp_cost = Column(Integer, default=0)
    attack_value = Column(Integer, nullable=True)
    defense_value = Column(Integer, nullable=True)


class UserCard(Base):
    __tablename__ = "user_cards"
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    card_id = Column(Integer, ForeignKey("cards.id"), primary_key=True)
    qty = Column(Integer, default=0)


# --------------------
# DB Init
# --------------------

@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)


# --------------------
# Dependencies
# --------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


# --------------------
# Routes
# --------------------

@app.get("/")
def root():
    return {"status": "backend running"}


@app.post("/register")
def register(username: str, password: str, db: Session = Depends(get_db)):
    if not username or not password:
        raise HTTPException(status_code=400, detail="username/password required")

    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username exists")

    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    return {"message": "registered"}


@app.post("/login")
def login(response: Response, username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ⚠ placeholder session token (no server-side session store yet)
    session_token = secrets.token_hex(16)
    response.set_cookie(key="session", value=session_token, httponly=True, samesite="lax")
    return {"message": "logged in"}


@app.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    session_cookie = request.cookies.get("session")
    if not session_cookie:
        raise HTTPException(status_code=401, detail="Not logged in")

    # ⚠ placeholder: returns first user (replace with session->user mapping)
    user = db.query(User).order_by(User.id.asc()).first()
    if not user:
        raise HTTPException(status_code=404, detail="No users")

    return {"username": user.username, "coins": user.coins, "hp": user.hp_base, "mp": user.mp_base}
