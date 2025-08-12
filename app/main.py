from fastapi import FastAPI, HTTPException, Depends, Form, status
from sqlalchemy.orm import Session
from typing import Optional
from app.database import SessionLocal, engine
from app.models import Base, User, UserType
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer
from random import randint
from datetime import datetime, timedelta

app = FastAPI()
Base.metadata.create_all(bind=engine)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 token dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Temporary OTP storage
otp_store = {}

# ---------------------- DB Dependency -----------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------- JWT Token Creation -----------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ---------------------- Signup: OTP Flow -----------------------

@app.post("/signup/")
def signup(
    username: str = Form(...),
    email: str = Form(...),
    phone_number: str = Form(...),
    password: str = Form(...),
    user_type: UserType = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(
        (User.email == email) | 
        (User.username == username) | 
        (User.phone_number == phone_number)
    ).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    otp = str(randint(100000, 999999))
    otp_store[phone_number] = {
        "otp": otp,
        "data": {
            "username": username,
            "email": email,
            "phone_number": phone_number,
            "password": password,
            "user_type": user_type
        }
    }

    print(f"OTP for signup ({phone_number}): {otp}")
    return {"message": f"OTP sent to your phone (simulated):{otp}"}

@app.post("/verify-signup/")
def verify_signup(
    phone_number: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)
):
    stored = otp_store.get(phone_number)
    if not stored or stored["otp"] != otp:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    user_data = stored["data"]
    hashed_pw = pwd_context.hash(user_data["password"])

    new_user = User(
        username=user_data["username"],
        email=user_data["email"],
        phone_number=user_data["phone_number"],
        hashed_password=hashed_pw,
        user_type=user_data["user_type"]
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    del otp_store[phone_number]

    return {"message": "User registered successfully"}

# ---------------------- Login: OTP Flow -----------------------

@app.post("/login/")
def login(
    phone_number: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.phone_number == phone_number).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = str(randint(100000, 999999))
    otp_store[phone_number] = {"otp": otp, "user_id": user.id}
    print(f"OTP for login ({phone_number}): {otp}")
    return {"message": f"OTP sent to your phone (simulated) : {otp}"}

@app.post("/verify-login/")
def verify_login(
    phone_number: str = Form(...),
    otp: str = Form(...)
):
    stored = otp_store.get(phone_number)
    if not stored or stored["otp"] != otp:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    access_token = create_access_token(data={"sub": str(stored["user_id"])})
    del otp_store[phone_number]
    return {"access_token": access_token, "token_type": "bearer"}

# ---------------------- JWT Auth: Protected Route -----------------------

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user

@app.get("/protected/")
def protected_route(current_user: User = Depends(get_current_user)):
    return {
        "message": f"Hello, {current_user.username}! You are authorized.",
        "user_type": current_user.user_type
    }
