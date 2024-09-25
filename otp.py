from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from model import MgUser, MgVerificationCode
from pydantic import BaseModel, EmailStr
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
import pyotp
import aiosmtplib
from email.message import EmailMessage
import random
import string
import jwt

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

class Login(BaseModel):
    username: str
    password: str

class VerifyOtp(BaseModel):
    email: EmailStr
    otp: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

async def send_otp_email(email: str, otp: str):
    message = EmailMessage()
    message["From"] = "your_email@example.com"
    message["To"] = email
    message["Subject"] = "Your OTP Code"
    message.set_content(f"Your OTP code is {otp}")

    await aiosmtplib.send(message, hostname="smtp.outlook.com", port=587, start_tls=True, username="your_email@example.com", password="your_password")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/login")
async def login(request: Login, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(MgUser).filter(MgUser.user_name == request.username).first()
    if not user or not pwd_context.verify(request.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    otp = generate_otp()
    db_otp = MgVerificationCode(user_id=user.id, code=otp)
    db.add(db_otp)
    db.commit()

    background_tasks.add_task(send_otp_email, user.email, otp)
    return {"message": "OTP sent to your email"}

@app.post("/verify_otp")
async def verify_otp(request: VerifyOtp, db: Session = Depends(get_db)):
    user = db.query(MgUser).filter(MgUser.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp_record = db.query(MgVerificationCode).filter(MgVerificationCode.user_id == user.id, MgVerificationCode.code == request.otp).first()
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    db.delete(otp_record)
    db.commit()

    access_token = create_access_token(data={"sub": user.user_name})
    return {"access_token": access_token, "token_type": "bearer"}
