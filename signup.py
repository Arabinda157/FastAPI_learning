from fastapi import FastAPI,HTTPException,Depends,status,Form,BackgroundTasks
from jose import JWTError,jwt
from pydantic import BaseModel, EmailStr
from database import SessionLocal
from model import *
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import timedelta,datetime
from typing import Optional
import aiosmtplib
from email.message import EmailMessage
#import jwt

SECRET_KEY = "2281c1e3b80e95aa12f0aac68180cc9a183bf0d24e2c1b3584c8ddcaa45d04ea"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

class UserCreate(BaseModel):
    Username: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    Username: Optional[str]=None

class ResetPassword(BaseModel):
    email: EmailStr
    new_password: str

class UserProfileOut(BaseModel):
        user_name:str
        email:EmailStr
        hashed_password:str

def get_User(db, Username: str):
    return db.query(MgUser).filter(MgUser.user_name == Username).first()

def get_User_by_email(db, email: str):
    return db.query(MgUser).filter(MgUser.email == email).first()

def create_User(db, User: UserCreate):
    db_User = MgUser(
        user_name=User.Username,
        email=User.email,
        hashed_password=pwd_context.hash(User.password)
    )
    db.add(db_User)
    db.commit()
    db.refresh(db_User)
    return db_User

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_User(db, Username: str, password: str):
    User = get_User(db, Username)
    if not User or not verify_password(password, User.hashed_password):
        return False
    return User

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
        expire_str = expire.isoformat()
    else:
        expire = datetime.now() + timedelta(minutes=15)
        expire_str = expire.isoformat()
    to_encode.update({"exp": expire_str})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_User(token: str = Depends(oauth2_scheme)):
    db=SessionLocal()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        print(username)
        if username is None:
            raise credentials_exception
        token_data = TokenData(Username=username)
    except JWTError:
        raise credentials_exception
    user = get_User(db, token_data.Username)
    if user is None:
        raise credentials_exception
    return user

async def send_welcome_email(email: str, username: str):
    message = EmailMessage()
    message["From"] = "arabinda157@outlook.com"
    message["To"] = email
    message["Subject"] = "Welcome to Our Service"
    message.set_content(f"Hello {username},\n\nWelcome to our service! We're glad to have you with us.\n\nBest regards,\nThe Team")

    await aiosmtplib.send(message, hostname="smtp.outlook.com", port=587, start_tls=True, username="arabinda157@outlook.com", password="Aryan@1257")

@app.post("/signup", response_model=Token)
async def signup(user: UserCreate,background_tasks: BackgroundTasks):
    db = SessionLocal()
    db_user = get_User(db, user.Username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    db_email = get_User_by_email(db, user.email)
    if db_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    create_User(db, user)
    # access_token = create_access_token(
    #     data={"sub": user.Username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # )
    background_tasks.add_task(send_welcome_email, user.email, user.Username)
    # return {"access_token": access_token, "token_type": "bearer"}
    return {"msg":"created successfully"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = authenticate_User(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.user_name}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/forgot-password")
async def forgot_password(reset_data: ResetPassword):
    db = SessionLocal()
    user = get_User_by_email(db, reset_data.email)
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")
    user.hashed_password = pwd_context.hash(reset_data.new_password)
    db.add(user)
    db.commit()
    return {"msg": "Password reset successful"}

@app.get("/users/me", response_model=UserProfileOut)
async def read_users_me(current_user: dict = Depends(get_current_User)):
    return current_user
    # return UserProfileOut(
    #     user_name=current_user.user_name,
    #     email=current_user.email,
    #     hashed_password=current_user.hashed_password
    # )

@app.get("/retrive data")
async def show_data(current_user  = Depends(get_current_User)):
    db = SessionLocal()
    db_user = db.query(MgUser).filter(MgUser.user_name == current_user["user_name"],MgUser.is_deleted==False).first()
    print(current_user["user_name"])
    if not db_user:
        raise HTTPException(status_code=409,detail="user not found")
    user =UserProfileOut(
        user_name=db_user.user_name,
        email=db_user.email,
        hashed_password=db_user.hashed_password
    )
    return user