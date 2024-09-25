from fastapi import FastAPI,HTTPException,Depends,status,BackgroundTasks
from pydantic import BaseModel, EmailStr
from database import SessionLocal
from model import *
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import timedelta,datetime
import jwt
import aiosmtplib
from email.message import EmailMessage
import random
import string

user_app=FastAPI()

# schema
class UserBase(BaseModel):
    username: str
    email: EmailStr
    hashed_password: str

class UserOut(BaseModel):
    username: str
    email: EmailStr

class UserUp(BaseModel):
    old_username: str
    user_name:str

class Pwd(BaseModel):
    old_password:str
    new_password:str

class VerificationCode(BaseModel):
    email: EmailStr
    code: str

class ResetPasswordWithCode(BaseModel):
    email: EmailStr
    code: str
    new_password: str
    
# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT settings
SECRET_KEY = '2281c1e3b80e95aa12f0aac68180cc9a183bf0d24e2c1b3584c8ddcaa45d04ea'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7

# Functions for password hashing and verification
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# get current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
     try:
         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
         user = dict(payload)
         return user
     except jwt.PyJWTError:
         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate credentials")
     
async def send_verification_email(email: str, code: str):
    message = EmailMessage()
    message["From"] = "your email"
    message["To"] = email
    message["Subject"] = "Email Verification Code"
    message.set_content(f"Hello,\n\nYour verification code is {code}.\n\nBest regards,\nThe Team")

    await aiosmtplib.send(message, hostname="smtp.outlook.com", port=587, start_tls=True, username="your email", password="your mail password")

def generate_verification_code(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

############################################################################## user crud #########################################################
@user_app.post("/mg_users", tags=["user"])
async def create_user(user: UserBase, background_tasks: BackgroundTasks):
    db=SessionLocal()
    hashed_password = get_password_hash(user.hashed_password)
    
    existing_user = db.query(MgUser).filter(MgUser.email == user.email, MgUser.user_name == user.username, MgUser.is_deleted == False).first()

    if existing_user:
        raise HTTPException(status_code=409, detail="User already exists")

    db_user = MgUser(
        user_name=user.username,
        email=user.email,
        hashed_password=hashed_password,
        is_deleted=False
    )
    db.add(db_user)
    db.commit()
    
    verification_code = generate_verification_code()
    verification_record = MgVerificationCode(user_id=db_user.id, code=verification_code)
    db.add(verification_record)
    db.commit()
    
    background_tasks.add_task(send_verification_email, user.email, verification_code)
    return {"message": "User successfully created. Please verify your email."}

# verify email
@user_app.post("/verify_email", tags=["user"])
async def verify_email(verification: VerificationCode):
    db=SessionLocal()
    user = db.query(MgUser).filter(MgUser.email == verification.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    code_record = db.query(MgVerificationCode).filter(MgVerificationCode.user_id == user.id, MgVerificationCode.code == verification.code).first()
    if not code_record:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    user.is_verified = True
    db.delete(code_record)
    db.commit()

    return {"message": "Email verified successfully"}
# show single user data
@user_app.get("/mg_user_name/", tags=["user"])
async def get_all_users( current_user  = Depends(get_current_user)):
    db= SessionLocal()
    users = db.query(MgUser).filter(MgUser.user_name==current_user['username'],MgUser.id == current_user['id'], MgUser.is_deleted ==False).first()

    if not users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not exist")
    result=[]
    data_obj=UserOut(username=users.user_name,
                          email=users.email,    
                        )
    result.append(data_obj)
    return result

# show all users
@user_app.get("/mg_all_users/", tags=["user"])
async def get_all_users():
    db=SessionLocal()
    users = db.query(MgUser).filter(MgUser.is_deleted == False).all()
    if not users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not exist")
    result=[]
    for user in users:
        data_obj=UserOut(username=user.user_name,
                          email=user.email,     
                        )
        result.append(data_obj)
    return result

#update user
@user_app.put("/mg_user/", tags=["user"])
async def update_user( user: UserUp, current_user: dict = Depends(get_current_user)):
    db= SessionLocal()
    db_user = db.query(MgUser).filter(MgUser.user_name==user.old_username,MgUser.id==current_user['id'],MgUser.is_deleted==False ).first()

    # Update user information
    db_user.user_name = user.username
    
    db.commit()
    db.refresh(db_user)
    return {"message": "User successfully updated"}

#soft delete user
@user_app.delete("/delete user", tags=["user"])
async def update_user( current_user: dict = Depends(get_current_user)):
    db= SessionLocal()

    username = current_user.get("username")

    db.query(MgUser).filter(MgUser.email == username,MgUser.id==current_user['id']).update({"is_delet": True})
    db.commit()

    return {"message": "user soft deleted"}

# reset password
@user_app.post("/reset_password", tags=["Reset Password"])
async def reset_password_with_code(reset_data: ResetPasswordWithCode):
    db=SessionLocal()

    user = db.query(MgUser).filter(MgUser.email == reset_data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    code_record = db.query(MgVerificationCode).filter(MgVerificationCode.user_id == user.id, MgVerificationCode.code == reset_data.code).first()
    if not code_record:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    new_hashed_password = get_password_hash(reset_data.new_password)
    user.hashed_password = new_hashed_password
    db.delete(code_record)
    db.commit()

    return {"message": "Password updated successfully"}

######################################################## token ############################################

# create token     
@user_app.post("/token", tags=["token"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db= SessionLocal()

    user = db.query(MgUser).filter(MgUser.user_name == form_data.username,MgUser.is_deleted==False).first()
    expire = datetime.now()+ timedelta(days=7)
    expire_str = expire.isoformat()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="user not found")
    
    pswd = verify_password(form_data.password, user.hashed_password)

    if not pswd:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate credentials")
    
    data = {"id": user.id, "username": user.user_name, "expire": expire_str}
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": encoded_jwt, "token_type": "bearer"}

# establish a protected root
@user_app.get("/protected/", tags=["token"])
async def protected_route(current_user: dict = Depends(get_current_user)):
    return current_user

################################################################################################