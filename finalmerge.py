from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from pymongo import MongoClient, ReturnDocument
from datetime import datetime, timedelta
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from enum import Enum
import string
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
#from my_module import Status
from fastapi import APIRouter
from fastapi import Query, BackgroundTasks
from bson import json_util
from typing import List
from pydantic import BaseModel, Field, validator
import secrets
import re
import logging




app = FastAPI()

# Add CORSMiddleware to the application instance
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # List of allowed origins
    allow_credentials=True,  # Allows credentials (such as cookies, authorization headers, etc.) to be sent in cross-origin requests
    allow_methods=["*"],  # Allows all methods (such as GET, POST, DELETE, etc.)
    allow_headers=["*"],  # Allows all headers
    expose_headers=["*"]
)

# Load environment variables
load_dotenv()

EMAIL_ADDRESS="snipe.upl@gmail.com"
EMAIL_PASSWORD="ljzz hsqx qvwc fbdr"
MONGO_DETAILS="mongodb+srv://somnath:somnath@cluster0.izhugny.mongodb.net/"
client = MongoClient(MONGO_DETAILS)
db = client.Login_Register
users_collection = db.Login_Register_Auth

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


#client = MongoClient(MONGO_DETAILS)
database = client.Admin_Module

# Admin Department
department_collection = database.Dept
sequence_department_collection = database.Dept_Sequence

# Admin Sector
sector_collection = database.Sector
sequence_sector_collection = database.Sector_Sequence

# Admin Skill
skill_collection = database.Skill
sequence_skill_collection = database.Skill_Sequence

# mycol = database.city_management

# Organization Role
# db1 = client.Role_Management
db1 = client.Role_Management
role_collection = db1.role
role_sequence_collection = db1.role_sequence

# Organization User
mycol1 = db1.users
user_sequence_collection = db1.user_sequence

# Organization City
mycol2 = db1.departments
dept_sequence_collection = db1.dept_sequence

# Organization Job
job_collection = db1.job_descriptions
organization_collection = db1.organizations

# Subsequent admin management
subsequent_admin = client.subsequent_admin
subsequent_collection = subsequent_admin.subsequent_admin




#-------------------------------------------ORGANIZATION & STUDENT---------------------------------------------------------------------------------------------


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Enum for User Roles
class UserRole(str, Enum):
    organization = "Organization"
    student = "Student"

# Pydantic Models
class UserSchema(BaseModel):
    email: EmailStr
    role: UserRole
    name: str
    mobile_number: str
    password: str
    confirm_password: str
    organization_id: Optional[str] = None

class OTPVerificationSchema(BaseModel):
    email: EmailStr
    otp: int

class Token(BaseModel):
    access_token: str
    token_type: str
    organization_id: Optional[str] = None
    name: str
    role: UserRole
    email: EmailStr

class TokenData(BaseModel):
    email: Optional[str] = None

# (rest of your code)

# Utility Functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(email: str, password: str):
    user = users_collection.find_one({"email": email})
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def send_email_otp(email: str, otp: int):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Your OTP'
    body = f'Your OTP is: {otp}'
    message.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()

def save_user_organisation(user_data: UserSchema, hashed_password: str, otp: int):
    user_dict = user_data.dict()
    user_dict.pop('confirm_password')
    user_dict['password'] = hashed_password
    user_dict['otp'] = otp
    user_dict['otp_expiry'] = datetime.utcnow() + timedelta(minutes=10)
    users_collection.insert_one(user_dict)

def generate_unique_organization_id(length=10):
    characters = string.ascii_uppercase + string.digits
    while True:
        organization_id = ''.join(random.choice(characters) for _ in range(length))
        if not users_collection.find_one({"organization_id": organization_id}):
            return organization_id
        
def send_password_reset_confirmation_email(email: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Password Reset Confirmation'

    body = f'Hi {name},\n\nYour password has been successfully reset. If you did not initiate this change, please contact our support immediately.\n\nBest Regards,\nAI- Disha'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()

def send_welcome_email(email: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Welcome to Our AI - Disha!'
    body = f'Hi {name},\n\nWelcome to AI- Disha!\nCongratulations you have Registered Successfully!!! \nWe are excited to have you on board.\n\nWe are glad you have registered to our platform. \nVisit: www.aidisha.com \n\nThanks & Regards,\nAI - Disha'
    message.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()

def get_client_ip(request: Request):
    if "X-Forwarded-For" in request.headers:
        return request.headers["X-Forwarded-For"].split(",")[0]
    return request.client.host

def send_new_device_login_email(email: str, ip: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'New Device Login Detected'
    body = f"""Hi {name},
    
A new login to your account was detected from a device using IP address {ip}.
If this was you, you can safely ignore this email. If you do not recognize this login, we strongly recommend that you change your password immediately as your account may be compromised.

Best Regards,
AI- Disha"""
    message.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()



@app.post("/organization-Register/")
async def send_otp(user_data: UserSchema):
    if user_data.password != user_data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    
    if users_collection.find_one({"email": user_data.email}):
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    hashed_password = get_password_hash(user_data.password)
    otp = random.randint(100000, 999999)
    save_user_organisation(user_data, hashed_password, otp)
    send_email_otp(user_data.email, otp)
    
    return {"message": "OTP sent to the email. Please verify to complete registration."}

# Enum for User Roles
class UserRole(str, Enum):
    organization = "Organization"
    student = "Student"

@app.post("/organization-Register-Verify-OTP/")
async def verify_otp(otp_data: OTPVerificationSchema):
    user = users_collection.find_one({"email": otp_data.email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    current_time = datetime.utcnow()
    if user.get('otp') == otp_data.otp and current_time < user.get('otp_expiry'):
        update_data = {"is_verified": True}
        
        if user.get('role') == UserRole.organization.value:  # Ensure this line uses UserRole
            organization_id1 = generate_unique_organization_id()
            update_data["organization_id1"] = organization_id1
        
        users_collection.update_one({"email": otp_data.email}, {"$set": update_data})
        send_welcome_email(otp_data.email, user.get('name', 'User'))
        
        return {"message": "OTP verified successfully. Registration complete."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


@app.post("/organization-Login", response_model=Token)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):   
    email = form_data.username  # Treat the 'username' field as the user's email
    password = form_data.password

    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Continue with your existing logic...


    # Example function to get client IP - implement this based on your requirements
    client_ip = get_client_ip(request)
    
    # Check if IP is new
    if client_ip not in user.get('known_ips', []):
        # If new, update known IPs and send email
        users_collection.update_one({"email": user['email']}, {"$addToSet": {"known_ips": client_ip}})
        send_new_device_login_email(user['email'], client_ip, user['name'])

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )

    # Extract additional information from the user object
    organization_id = user.get('organization_id')
    name = user.get('name')
    role = user.get('role')
    email = user['email']

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "organization_id": organization_id,
        "name": name,
        "role": role,
        "email": email
    }

@app.post("/organization-Forget-Password-Email/")
async def password_reset_send_otp(email: EmailStr):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found.")
    
    # Generate and save OTP
    otp = random.randint(100000, 999999)
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)  # OTP expires in 10 minutes
    users_collection.update_one({"email": email}, {"$set": {"reset_otp": otp, "reset_otp_expiry": otp_expiry}})
    
    # Send OTP to user's email
    send_email_otp(email, otp)
    
    return {"message": "OTP sent to the email. Please verify to proceed with password reset."}

@app.post("/organization-Forget-Password/Verify-OTP/")
async def password_reset_verify_otp(otp_data: OTPVerificationSchema):
    user = users_collection.find_one({"email": otp_data.email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    current_time = datetime.utcnow()
    if user.get('reset_otp') == otp_data.otp and current_time < user.get('reset_otp_expiry'):
        # Optionally, you could mark the OTP as used here to prevent reuse
        return {"message": "OTP verified successfully. You may now reset your password."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

@app.post("/organization-Password-Reset/")
async def password_reset(otp_data: OTPVerificationSchema, new_password: str, confirm_password: str):
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    
    user = users_collection.find_one({"email": otp_data.email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    current_time = datetime.utcnow()
    if user.get('reset_otp') == otp_data.otp and current_time < user.get('reset_otp_expiry'):
        hashed_password = get_password_hash(new_password)
        users_collection.update_one({"email": otp_data.email}, {"$set": {"password": hashed_password}})
        # Optionally, clear the OTP fields here to prevent reuse

        # Send password reset confirmation email
        send_password_reset_confirmation_email(otp_data.email, user['name'])

        return {"message": "Password reset successfully."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
    
#-----------------------------------------ADMIN LOGIN----------------------------------------------------------------------------------------


db = client.admin_user_Login_Register
users_collection = db.admin_user_Login_Register_Auth

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Role(str, Enum):
    admin = "Admin"
    # student = "Student"


class UserSchema(BaseModel):
    email: EmailStr
    role: Role
    name: str
    mobile_number: str



class OTPVerificationSchema(BaseModel):
    email: EmailStr
    otp: int


class Token(BaseModel):
    access_token: str
    token_type: str
    admin_id: Optional[str] = None
    name: str
    role: Role
    email: EmailStr


class TokenData(BaseModel):
    email: Optional[str] = None

def generate_random_password(length=8):
    # I am Generating a random password here.....
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(email: str, password: str):
    user = users_collection.find_one({"email": email})
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def send_email_otp(email: str, otp: int):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Your OTP'

    body = f'Your OTP is: {otp}'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()



def save_user(user_data: UserSchema,otp: int):
    user_dict = user_data.dict()
    user_dict['otp'] = otp
    user_dict['otp_expiry'] = datetime.utcnow() + timedelta(minutes=10)
    users_collection.insert_one(user_dict)


def generate_unique_admin_id(length=5):
    prefix = "ADM"
    while True:
        suffix = ''.join(random.choices(string.digits, k=length))
        admin_id = f"{prefix}{suffix}"
        if not users_collection.find_one({"admin_id": admin_id}):
            return admin_id


def send_password_reset_confirmation_email(email: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Password Reset Confirmation'

    body = f'Hi {name},\n\nYour password has been successfully reset. If you did not initiate this change, please contact our support immediately.\n\nBest Regards,\nAI- Disha'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def send_welcome_email(email: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Welcome to Our AI - Disha!'

    body = f'Hi {name},\n\nWelcome to AI- Disha!\nCongratulations you have Registered Successfully!!! \nWe are excited to have you on board.\n\nWe are glad you have registered to our platform. \nVisit: www.aidisha.com \n\nThanks & Regards,\nAI - Disha'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def get_client_ip(request: Request):
    if "X-Forwarded-For" in request.headers:
        return request.headers["X-Forwarded-For"].split(",")[0]
    return request.client.host


def send_new_device_login_email(email: str, ip: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'New Device Login Detected'

    body = f"""Hi {name},

A new login to your account was detected from a device using IP address {ip}.
If this was you, you can safely ignore this email. \nIf you do not recognize this login, we strongly recommend that you change your password immediately as your account may be compromised.

Best Regards,
AI- Disha"""
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def send_email(recipient_email: str, subject: str, body: str):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "snipe.upl@gmail.com"
    sender_password = "ljzz hsqx qvwc fbdr"

    # Creating the email here
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email
    # Sending the email here
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())


def creating_super_adminid():
    existing_super_admin = users_collection.find_one({"super_admin": 1})
    if existing_super_admin:
        raise HTTPException(status_code=400, detail="A super admin already exists.")

    counter = users_collection.find_one_and_update(
        {'_id': 'super_admin_id'},
        {'$inc': {'sequence_value': 1}},
        upsert=True,
        return_document=True
    )
    return counter['sequence_value']

@app.post("/admin-user-Register/")
async def send_otp(user_data: UserSchema, status: str = Query(...,enum = ["InActive"]) ):
    if users_collection.find_one({"email": user_data.email}):
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    sequence_id = creating_super_adminid()
    otp = random.randint(100000, 999999)
    save_user(user_data,otp)
    send_email_otp(user_data.email, otp)
    users_collection.find_one_and_update({"email":user_data.email},
                        {"$set":{"status":status, "super_admin":sequence_id}},return_document=True)

    return {"message": "OTP sent to the email. Please verify to complete registration."}


def save_automated_password(email,password):
    hashed_password = get_password_hash(password)
    users_collection.find_one_and_update({"email":email},
                        {"$set":{"password":hashed_password}},return_document=True)

@app.post("/admin-user-Register-Verify-OTP/")
async def verify_otp(admin_schema:UserSchema ,background_tasks:BackgroundTasks ,otp_data: OTPVerificationSchema):
    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    
    current_time = datetime.utcnow()
    if user.get('otp') == otp_data.otp and current_time < user.get('otp_expiry'):
        update_data = {"is_verified": True}
        if user.get('role') == Role.admin:
            admin_id = generate_unique_admin_id()
            update_data["admin_id"] = admin_id
        users_collection.find_one_and_update({"email": otp_data.email}, {"$set": update_data})

        send_welcome_email(otp_data.email, user['name'])
        
        automated_password = generate_random_password()
        save_automated_password(otp_data.email,automated_password)
        email_subject = "Your New Account Information"
        email_body = (f"Dear {admin_schema.name},\n\n"
                  f"Your account has been created. Please use the following credentials to log in:\n"
                  f"Email: {otp_data.email}\n"
                  f"Password: {automated_password}\n"
                  f"Click to Login: www.ai_dishalogin.co.in\n"
                  f"After logging in, please change your password immediately.\n\n"
                  f"Best regards,\nAI DISHA")

    # Below line will send mail automatically when post operation is applied
        background_tasks.add_task(send_email, otp_data.email, email_subject, email_body)


        return {"message": "OTP verified successfully. Registration complete."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


@app.post("/admin-user-Login", response_model=Token)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username
    password = form_data.password

    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client_ip = get_client_ip(request)
    if client_ip not in user.get('known_ips', []):
        users_collection.update_one({"email": user['email']}, {"$addToSet": {"known_ips": client_ip}})
        send_new_device_login_email(user['email'], client_ip, user['name'])

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )

    admin_id = user.get('admin_id')
    name = user.get('name')
    role = user.get('role')
    email = user['email']

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "admin_id": admin_id,
        "name": name,
        "role": role,
        "email": email
    }


@app.post("/admin-user-Forget-Password-Email/")
async def password_reset_send_otp(email: EmailStr):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found.")

    otp = random.randint(100000, 999999)
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    users_collection.update_one({"email": email}, {"$set": {"reset_otp": otp, "reset_otp_expiry": otp_expiry}})

    send_email_otp(email, otp)

    return {"message": "OTP sent to the email. Please verify to proceed with password reset."}


@app.post("/admin-user-Forget-Password/Verify-OTP/")
async def password_reset_verify_otp(otp_data: OTPVerificationSchema):
    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    current_time = datetime.utcnow()
    if user.get('reset_otp') == otp_data.otp and current_time < user.get('reset_otp_expiry'):
        return {"message": "OTP verified successfully. You may now reset your password."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


def validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit.")
    # if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
    #     raise HTTPException(status_code=400, detail="Password must contain at least one special character.")

@app.post("/admin-user-Password-Reset/")
async def password_reset(otp_data: OTPVerificationSchema, new_password: str, confirm_password: str):
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    
    validate_password_strength(new_password)

    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    current_time = datetime.utcnow()
    if user.get('reset_otp') == otp_data.otp and current_time < user.get('reset_otp_expiry'):
        hashed_password = get_password_hash(new_password)
        users_collection.update_one({"email": otp_data.email}, {"$set": {"password": hashed_password}})
        users_collection.find_one_and_update({"email":otp_data.email},
                        {"$set": {"status":"Active"}},return_document=True)
        send_password_reset_confirmation_email(otp_data.email, user['name'])


        return {"message": "Password reset successfully."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


@app.get("/check status for super_admin")
async def check_status(adminId:int):
    return users_collection.find_one({ "super_admin": adminId },{ "status": 1, "_id": 0 })


@app.get("/check status for subsequent_admin")
async def check_status(adminId:str):
    return users_collection.find_one({ "user_id": adminId },{ "status": 1, "_id": 0 })



# *------------------------------------------------------------subsequent admin---------------------------------------------------------------*



class get_subsequent_admin_user_data(BaseModel):
   name : str
   email : EmailStr
   mobile : int
   Date_of_birth : datetime
   address : str
   aadhar_number : int
   pan_number : str
   Joined_date : Optional[datetime] = datetime.now().isoformat()
#    password : Optional[str] = None

   @validator('mobile')
   def validate_mobile(cls, value):
        if len(str(value)) != 10:
            raise ValueError('Mobile number must be 10 digits.')
        return value
    
   @validator('aadhar_number')
   def validate_aadhar(cls, value):
        if len(str(value)) != 12:
            raise ValueError('Aadhar number must be 12 digits.')
        return value
    
   @validator('pan_number')
   def validate_pan(cls, value):
        pan_pattern = r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$'
        if not re.match(pan_pattern, value):
            raise ValueError('Invalid PAN number format.')
        return value
   

def creating_userid():
    counter = users_collection.find_one_and_update(
        {'_id': 'user_id'},
        {'$inc': {'sequence_value': 1}},
        upsert=True,
        return_document=True
    )
    return counter['sequence_value']


@app.post("/create_subsequent_admin")
async def post_data(admin_detail: get_subsequent_admin_user_data,background_tasks:BackgroundTasks, gender : str = Query(...,enum=["Male","Female"]),
            state_name: str = Query(..., enum=["Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
                                            "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand","Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur","Meghalaya", "Mizoram", "Nagaland",
                                            "Odisha", "Punjab","Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura","Uttar Pradesh", "Uttarakhand", "West Bengal"]), 
            city_name: str = Query(..., enum = ["Visakhapatnam", "Vijayawada","Itanagar", "Tawang","Guwahati", "Dibrugarh","Patna","Gaya","Raipur", "Bhilai","Panaji", "Margao","Ahmedabad", "Surat","Gurugram", "Faridabad", 
                                            "Shimla", "Manali","Ranchi", "Jamshedpur","Bengaluru", "Mysuru","Thiruvananthapuram", "Kochi","Indore", "Bhopal","Mumbai", "Pune", "Imphal", "Churachandpur","Shillong", "Tura", 
                                            "Aizawl", "Lunglei","Kohima", "Dimapur","Bhubaneswar", "Cuttack","Ludhiana", "Amritsar","Jaipur", "Udaipur","Gangtok", "Pelling","Chennai", "Coimbatore","Hyderabad", "Warangal", 
                                            "Agartala", "Udaipur","Lucknow", "Varanasi","Dehradun", "Haridwar","Kolkata", "Darjeeling"]),
            status: str = Query(..., enum=["InActive"]), role: str = Query(..., enum = ["Admin","Organisation", "student"])):
    
    if users_collection.find_one({"email": admin_detail.email}):
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    generate_password = generate_random_password()
    # save_automated_password(admin_detail.email,generate_password)
    sequence_value = creating_userid()
    document = admin_detail.dict()
    document["gender"] = gender
    document["state"] = state_name
    document["city"] = city_name
    document["role"] = role
    document["department"] = role
    # document["password"] = generate_password
    document["status"] = status
    document["user_id"] = f"UID{sequence_value:06d}"
    
    users_collection.insert_one(document)
    save_automated_password(admin_detail.email,generate_password)

    email_subject = "Your New Account Information"
    email_body = (f"Dear {admin_detail.name},\n\n"
                  f"Your account has been created. Please use the following credentials to log in:\n"
                  f"Email: {admin_detail.email}\n"
                  f"Password: {generate_password}\n"
                  f"After logging in, please change your password immediately.\n\n"
                  f"Best regards,\nAI DISHA")
    
    # Below line will send mail automatically when post operation is applied
    background_tasks.add_task(send_email, admin_detail.email, email_subject, email_body)

    return {"status": "success", "user_id": document["user_id"], "generated_password": generate_password}

@app.put("/create_subsequent_admin")
async def edit_data(user_id: str, admin_detail: get_subsequent_admin_user_data, gender : str = Query(...,enum=["Male","Female"]),
            state_name: str = Query(..., enum=["Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
                                            "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand","Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur","Meghalaya", "Mizoram", "Nagaland",
                                            "Odisha", "Punjab","Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura","Uttar Pradesh", "Uttarakhand", "West Bengal"]), 
            city_name: str = Query(..., enum = ["Visakhapatnam", "Vijayawada","Itanagar", "Tawang","Guwahati", "Dibrugarh","Patna","Gaya","Raipur", "Bhilai","Panaji", "Margao","Ahmedabad", "Surat","Gurugram", "Faridabad", 
                                            "Shimla", "Manali","Ranchi", "Jamshedpur","Bengaluru", "Mysuru","Thiruvananthapuram", "Kochi","Indore", "Bhopal","Mumbai", "Pune", "Imphal", "Churachandpur","Shillong", "Tura", 
                                            "Aizawl", "Lunglei","Kohima", "Dimapur","Bhubaneswar", "Cuttack","Ludhiana", "Amritsar","Jaipur", "Udaipur","Gangtok", "Pelling","Chennai", "Coimbatore","Hyderabad", "Warangal", 
                                            "Agartala", "Udaipur","Lucknow", "Varanasi","Dehradun", "Haridwar","Kolkata", "Darjeeling"]),
             role: str = Query(..., enum = ["Admin","Organisation", "student"])): 
    
    Full_name = admin_detail.name
    Email = admin_detail.email
    Mobile = admin_detail.mobile 
    DOB = admin_detail.Date_of_birth 
    Address = admin_detail.address
    Anumber = admin_detail.aadhar_number 
    Pnumber = admin_detail.pan_number 
    update_details = {
            "name" : Full_name,
            "email" : Email,
            "mobile" : Mobile,
            "address" : Address,
            "Date_of_birth":DOB,
            "aadhar_number" : Anumber,
            "pan_number" : Pnumber,
            "gender" : gender,
            "state" : state_name,
            "city" : city_name,
            "role": role,
            "department": role,
    }
    
    document = users_collection.find_one_and_update({"user_id":user_id},
                        {"$set": update_details},return_document=True)
    document["_id"] = str(document["_id"])
    return document


@app.patch("/update_status")
async def update_admin_user_status(user_id: str, status: str = Query(..., enum=["Active","InActive"]),):
    document = users_collection.find_one_and_update({"user_id":user_id},
                        {"$set": {"status":status}},return_document=True)
    document["_id"] = str(document["_id"])
    return document

@app.get("/get_active_user")
async def get_All_active_admin():
    document = users_collection.find({"status":"Active"})
    result = []
    for doc in document:
        doc["_id"] = str(doc["_id"])
        result.append(doc)
    return result

@app.get("/get_all_users")
def get_all_admin():
    # documents = client.subsequent_admin.subsequent_collection.find({})
    documents = users_collection.find({})
    result = []
    for doc in documents:
        doc["_id"] = str(doc["_id"])
        result.append(doc)
    return result

@app.delete("/delete_super_admin")
async def delete_super_admin(Super_admin:int):
    users_collection.delete_one({"super_admin":Super_admin})
    users_collection.delete_one({"sequence_value":1})
    return {"message": "Super Admin Deleted Successfully."}

@app.delete("/delete_subsequent_admin")
async def delete_subsequent_admin(userid:str):
        users_collection.delete_one({"user_id":userid})
        return {"message": "Subsequent Admin Deleted Successfully."}




#----------------------------------ADMIN DEPARTMENT / ADMIN SEQUENCE / SKILL------------------------------------------------------------------------




# Enum for department status
class Status(str, Enum):
    active = "Active"
    inactive = "Inactive"

# Pydantic model for updating department status
class DepartmentStatusUpdate(BaseModel):
    status: Status

# Pydantic models
class Department(BaseModel):
    admin_id: str
    dept_name: str
    creation_date: datetime = Field(default_factory=datetime.now)
    status: Status = Status.active

    @validator('dept_name')
    def validate_dept_name(cls, value):
        if value.isdigit():
            raise ValueError('Department name cannot be only numeric.')
        if not value.strip():
            raise ValueError('Department name cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Department name must contain at least one alphanumeric character.')
        return value

# Pydantic model for department in the database
class DepartmentInDB(Department):
    dept_id: str
    updated_date: Optional[datetime] = None

# Pydantic model for updating department
class DepartmentUpdate(BaseModel):
    dept_name: str
    updated_date: datetime = Field(default_factory=datetime.now)

    @validator('dept_name')
    def validate_dept_name(cls, value):
        if value.isdigit():
            raise ValueError('Department name cannot be only numeric.')
        if not value.strip():
            raise ValueError('Department name cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Department name must contain at least one alphanumeric character.')
        return value


def fetch_next_dept_id():
    sequence_document = sequence_department_collection.find_one_and_update(
        {"_id": "dept_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"DPID{sequence:06}"

# Function to add a new department
def add_department(department: Department) -> DepartmentInDB:
    dept_id = fetch_next_dept_id()
    department_data = department.dict()
    department_data["dept_id"] = dept_id
    department_collection.insert_one(department_data)
    return DepartmentInDB(**department_data)

# Endpoint to create a new department
@app.post("/admin-departments/", response_model=DepartmentInDB)
def create_department(department: Department):
    normalized_name = department.dept_name.strip().lower()
    existing_department = department_collection.find_one({"dept_name": normalized_name})
    if existing_department:
        raise HTTPException(status_code=409, detail="Department name already exists.")
    
    department_in_db = add_department(department)
    return department_in_db

# Endpoint to update a department
@app.put("/admin-departments-update/{admin_id}/{dept_id}", response_model=DepartmentInDB)
def update_department(admin_id: str, dept_id: str, department_update: DepartmentUpdate):
    updated_result = department_collection.find_one_and_update(
        {"admin_id": admin_id, "dept_id": dept_id},
        {"$set": {"dept_name": department_update.dept_name, "updated_date": department_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return DepartmentInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Department not found")

# Endpoint to update the status of a department
@app.patch("/admin-departments-status/{admin_id}/{dept_id}/status", response_model=DepartmentInDB)
def update_department_status(admin_id: str, dept_id: str, status_update: DepartmentStatusUpdate):
    updated_result = department_collection.find_one_and_update(
        {"admin_id": admin_id, "dept_id": dept_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return DepartmentInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Department not found")

# Convert BSON ObjectId to string
def convert_objectid_to_str(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    return obj

# Endpoint to get all active departments for a specific admin
@app.get("/admin-departments-show/{admin_id}/Active", response_model=List[DepartmentInDB])
def get_active_departments_by_admin(admin_id: str):
    active_departments = list(department_collection.find({"admin_id": admin_id, "status": Status.Active.value}))
    if not active_departments:
        raise HTTPException(status_code=404, detail="No Active departments found for the given admin ID")
    
    return [DepartmentInDB(**convert_objectid_to_str(department)) for department in active_departments]

@app.get("/all-departments/", response_model=List[DepartmentInDB])
def get_all_departments():
    departments = list(department_collection.find())
    
    if not departments:
        raise HTTPException(status_code=404, detail="No departments found.")
    
    return [DepartmentInDB(**convert_objectid_to_str(department)) for department in departments]


# Sector

# Pydantic model for updating sector status
class SectorStatusUpdate(BaseModel):
    status: Status

# Pydantic model for sector
class Sector(BaseModel):
    admin_id: str
    sector_name: str
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    status: Status = Status.active

    @validator('sector_name')
    def validate_sector_name(cls, value):
        if value.isdigit():
            raise ValueError('Sector name cannot be only numeric.')
        if not value.strip():
            raise ValueError('Sector name cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Sector name must contain at least one alphanumeric character.')
        return value

# Pydantic model for sector in the database
class SectorInDB(Sector):
    sector_id: str
    updated_date: Optional[datetime] = None

# Pydantic model for updating sector
class SectorUpdate(BaseModel):
    sector_name: str
    updated_date: datetime = Field(default_factory=datetime.utcnow)

    @validator('sector_name')
    def validate_sector_name(cls, value):
        if value.isdigit():
            raise ValueError('Sector name cannot be only numeric.')
        if not value.strip():
            raise ValueError('Sector name cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Sector name must contain at least one alphanumeric character.')
        return value


# Function to fetch the next sector ID
def fetch_next_sector_id():
    sequence_document = sequence_sector_collection.find_one_and_update(
        {"_id": "sector_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"SECTID{sequence:06}"

# Function to add a new sector
def add_sector(sector: Sector) -> SectorInDB:
    sector_id = fetch_next_sector_id()
    sector_data = sector.dict()
    sector_data["sector_id"] = sector_id
    sector_collection.insert_one(sector_data)
    return SectorInDB(**sector_data)

# Endpoint to create a new sector
@app.post("/admin-sectors/", response_model=SectorInDB)
def create_sector(sector: Sector):
    normalized_name = sector.sector_name.strip().lower()
    existing_sector = sector_collection.find_one({"sector_name": normalized_name})
    if existing_sector:
        raise HTTPException(status_code=409, detail="Sector name already exists.")
    
    sector_in_db = add_sector(sector)
    return sector_in_db

# Endpoint to update a sector
@app.put("/admin-sectors-update/{admin_id}/{sector_id}", response_model=SectorInDB)
def update_sector(admin_id: str, sector_id: str, sector_update: SectorUpdate):
    updated_result = sector_collection.find_one_and_update(
        {"admin_id": admin_id, "sector_id": sector_id},
        {"$set": {"sector_name": sector_update.sector_name, "updated_date": sector_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SectorInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Sector not found")

# Endpoint to update the status of a sector
@app.patch("/admin-sectors-status/{admin_id}/{sector_id}/status", response_model=SectorInDB)
def update_sector_status(admin_id: str, sector_id: str, status_update: SectorStatusUpdate):
    updated_result = sector_collection.find_one_and_update(
        {"admin_id": admin_id, "sector_id": sector_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SectorInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Sector not found")

# Endpoint to get all active sectors for a specific admin
@app.get("/admin-sectors-show-active/{admin_id}/Active", response_model=List[SectorInDB])
def get_active_sectors_by_admin(admin_id: str):
    active_sectors = list(sector_collection.find({"admin_id": admin_id, "status": Status.Active.value}))
    if not active_sectors:
        raise HTTPException(status_code=404, detail="No active sectors found for the given admin ID")
    
    return [SectorInDB(**convert_objectid_to_str(sector)) for sector in active_sectors]

@app.get("/all-sector/", response_model=List[SectorInDB])
def get_all_sectors():
    Sector = list(sector_collection.find())
    
    if not Sector:
        raise HTTPException(status_code=404, detail="No sector found.")
    
    return [SectorInDB(**convert_objectid_to_str(Sector)) for Sector in Sector]



# Enum for skill status
class SkillStatus(str, Enum):
    active = "Active"
    inactive = "Inactive"

# Pydantic model for updating skill status
class SkillStatusUpdate(BaseModel):
    status: SkillStatus

# Pydantic model for skill
class Skill(BaseModel):
    admin_id: str
    skill_name: str
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    status: SkillStatus = SkillStatus.active

    @validator('skill_name')
    def validate_skill_name(cls, value):
        if value.isdigit():
            raise ValueError('Skill name cannot be only numeric.')
        if not value.strip():
            raise ValueError('Skill name cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Skill name must contain at least one alphanumeric character.')
        return value

# Pydantic model for skill in the database
class SkillInDB(Skill):
    skill_id: str
    updated_date: Optional[datetime] = None

# Pydantic model for updating skill
class SkillUpdate(BaseModel):
    skill_name: str
    updated_date: datetime = Field(default_factory=datetime.utcnow)

    @validator('skill_name')
    def validate_skill_name(cls, value):
        if value.isdigit():
            raise ValueError('Skill name cannot be only numeric.')
        if not value.strip():
            raise ValueError('Skill name cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Skill name must contain at least one alphanumeric character.')
        return value


# Function to fetch the next skill ID
def fetch_next_skill_id():
    sequence_document = sequence_skill_collection.find_one_and_update(
        {"_id": "skill_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"SKILLID{sequence:06}"

# Function to add a new skill
def add_skill(skill: Skill) -> SkillInDB:
    skill_id = fetch_next_skill_id()
    skill_data = skill.dict()
    skill_data["skill_id"] = skill_id
    skill_collection.insert_one(skill_data)
    return SkillInDB(**skill_data)

# Endpoint to create a new skill
@app.post("/admin-skills/", response_model=SkillInDB)
def create_skill(skill: Skill):
    normalized_name = skill.skill_name.strip().lower()
    existing_skill = skill_collection.find_one({"skill_name": normalized_name})
    if existing_skill:
        raise HTTPException(status_code=409, detail="Skill name already exists.")
    
    skill_in_db = add_skill(skill)
    return skill_in_db

# Endpoint to update a skill
@app.put("/admin-skills-update/{admin_id}/{skill_id}", response_model=SkillInDB)
def update_skill(admin_id: str, skill_id: str, skill_update: SkillUpdate):
    updated_result = skill_collection.find_one_and_update(
        {"admin_id": admin_id, "skill_id": skill_id},
        {"$set": {"skill_name": skill_update.skill_name, "updated_date": skill_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SkillInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Skill not found")

# Endpoint to update the status of a skill
@app.patch("/admin-skills-status/{admin_id}/{skill_id}/status", response_model=SkillInDB)
def update_skill_status(admin_id: str, skill_id: str, status_update: SkillStatusUpdate):
    updated_result = skill_collection.find_one_and_update(
        {"admin_id": admin_id, "skill_id": skill_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SkillInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Skill not found")

# Endpoint to get all active skills for a specific admin
@app.get("/admin-skills-show/{admin_id}/active", response_model=List[SkillInDB])
def get_active_skills_by_admin(admin_id: str):
    active_skills = skill_collection.find({"admin_id": admin_id, "status": SkillStatus.active.value})
    if not active_skills:
        raise HTTPException(status_code=404, detail="No active skills found for the given admin ID")
    
    return [SkillInDB(**convert_objectid_to_str(skill)) for skill in active_skills]

@app.get("/all-skill/", response_model=List[SkillInDB])
def get_all_skills():
    Skill = list(skill_collection.find())
    
    if not Skill:
        raise HTTPException(status_code=404, detail="No skill found.")
    
    return [SkillInDB(**convert_objectid_to_str(Skill)) for Skill in Skill]




#-------------------------------------------------- ADMIN AREA MANAGEMENT--------------------------------------------------------------------

db3 = client.State_Management
state_collection = db3.states
sequence_state_collection = db3.State_Sequence

district_collection = db3.district
sequence_district_collection = db3.district_Sequence

city_collection = db3.city
sequence_city_collection = db3.city_Sequence


# Enum for Status
class Status(str, Enum):
    Active = "Active"
    Inactive = "Inactive"

# Mapping of state names to state codes
state_codes = {
    "Andhra Pradesh": "AP",
    "Arunachal Pradesh": "AR",
    "Assam": "AS",
    "Bihar": "BR",
    "Chhattisgarh": "CG",
    "Goa": "GA",
    "Gujarat": "GJ",
    "Haryana": "HR",
    "Himachal Pradesh": "HP",
    "Jharkhand": "JH",
    "Karnataka": "KA",
    "Kerala": "KL",
    "Madhya Pradesh": "MP",
    "Maharashtra": "MH",
    "Manipur": "MN",
    "Meghalaya": "ML",
    "Mizoram": "MZ",
    "Nagaland": "NL",
    "Odisha": "OR",
    "Punjab": "PB",
    "Rajasthan": "RJ",
    "Sikkim": "SK",
    "Tamil Nadu": "TN",
    "Telangana": "TG",
    "Tripura": "TR",
    "Uttar Pradesh": "UP",
    "Uttarakhand": "UK",
    "West Bengal": "WB"
}

# Pydantic models
class StateBase(BaseModel):
    state_name: str = Field(..., description="The name of the state", example="Karnataka")
    state_code: str = Field(..., description="The code of the state", example="KA")
    status: Optional[Status] = Status.Active

class StateInDB(StateBase):
    state_id: str
    created_date: datetime
    updated_date: Optional[datetime] = None

class StateUpdate(BaseModel):
    state_name: Optional[str] = Field(None, description="The name of the state", example="Karnataka")

# Function to get the next sequence value
def get_next_sequence_value(sequence_name: str) -> int:
    sequence_document = sequence_state_collection.find_one_and_update(
        {"_id": sequence_name},
        {"$inc": {"sequence_value": 1}},
        return_document=ReturnDocument.AFTER,
        upsert=True
    )
    return sequence_document["sequence_value"]

@app.get("/states/")
async def get_states(
    state_name: str = Query(..., enum=list(state_codes.keys()))
):
    state_code = state_codes[state_name]
    sequence_value = get_next_sequence_value("state_id")
    state_id = f"STID{sequence_value:06d}"  # Format state_id as STID000001, STID000002, etc.
    state_document = {
        "state_id": state_id,
        "state_name": state_name,
        "state_code": state_code,
        "status": Status.Active.value,
        "created_date": datetime.utcnow(),
        "updated_date": datetime.utcnow()
    }
    result = state_collection.insert_one(state_document)
    return {"selected_state": state_name, "state_code": state_code, "created_date": datetime.utcnow(), "state_id": state_id}

# Endpoint to update a state
@app.put("/states/{state_id}", response_model=StateInDB)
async def edit_state(
    state_id: str,
    state_name: Optional[str] = Query(None, enum=list(state_codes.keys()))
):
    update_data = {}
    if state_name:
        update_data["state_name"] = state_name
        update_data["state_code"] = state_codes[state_name]

    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    update_data["updated_date"] = datetime.utcnow()
    updated_result = state_collection.find_one_and_update(
        {"state_id": state_id},
        {"$set": update_data},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return StateInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="State not found")

# Endpoint to update state status
@app.put("/states/{state_id}/active-inactive", response_model=StateInDB)
async def active_inactive_status(state_id: str, status: Status = Query(..., enum=[Status.Active, Status.Inactive])):
    state = state_collection.find_one({"state_id": state_id})
    if not state:
        raise HTTPException(status_code=404, detail="State not found")

    updated_result = state_collection.find_one_and_update(
        {"state_id": state_id},
        {"$set": {"status": status.value, "updated_date": datetime.utcnow()}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return StateInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Failed to update state status")

# Endpoint to get all active states
@app.get("/states/active", response_model=List[StateInDB])
async def get_active_states():
    active_states = list(state_collection.find({"status": Status.Active.value}))
    return [StateInDB(**state) for state in active_states]

# Endpoint to get all states
@app.get("/states/all-states", response_model=List[StateInDB])
async def get_all_states():
    all_states = list(state_collection.find({"status": {"$in": [Status.Active.value, Status.Inactive.value]}}))
    return [StateInDB(**state) for state in all_states]



# ---------------------------------------------District Management-------------------------------------------

class GetStateDetails(BaseModel):
    creation_date: datetime = datetime.utcnow()
    district_name: str
    District_Code: int

districts_by_state = {
    "Andhra Pradesh": ["Anantapur", "Chittoor", "East Godavari", "Guntur", "Krishna", "Kurnool", "Nellore", "Prakasam", "Srikakulam", "Visakhapatnam", "Vizianagaram", "West Godavari", "YSR Kadapa"],
    "Arunachal Pradesh": ["Anjaw", "Changlang", "Dibang Valley", "East Kameng", "East Siang", "Kamle", "Kra Daadi", "Kurung Kumey", "Lepa Rada", "Lohit", "Longding", "Lower Dibang Valley", "Lower Siang", "Lower Subansiri", "Namsai", "Pakke-Kessang", "Papum Pare", "Shi-Yomi", "Siang", "Tawang", "Tirap", "Upper Dibang Valley", "Upper Siang", "Upper Subansiri", "West Kameng", "West Siang"],
    "Assam": ["Baksa", "Barpeta", "Biswanath", "Bongaigaon", "Cachar", "Charaideo", "Chirang", "Darrang", "Dhemaji", "Dhubri", "Dibrugarh", "Dima Hasao", "Goalpara", "Golaghat", "Hailakandi", "Hojai", "Jorhat", "Kamrup", "Kamrup Metropolitan", "Karbi Anglong", "Karimganj", "Kokrajhar", "Lakhimpur", "Majuli", "Morigaon", "Nagaon", "Nalbari", "Sivasagar", "Sonitpur", "South Salmara-Mankachar", "Tinsukia", "Udalguri", "West Karbi Anglong"],
    "Bihar": ["Araria", "Arwal", "Aurangabad", "Banka", "Begusarai", "Bhagalpur", "Bhojpur", "Buxar", "Darbhanga", "East Champaran (Motihari)", "Gaya", "Gopalganj", "Jamui", "Jehanabad", "Kaimur (Bhabua)", "Katihar", "Khagaria", "Kishanganj", "Lakhisarai", "Madhepura", "Madhubani", "Munger", "Muzaffarpur", "Nalanda", "Nawada", "Patna", "Purnia", "Rohtas", "Saharsa", "Samastipur", "Saran", "Sheikhpura", "Sheohar", "Sitamarhi", "Siwan", "Supaul", "Vaishali", "West Champaran"],
    "Chhattisgarh": ["Balod", "Baloda Bazar", "Balrampur", "Bastar", "Bemetara", "Bijapur", "Bilaspur", "Dantewada", "Dhamtari", "Durg", "Gariaband", "Gaurela-Pendra-Marwahi", "Janjgir-Champa", "Jashpur", "Kabirdham (Kawardha)", "Kanker", "Kondagaon", "Korba", "Koriya (Baikunthpur)", "Mahasamund", "Mungeli", "Narayanpur", "Raigarh", "Raipur", "Rajnandgaon", "Sukma", "Surajpur", "Surguja"],
    "Goa": ["North Goa", "South Goa"],
    "Gujarat": ["Ahmedabad", "Amreli", "Anand", "Aravalli", "Banaskantha (Palanpur)", "Bharuch", "Bhavnagar", "Botad", "Chhota Udaipur", "Dahod", "Dang (Ahwa)", "Devbhoomi Dwarka", "Gandhinagar", "Gir Somnath", "Jamnagar", "Junagadh", "Kheda (Nadiad)", "Kutch", "Mahisagar", "Mehsana", "Morbi", "Narmada (Rajpipla)", "Navsari", "Panchmahal (Godhra)", "Patan", "Porbandar", "Rajkot", "Sabarkantha (Himmatnagar)", "Surat", "Surendranagar", "Tapi (Vyara)", "Vadodara", "Valsad"],
    "Haryana": ["Ambala", "Bhiwani", "Charkhi Dadri", "Faridabad", "Fatehabad", "Gurugram", "Hisar", "Jhajjar", "Jind", "Kaithal", "Karnal", "Kurukshetra", "Mahendragarh", "Nuh", "Palwal", "Panchkula", "Panipat", "Rewari", "Rohtak", "Sirsa", "Sonipat", "Yamunanagar"],
    "Himachal Pradesh": ["Bilaspur", "Chamba", "Hamirpur", "Kangra", "Kinnaur", "Kullu", "Lahaul and Spiti", "Mandi", "Shimla", "Sirmaur", "Solan", "Una"],
    "Jharkhand": ["Bokaro", "Chatra", "Deoghar", "Dhanbad", "Dumka", "East Singhbhum", "Garhwa", "Giridih", "Godda", "Gumla", "Hazaribagh", "Jamtara", "Khunti", "Koderma", "Latehar", "Lohardaga", "Pakur", "Palamu", "Ramgarh", "Ranchi", "Sahebganj", "Seraikela Kharsawan", "Simdega", "West Singhbhum"],
    "Karnataka": ["Bagalkot", "Ballari", "Belagavi", "Bengaluru Rural", "Bengaluru Urban", "Bidar", "Chamarajanagar", "Chikkaballapur", "Chikkamagaluru", "Chitradurga", "Dakshina Kannada", "Davanagere", "Dharwad", "Gadag", "Hassan", "Haveri", "Kalaburagi", "Kodagu", "Kolar", "Koppal", "Mandya", "Mysuru", "Raichur", "Ramanagara", "Shivamogga", "Tumakuru", "Udupi", "Uttara Kannada", "Vijayapura", "Yadgir"],
    "Kerala": ["Alappuzha", "Ernakulam", "Idukki", "Kannur", "Kasaragod", "Kollam", "Kottayam", "Kozhikode", "Malappuram", "Palakkad", "Pathanamthitta", "Thiruvananthapuram", "Thrissur", "Wayanad"],
    "Madhya Pradesh": ["Agar Malwa", "Alirajpur", "Anuppur", "Ashoknagar", "Balaghat", "Barwani", "Betul", "Bhind", "Bhopal", "Burhanpur", "Chhatarpur", "Chhindwara", "Damoh", "Datia", "Dewas", "Dhar", "Dindori", "Guna", "Gwalior", "Harda", "Hoshangabad", "Indore", "Jabalpur", "Jhabua", "Katni", "Khandwa", "Khargone", "Mandla", "Mandsaur", "Morena", "Narsinghpur", "Neemuch", "Panna", "Raisen", "Rajgarh", "Ratlam", "Rewa", "Sagar", "Satna", "Sehore", "Seoni", "Shahdol", "Shajapur", "Sheopur", "Shivpuri", "Sidhi", "Singrauli", "Tikamgarh", "Ujjain", "Umaria", "Vidisha"],
    "Maharashtra": ["Ahmednagar", "Akola", "Amravati", "Aurangabad", "Beed", "Bhandara", "Buldhana", "Chandrapur", "Dhule", "Gadchiroli", "Gondia", "Hingoli", "Jalgaon", "Jalna", "Kolhapur", "Latur", "Mumbai City", "Mumbai Suburban", "Nagpur", "Nanded", "Nandurbar", "Nashik", "Osmanabad", "Palghar", "Parbhani", "Pune", "Raigad", "Ratnagiri", "Sangli", "Satara", "Sindhudurg", "Solapur", "Thane", "Wardha", "Washim", "Yavatmal"],
    "Manipur": ["Bishnupur", "Chandel", "Churachandpur", "Imphal East", "Imphal West", "Jiribam", "Kakching", "Kamjong", "Kangpokpi", "Noney", "Pherzawl", "Senapati", "Tamenglong", "Tengnoupal", "Thoubal", "Ukhrul"],
    "Meghalaya": ["East Garo Hills", "East Jaintia Hills", "East Khasi Hills", "North Garo Hills", "Ri-Bhoi", "South Garo Hills", "South West Garo Hills", "South West Khasi Hills", "West Garo Hills", "West Jaintia Hills", "West Khasi Hills"],
    "Mizoram": ["Aizawl", "Champhai", "Hnahthial", "Khawzawl", "Kolasib", "Lawngtlai", "Lunglei", "Mamit", "Saiha", "Saitual", "Serchhip"],
    "Nagaland": ["Dimapur", "Kiphire", "Kohima", "Longleng", "Mokokchung", "Mon", "Peren", "Phek", "Tuensang", "Wokha", "Zunheboto"],
    "Odisha": ["Angul", "Balangir", "Balasore", "Bargarh", "Bhadrak", "Boudh", "Cuttack", "Deogarh", "Dhenkanal", "Gajapati", "Ganjam", "Jagatsinghpur", "Jajpur", "Jharsuguda", "Kalahandi", "Kandhamal", "Kendrapara", "Kendujhar (Keonjhar)", "Khordha", "Koraput", "Malkangiri", "Mayurbhanj", "Nabarangpur", "Nayagarh", "Nuapada", "Puri", "Rayagada", "Sambalpur", "Sonepur", "Sundargarh"],
    "Punjab": ["Amritsar", "Barnala", "Bathinda", "Faridkot", "Fatehgarh Sahib", "Fazilka", "Ferozepur", "Gurdaspur", "Hoshiarpur", "Jalandhar", "Kapurthala", "Ludhiana", "Malerkotla", "Mansa", "Moga", "Muktsar", "Pathankot", "Patiala", "Rupnagar", "Sangrur", "SAS Nagar (Mohali)", "SBS Nagar (Nawanshahr)", "Tarn Taran"],
    "Rajasthan": ["Ajmer", "Alwar", "Banswara", "Baran", "Barmer", "Bharatpur", "Bhilwara", "Bikaner", "Bundi", "Chittorgarh", "Churu", "Dausa", "Dholpur", "Dungarpur", "Hanumangarh", "Jaipur", "Jaisalmer", "Jalore", "Jhalawar", "Jhunjhunu", "Jodhpur", "Karauli", "Kota", "Nagaur", "Pali", "Pratapgarh", "Rajsamand", "Sawai Madhopur", "Sikar", "Sirohi", "Sri Ganganagar", "Tonk", "Udaipur"],
    "Sikkim": ["East Sikkim", "North Sikkim", "South Sikkim", "West Sikkim"],
    "Tamil Nadu": ["Ariyalur", "Chengalpattu", "Chennai", "Coimbatore", "Cuddalore", "Dharmapuri", "Dindigul", "Erode", "Kallakurichi", "Kancheepuram", "Karur", "Krishnagiri", "Madurai", "Mayiladuthurai", "Nagapattinam", "Namakkal", "Nilgiris", "Perambalur", "Pudukkottai", "Ramanathapuram", "Ranipet", "Salem", "Sivaganga", "Tenkasi", "Thanjavur", "Theni", "Thoothukudi (Tuticorin)", "Tiruchirappalli", "Tirunelveli", "Tirupathur", "Tiruppur", "Tiruvallur", "Tiruvannamalai", "Tiruvarur", "Vellore", "Viluppuram", "Virudhunagar"],
    "Telangana": ["Adilabad", "Bhadradri Kothagudem", "Hyderabad", "Jagtial", "Jangaon", "Jayashankar Bhupalapally", "Jogulamba Gadwal", "Kamareddy", "Karimnagar", "Khammam", "Kumuram Bheem Asifabad", "Mahabubabad", "Mahbubnagar", "Mancherial", "Medak", "Medchal-Malkajgiri", "Mulugu", "Nagarkurnool", "Nalgonda", "Narayanpet", "Nirmal", "Nizamabad", "Peddapalli", "Rajanna Sircilla", "Ranga Reddy", "Sangareddy", "Siddipet", "Suryapet", "Vikarabad", "Wanaparthy", "Warangal (Rural)", "Warangal (Urban)", "Yadadri Bhuvanagiri"],
    "Tripura": ["Dhalai", "Gomati", "Khowai", "North Tripura", "Sepahijala", "South Tripura", "Unakoti", "West Tripura"],
    "Uttar Pradesh": ["Agra", "Aligarh", "Ambedkar Nagar", "Amethi", "Amroha", "Auraiya", "Ayodhya (Faizabad)", "Azamgarh", "Baghpat", "Bahraich", "Ballia", "Balrampur", "Banda", "Barabanki", "Bareilly", "Basti", "Bhadohi", "Bijnor", "Budaun", "Bulandshahr", "Chandauli", "Chitrakoot", "Deoria", "Etah", "Etawah", "Farrukhabad", "Fatehpur", "Firozabad", "Gautam Buddha Nagar", "Ghaziabad", "Ghazipur", "Gonda", "Gorakhpur", "Hamirpur", "Hapur", "Hardoi", "Hathras", "Jalaun", "Jaunpur", "Jhansi", "Kannauj", "Kanpur Dehat", "Kanpur Nagar", "Kasganj", "Kaushambi", "Kheri", "Kushinagar", "Lalitpur", "Lucknow", "Maharajganj", "Mahoba", "Mainpuri", "Mathura", "Mau", "Meerut", "Mirzapur", "Moradabad", "Muzaffarnagar", "Pilibhit", "Pratapgarh", "Prayagraj", "Rae Bareli", "Rampur", "Saharanpur", "Sambhal", "Sant Kabir Nagar", "Shahjahanpur", "Shamli", "Shrawasti", "Siddharthnagar", "Sitapur", "Sonbhadra", "Sultanpur", "Unnao", "Varanasi"],
    "Uttarakhand": ["Almora", "Bageshwar", "Chamoli", "Champawat", "Dehradun", "Haridwar", "Nainital", "Pauri Garhwal", "Pithoragarh", "Rudraprayag", "Tehri Garhwal", "Udham Singh Nagar", "Uttarkashi"],
    "West Bengal": ["Alipurduar", "Bankura", "Birbhum", "Cooch Behar", "Dakshin Dinajpur (South Dinajpur)", "Darjeeling", "Hooghly", "Howrah", "Jalpaiguri", "Jhargram", "Kalimpong", "Kolkata", "Malda", "Murshidabad", "Nadia", "North 24 Parganas", "Paschim Bardhaman (West Bardhaman)", "Paschim Medinipur (West Medinipur)", "Purba Bardhaman (East Bardhaman)", "Purba Medinipur (East Medinipur)", "Purulia", "South 24 Parganas", "Uttar Dinajpur (North Dinajpur)"]
}

def creating_districtid():
    counter = sequence_district_collection.find_one_and_update(
        {'_id': 'districtid'},
        {'$inc': {'sequence_value': 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    return counter['sequence_value']

@app.post('/Add District')
async def savedata(statedetail: GetStateDetails, state_name: str = Query(..., enum=list(state_codes.keys()))):
    district = statedetail.district_name
    normalized_district = district.strip().lower()
    normalized_districts = [d.lower() for d in districts_by_state.get(state_name, [])]
    
    if normalized_district not in normalized_districts:
        raise HTTPException(status_code=400, detail=f"District '{district}' does not belong to state '{state_name}'")

    sequence_value = creating_districtid()    
    document = statedetail.dict()
    document["State_name"] = state_name
    document["Status"] = Status.Active.value  # Set status to active by default
    document["District_Id"] = f"DISTID{sequence_value:06d}"  

    insert_result = district_collection.insert_one(document)
    document["_id"] = str(insert_result.inserted_id)
    return document

@app.put('/updating_District')
async def editdata(districtid: str, statedetail: GetStateDetails, state_name: str = Query(..., enum=list(state_codes.keys()))):
    district = statedetail.district_name
    normalized_district = district.strip().lower()
    normalized_districts = [d.lower() for d in districts_by_state.get(state_name, [])]
    
    if normalized_district not in normalized_districts:
        raise HTTPException(status_code=400, detail=f"District '{district}' does not belong to state '{state_name}'")

    update_fields = {
        "State_name": state_name,
        "district_name": statedetail.district_name,
        "creation_date": statedetail.creation_date,
        "District_Code": statedetail.District_Code
    }
    
    document = district_collection.find_one_and_update({"District_Id": districtid},  # Changed State_Id to District_Id
                        {'$set': update_fields}, return_document=ReturnDocument.AFTER)
    if document is not None:
        document["_id"] = str(document["_id"])
    return document

@app.get('/get_Active_Districts')
async def getdata():
    documents = district_collection.find({"Status": Status.Active.value})
    print(documents)  # Log the query result
    result = []
    for doc in documents:
        doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
        result.append(doc)
    return result

@app.get('/get_All_Districts')
async def get_all_districts():
    documents = district_collection.find({})
    print(documents)  # Log the query result
    result = []
    for doc in documents:
        doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
        result.append(doc)
    return result

@app.patch('/update Active_InActive')
async def updating_active_inactive(districtid: str, status: Status = Query(...)):
    document = district_collection.find_one_and_update({"District_Id": districtid},  # Changed State_Id to District_Id
                        {"$set": {"Status": status.value, "updated_date": datetime.utcnow()}}, return_document=ReturnDocument.AFTER)
    if document is not None:
        document["_id"] = str(document["_id"])
    return document





# --------------------------------------------ADMIN CITY MANAGEMENT----------------------------------------------------------------


from pydantic import BaseModel

class CityBase(BaseModel):
    city_name: str
    Pin_Code: int

class CityInDB(CityBase):
    City_Id: str
    State_name: str
    district_name: str
    Status: str = "active"  # Default status is active
    Pin_Code: Optional[int] = None  # Make Pin_Code optional

# Districts by state mapping
districts_by_state = {
    "Andhra Pradesh": ["Anantapur", "Chittoor", "East Godavari", "Guntur", "Krishna", "Kurnool", "Nellore", "Prakasam", "Srikakulam", "Visakhapatnam", "Vizianagaram", "West Godavari", "YSR Kadapa"],
    "Arunachal Pradesh": ["Anjaw", "Changlang", "Dibang Valley", "East Kameng", "East Siang", "Kamle", "Kra Daadi", "Kurung Kumey", "Lepa Rada", "Lohit", "Longding", "Lower Dibang Valley", "Lower Siang", "Lower Subansiri", "Namsai", "Pakke-Kessang", "Papum Pare", "Shi-Yomi", "Siang", "Tawang", "Tirap", "Upper Dibang Valley", "Upper Siang", "Upper Subansiri", "West Kameng", "West Siang"],
    "Assam": ["Baksa", "Barpeta", "Biswanath", "Bongaigaon", "Cachar", "Charaideo", "Chirang", "Darrang", "Dhemaji", "Dhubri", "Dibrugarh", "Dima Hasao", "Goalpara", "Golaghat", "Hailakandi", "Hojai", "Jorhat", "Kamrup", "Kamrup Metropolitan", "Karbi Anglong", "Karimganj", "Kokrajhar", "Lakhimpur", "Majuli", "Morigaon", "Nagaon", "Nalbari", "Sivasagar", "Sonitpur", "South Salmara-Mankachar", "Tinsukia", "Udalguri", "West Karbi Anglong"],
    "Bihar": ["Araria", "Arwal", "Aurangabad", "Banka", "Begusarai", "Bhagalpur", "Bhojpur", "Buxar", "Darbhanga", "East Champaran (Motihari)", "Gaya", "Gopalganj", "Jamui", "Jehanabad", "Kaimur (Bhabua)", "Katihar", "Khagaria", "Kishanganj", "Lakhisarai", "Madhepura", "Madhubani", "Munger", "Muzaffarpur", "Nalanda", "Nawada", "Patna", "Purnia", "Rohtas", "Saharsa", "Samastipur", "Saran", "Sheikhpura", "Sheohar", "Sitamarhi", "Siwan", "Supaul", "Vaishali", "West Champaran"],
    "Chhattisgarh": ["Balod", "Baloda Bazar", "Balrampur", "Bastar", "Bemetara", "Bijapur", "Bilaspur", "Dantewada", "Dhamtari", "Durg", "Gariaband", "Gaurela-Pendra-Marwahi", "Janjgir-Champa", "Jashpur", "Kabirdham (Kawardha)", "Kanker", "Kondagaon", "Korba", "Koriya (Baikunthpur)", "Mahasamund", "Mungeli", "Narayanpur", "Raigarh", "Raipur", "Rajnandgaon", "Sukma", "Surajpur", "Surguja"],
    "Goa": ["North Goa", "South Goa"],
    "Gujarat": ["Ahmedabad", "Amreli", "Anand", "Aravalli", "Banaskantha (Palanpur)", "Bharuch", "Bhavnagar", "Botad", "Chhota Udaipur", "Dahod", "Dang (Ahwa)", "Devbhoomi Dwarka", "Gandhinagar", "Gir Somnath", "Jamnagar", "Junagadh", "Kheda (Nadiad)", "Kutch", "Mahisagar", "Mehsana", "Morbi", "Narmada (Rajpipla)", "Navsari", "Panchmahal (Godhra)", "Patan", "Porbandar", "Rajkot", "Sabarkantha (Himmatnagar)", "Surat", "Surendranagar", "Tapi (Vyara)", "Vadodara", "Valsad"],
    "Haryana": ["Ambala", "Bhiwani", "Charkhi Dadri", "Faridabad", "Fatehabad", "Gurugram", "Hisar", "Jhajjar", "Jind", "Kaithal", "Karnal", "Kurukshetra", "Mahendragarh", "Nuh", "Palwal", "Panchkula", "Panipat", "Rewari", "Rohtak", "Sirsa", "Sonipat", "Yamunanagar"],
    "Himachal Pradesh": ["Bilaspur", "Chamba", "Hamirpur", "Kangra", "Kinnaur", "Kullu", "Lahaul and Spiti", "Mandi", "Shimla", "Sirmaur", "Solan", "Una"],
    "Jharkhand": ["Bokaro", "Chatra", "Deoghar", "Dhanbad", "Dumka", "East Singhbhum", "Garhwa", "Giridih", "Godda", "Gumla", "Hazaribagh", "Jamtara", "Khunti", "Koderma", "Latehar", "Lohardaga", "Pakur", "Palamu", "Ramgarh", "Ranchi", "Sahebganj", "Seraikela Kharsawan", "Simdega", "West Singhbhum"],
    "Karnataka": ["Bagalkot", "Ballari", "Belagavi", "Bengaluru Rural", "Bengaluru Urban", "Bidar", "Chamarajanagar", "Chikkaballapur", "Chikkamagaluru", "Chitradurga", "Dakshina Kannada", "Davanagere", "Dharwad", "Gadag", "Hassan", "Haveri", "Kalaburagi", "Kodagu", "Kolar", "Koppal", "Mandya", "Mysuru", "Raichur", "Ramanagara", "Shivamogga", "Tumakuru", "Udupi", "Uttara Kannada", "Vijayapura", "Yadgir"],
    "Kerala": ["Alappuzha", "Ernakulam", "Idukki", "Kannur", "Kasaragod", "Kollam", "Kottayam", "Kozhikode", "Malappuram", "Palakkad", "Pathanamthitta", "Thiruvananthapuram", "Thrissur", "Wayanad"],
    "Madhya Pradesh": ["Agar Malwa", "Alirajpur", "Anuppur", "Ashoknagar", "Balaghat", "Barwani", "Betul", "Bhind", "Bhopal", "Burhanpur", "Chhatarpur", "Chhindwara", "Damoh", "Datia", "Dewas", "Dhar", "Dindori", "Guna", "Gwalior", "Harda", "Hoshangabad", "Indore", "Jabalpur", "Jhabua", "Katni", "Khandwa", "Khargone", "Mandla", "Mandsaur", "Morena", "Narsinghpur", "Neemuch", "Panna", "Raisen", "Rajgarh", "Ratlam", "Rewa", "Sagar", "Satna", "Sehore", "Seoni", "Shahdol", "Shajapur", "Sheopur", "Shivpuri", "Sidhi", "Singrauli", "Tikamgarh", "Ujjain", "Umaria", "Vidisha"],
    "Maharashtra": ["Ahmednagar", "Akola", "Amravati", "Aurangabad", "Beed", "Bhandara", "Buldhana", "Chandrapur", "Dhule", "Gadchiroli", "Gondia", "Hingoli", "Jalgaon", "Jalna", "Kolhapur", "Latur", "Mumbai City", "Mumbai Suburban", "Nagpur", "Nanded", "Nandurbar", "Nashik", "Osmanabad", "Palghar", "Parbhani", "Pune", "Raigad", "Ratnagiri", "Sangli", "Satara", "Sindhudurg", "Solapur", "Thane", "Wardha", "Washim", "Yavatmal"],
    "Manipur": ["Bishnupur", "Chandel", "Churachandpur", "Imphal East", "Imphal West", "Jiribam", "Kakching", "Kamjong", "Kangpokpi", "Noney", "Pherzawl", "Senapati", "Tamenglong", "Tengnoupal", "Thoubal", "Ukhrul"],
    "Meghalaya": ["East Garo Hills", "East Jaintia Hills", "East Khasi Hills", "North Garo Hills", "Ri-Bhoi", "South Garo Hills", "South West Garo Hills", "South West Khasi Hills", "West Garo Hills", "West Jaintia Hills", "West Khasi Hills"],
    "Mizoram": ["Aizawl", "Champhai", "Hnahthial", "Khawzawl", "Kolasib", "Lawngtlai", "Lunglei", "Mamit", "Saiha", "Saitual", "Serchhip"],
    "Nagaland": ["Dimapur", "Kiphire", "Kohima", "Longleng", "Mokokchung", "Mon", "Peren", "Phek", "Tuensang", "Wokha", "Zunheboto"],
    "Odisha": ["Angul", "Balangir", "Balasore", "Bargarh", "Bhadrak", "Boudh", "Cuttack", "Deogarh", "Dhenkanal", "Gajapati", "Ganjam", "Jagatsinghpur", "Jajpur", "Jharsuguda", "Kalahandi", "Kandhamal", "Kendrapara", "Kendujhar (Keonjhar)", "Khordha", "Koraput", "Malkangiri", "Mayurbhanj", "Nabarangpur", "Nayagarh", "Nuapada", "Puri", "Rayagada", "Sambalpur", "Sonepur", "Sundargarh"],
    "Punjab": ["Amritsar", "Barnala", "Bathinda", "Faridkot", "Fatehgarh Sahib", "Fazilka", "Ferozepur", "Gurdaspur", "Hoshiarpur", "Jalandhar", "Kapurthala", "Ludhiana", "Malerkotla", "Mansa", "Moga", "Muktsar", "Pathankot", "Patiala", "Rupnagar", "Sangrur", "SAS Nagar (Mohali)", "SBS Nagar (Nawanshahr)", "Tarn Taran"],
    "Rajasthan": ["Ajmer", "Alwar", "Banswara", "Baran", "Barmer", "Bharatpur", "Bhilwara", "Bikaner", "Bundi", "Chittorgarh", "Churu", "Dausa", "Dholpur", "Dungarpur", "Hanumangarh", "Jaipur", "Jaisalmer", "Jalore", "Jhalawar", "Jhunjhunu", "Jodhpur", "Karauli", "Kota", "Nagaur", "Pali", "Pratapgarh", "Rajsamand", "Sawai Madhopur", "Sikar", "Sirohi", "Sri Ganganagar", "Tonk", "Udaipur"],
    "Sikkim": ["East Sikkim", "North Sikkim", "South Sikkim", "West Sikkim"],
    "Tamil Nadu": ["Ariyalur", "Chengalpattu", "Chennai", "Coimbatore", "Cuddalore", "Dharmapuri", "Dindigul", "Erode", "Kallakurichi", "Kancheepuram", "Karur", "Krishnagiri", "Madurai", "Mayiladuthurai", "Nagapattinam", "Namakkal", "Nilgiris", "Perambalur", "Pudukkottai", "Ramanathapuram", "Ranipet", "Salem", "Sivaganga", "Tenkasi", "Thanjavur", "Theni", "Thoothukudi (Tuticorin)", "Tiruchirappalli", "Tirunelveli", "Tirupathur", "Tiruppur", "Tiruvallur", "Tiruvannamalai", "Tiruvarur", "Vellore", "Viluppuram", "Virudhunagar"],
    "Telangana": ["Adilabad", "Bhadradri Kothagudem", "Hyderabad", "Jagtial", "Jangaon", "Jayashankar Bhupalapally", "Jogulamba Gadwal", "Kamareddy", "Karimnagar", "Khammam", "Kumuram Bheem Asifabad", "Mahabubabad", "Mahbubnagar", "Mancherial", "Medak", "Medchal-Malkajgiri", "Mulugu", "Nagarkurnool", "Nalgonda", "Narayanpet", "Nirmal", "Nizamabad", "Peddapalli", "Rajanna Sircilla", "Ranga Reddy", "Sangareddy", "Siddipet", "Suryapet", "Vikarabad", "Wanaparthy", "Warangal (Rural)", "Warangal (Urban)", "Yadadri Bhuvanagiri"],
    "Tripura": ["Dhalai", "Gomati", "Khowai", "North Tripura", "Sepahijala", "South Tripura", "Unakoti", "West Tripura"],
    "Uttar Pradesh": ["Agra", "Aligarh", "Ambedkar Nagar", "Amethi", "Amroha", "Auraiya", "Ayodhya (Faizabad)", "Azamgarh", "Baghpat", "Bahraich", "Ballia", "Balrampur", "Banda", "Barabanki", "Bareilly", "Basti", "Bhadohi", "Bijnor", "Budaun", "Bulandshahr", "Chandauli", "Chitrakoot", "Deoria", "Etah", "Etawah", "Farrukhabad", "Fatehpur", "Firozabad", "Gautam Buddha Nagar", "Ghaziabad", "Ghazipur", "Gonda", "Gorakhpur", "Hamirpur", "Hapur", "Hardoi", "Hathras", "Jalaun", "Jaunpur", "Jhansi", "Kannauj", "Kanpur Dehat", "Kanpur Nagar", "Kasganj", "Kaushambi", "Kheri", "Kushinagar", "Lalitpur", "Lucknow", "Maharajganj", "Mahoba", "Mainpuri", "Mathura", "Mau", "Meerut", "Mirzapur", "Moradabad", "Muzaffarnagar", "Pilibhit", "Pratapgarh", "Prayagraj", "Rae Bareli", "Rampur", "Saharanpur", "Sambhal", "Sant Kabir Nagar", "Shahjahanpur", "Shamli", "Shrawasti", "Siddharthnagar", "Sitapur", "Sonbhadra", "Sultanpur", "Unnao", "Varanasi"],
    "Uttarakhand": ["Almora", "Bageshwar", "Chamoli", "Champawat", "Dehradun", "Haridwar", "Nainital", "Pauri Garhwal", "Pithoragarh", "Rudraprayag", "Tehri Garhwal", "Udham Singh Nagar", "Uttarkashi"],
    "West Bengal": ["Alipurduar", "Bankura", "Birbhum", "Cooch Behar", "Dakshin Dinajpur (South Dinajpur)", "Darjeeling", "Hooghly", "Howrah", "Jalpaiguri", "Jhargram", "Kalimpong", "Kolkata", "Malda", "Murshidabad", "Nadia", "North 24 Parganas", "Paschim Bardhaman (West Bardhaman)", "Paschim Medinipur (West Medinipur)", "Purba Bardhaman (East Bardhaman)", "Purba Medinipur (East Medinipur)", "Purulia", "South 24 Parganas", "Uttar Dinajpur (North Dinajpur)"]
}

# Function to get the next sequence value for city ID
def get_next_cityid() -> int:
    sequence_document = sequence_city_collection.find_one_and_update(
        {"_id": "Cityid"},
        {"$inc": {"sequence_value": 1}},
        return_document=ReturnDocument.AFTER,
        upsert=True
    )
    return sequence_document["sequence_value"]

@app.post('/Cities', response_model=CityInDB)
async def create_city(
    city_detail: CityBase,
    state_name: str = Query(..., enum=["Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
                                       "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand", "Karnataka",
                                       "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya", "Mizoram",
                                       "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana",
                                       "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal"]),
    district: str = Query(...),
):
    normalized_district = district.strip().lower()
    normalized_districts = [d.lower() for d in districts_by_state.get(state_name, [])]

    if normalized_district not in normalized_districts:
        raise HTTPException(status_code=400, detail=f"District '{district}' does not belong to state '{state_name}'")

    sequence_value = get_next_cityid()
    city_id = f"CID{sequence_value:06d}"
    
    document = city_detail.dict()
    document.update({
        "City_Id": city_id,
        "State_name": state_name,
        "district_name": district,
        "Status": "active",  # Default status is active
        "Creation_Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Auto-generated creation date
    })
    
    city_collection.insert_one(document)
    document["_id"] = str(document["_id"])  # Convert ObjectId to string
    return CityInDB(**document)

@app.put('/Cities/{city_id}', response_model=CityInDB)
async def update_city(
    city_id: str,
    city_data: CityBase,
    state_name: str = Query(..., enum=["Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
                                       "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand", "Karnataka",
                                       "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya", "Mizoram",
                                       "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana",
                                       "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal"]),
    district: str = Query(...)
):
    normalized_district = district.strip().lower()
    normalized_districts = [d.lower() for d in districts_by_state.get(state_name, [])]

    if normalized_district not in normalized_districts:
        raise HTTPException(status_code=400, detail=f"District '{district}' does not belong to state '{state_name}'")

    update_fields = city_data.dict()
    update_fields.update({
        "State_name": state_name,
        "district_name": district,
        "Updated_Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Auto-generated updated date
    })

    document = city_collection.find_one_and_update(
        {"City_Id": city_id},
        {"$set": update_fields},
        return_document=ReturnDocument.AFTER
    )

    if document:
        document["_id"] = str(document["_id"])  # Convert ObjectId to string
        if "Creation_Date" not in document:
            document["Creation_Date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Add creation date if not exists
        return CityInDB(**document)
    else:
        raise HTTPException(status_code=404, detail="City not found")
    

@app.get('/Cities/active', response_model=List[CityInDB])
async def get_active_cities():
    documents = city_collection.find({"Status": "active"})
    result = []
    for doc in documents:
        doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
        # Add Updated_Date if not exists
        if "Updated_Date" not in doc:
            doc["Updated_Date"] = ""
        city_doc = {k: v for k, v in doc.items()}
        result.append(CityInDB(**city_doc))
    return result

@app.get('/Cities/all', response_model=List[CityInDB])
async def get_all_cities():
    documents = city_collection.find({})
    result = []
    for doc in documents:
        doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
        # Add Updated_Date if not exists
        if "Updated_Date" not in doc:
            doc["Updated_Date"] = ""
        city_doc = {k: v for k, v in doc.items()}
        result.append(CityInDB(**city_doc))
    return result

class StatusEnum(str, Enum):
    active = "active"
    inactive = "inactive"

@app.patch('/Cities/{city_id}/status', response_model=CityInDB)
async def update_city_status(city_id: str, status: StatusEnum = Query(..., enum=[StatusEnum.active, StatusEnum.inactive])):
    document = city_collection.find_one_and_update(
        {"City_Id": city_id},
        {"$set": {"Status": status}},
        return_document=ReturnDocument.AFTER
    )

    if document:
        document["_id"] = str(document["_id"])  # Convert ObjectId to string
        return CityInDB(**document)
    else:
        raise HTTPException(status_code=404, detail="City not found")



# #---------------------------------------------------subsequent_admin_management---------------------------------------------------------

# class get_admin_user_data(BaseModel):
#    full_name : str
#    email : EmailStr
#    mobile : int
#    Date_of_birth : datetime
#    address : str
#    aadhar_number : int
#    pan_number : str
#    Joined_date : Optional[datetime] = datetime.now().isoformat()
# #    password : Optional[str] = None

#    @validator('mobile')
#    def validate_mobile(cls, value):
#         if len(str(value)) != 10:
#             raise ValueError('Mobile number must be 10 digits.')
#         return value
    
#    @validator('aadhar_number')
#    def validate_aadhar(cls, value):
#         if len(str(value)) != 12:
#             raise ValueError('Aadhar number must be 12 digits.')
#         return value
    
#    @validator('pan_number')
#    def validate_pan(cls, value):
#         pan_pattern = r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$'
#         if not re.match(pan_pattern, value):
#             raise ValueError('Invalid PAN number format.')
#         return value


# def generate_random_password(length=8):
#     # I am Generating a random password here.....
#     alphabet = string.ascii_letters + string.digits 
#     password = ''.join(secrets.choice(alphabet) for i in range(length))
#     return password

# def creating_userid():
#     counter = client.subsequent_admin.subsequent_collection.find_one_and_update(
#         {'_id': 'user_id'},
#         {'$inc': {'sequence_value': 1}},
#         upsert=True,
#         return_document=True
#     )
#     return counter['sequence_value']

# def send_email(recipient_email: str, subject: str, body: str):
#     smtp_server = "smtp.gmail.com"
#     smtp_port = 587
#     sender_email = "snipe.upl@gmail.com"
#     sender_password = "ljzz hsqx qvwc fbdr"
    
#     # Creating the email here
#     msg = MIMEText(body)
#     msg["Subject"] = subject
#     msg["From"] = sender_email
#     msg["To"] = recipient_email
#     # Sending the email here
#     with smtplib.SMTP(smtp_server, smtp_port) as server:
#         server.starttls()
#         server.login(sender_email, sender_password)
#         server.sendmail(sender_email, recipient_email, msg.as_string())

# @app.post("/create_subsequent_admin")
# def post_data(admin_detail: get_admin_user_data,background_tasks:BackgroundTasks, gender : str = Query(...,enum=["Male","Female"]),
#             state_name: str = Query(..., enum=["Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
#                                             "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand","Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur","Meghalaya", "Mizoram", "Nagaland",
#                                             "Odisha", "Punjab","Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura","Uttar Pradesh", "Uttarakhand", "West Bengal"]), 
#             city_name: str = Query(..., enum = ["Visakhapatnam", "Vijayawada","Itanagar", "Tawang","Guwahati", "Dibrugarh","Patna","Gaya","Raipur", "Bhilai","Panaji", "Margao","Ahmedabad", "Surat","Gurugram", "Faridabad", 
#                                             "Shimla", "Manali","Ranchi", "Jamshedpur","Bengaluru", "Mysuru","Thiruvananthapuram", "Kochi","Indore", "Bhopal","Mumbai", "Pune", "Imphal", "Churachandpur","Shillong", "Tura", 
#                                             "Aizawl", "Lunglei","Kohima", "Dimapur","Bhubaneswar", "Cuttack","Ludhiana", "Amritsar","Jaipur", "Udaipur","Gangtok", "Pelling","Chennai", "Coimbatore","Hyderabad", "Warangal", 
#                                             "Agartala", "Udaipur","Lucknow", "Varanasi","Dehradun", "Haridwar","Kolkata", "Darjeeling"]),
#             status: str = Query(..., enum=["Active"]), role: str = Query(..., enum = ["Admin","Organisation", "student"])):
    
#     generate_password = generate_random_password()
#     sequence_value = creating_userid()
#     document = admin_detail.dict()
#     document["gender"] = gender
#     document["state"] = state_name
#     document["city"] = city_name
#     document["role"] = role
#     document["department"] = role
#     document["password"] = generate_password
#     document["status"] = status
#     document["user_id"] = f"UID{sequence_value:06d}"
    
#     client.subsequent_admin.subsequent_collection.insert_one(document)

#     email_subject = "Your New Account Information"
#     email_body = (f"Dear {admin_detail.full_name},\n\n"
#                   f"Your account has been created. Please use the following credentials to log in:\n"
#                   f"Email: {admin_detail.email}\n"
#                   f"Password: {generate_password}\n"
#                   f"After logging in, please change your password immediately.\n\n"
#                   f"Best regards,\nAI DISHA")
    
#     # Below line will send mail automatically when post operation is applied
#     background_tasks.add_task(send_email, admin_detail.email, email_subject, email_body)

#     return {"status": "success", "user_id": document["user_id"], "generated_password": generate_password}



# @app.put("/create_subsequent_admin")
# def edit_data(user_id: str, admin_detail: get_admin_user_data, gender : str = Query(...,enum=["Male","Female"]),
#             state_name: str = Query(..., enum=["Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
#                                             "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand","Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur","Meghalaya", "Mizoram", "Nagaland",
#                                             "Odisha", "Punjab","Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura","Uttar Pradesh", "Uttarakhand", "West Bengal"]), 
#             city_name: str = Query(..., enum = ["Visakhapatnam", "Vijayawada","Itanagar", "Tawang","Guwahati", "Dibrugarh","Patna","Gaya","Raipur", "Bhilai","Panaji", "Margao","Ahmedabad", "Surat","Gurugram", "Faridabad", 
#                                             "Shimla", "Manali","Ranchi", "Jamshedpur","Bengaluru", "Mysuru","Thiruvananthapuram", "Kochi","Indore", "Bhopal","Mumbai", "Pune", "Imphal", "Churachandpur","Shillong", "Tura", 
#                                             "Aizawl", "Lunglei","Kohima", "Dimapur","Bhubaneswar", "Cuttack","Ludhiana", "Amritsar","Jaipur", "Udaipur","Gangtok", "Pelling","Chennai", "Coimbatore","Hyderabad", "Warangal", 
#                                             "Agartala", "Udaipur","Lucknow", "Varanasi","Dehradun", "Haridwar","Kolkata", "Darjeeling"]),
#              role: str = Query(..., enum = ["Admin","Organisation", "student"])): 
    
#     Full_name = admin_detail.full_name
#     Email = admin_detail.email
#     Mobile = admin_detail.mobile 
#     DOB = admin_detail.Date_of_birth 
#     Address = admin_detail.address
#     Anumber = admin_detail.aadhar_number 
#     Pnumber = admin_detail.pan_number 
#     # Password = admin_detail.password 
#     update_details = {
#             "full_name" : Full_name,
#             "email" : Email,
#             "mobile" : Mobile,
#             "address" : Address,
#             "Date_of_birth":DOB,
#             "aadhar_number" : Anumber,
#             "pan_number" : Pnumber,
#             "gender" : gender,
#             "state" : state_name,
#             "city" : city_name,
#             "role": role,
#             "department": role,
#             # "password": Password,
#     }
    
#     document = client.subsequent_admin.subsequent_collection.find_one_and_update({"user_id":user_id},
#                         {"$set": update_details},return_document=True)
#     document["_id"] = str(document["_id"])
#     return document



    
# @app.patch("/update_status")
# def update_admin_user_status(user_id: str, status: str = Query(..., enum=["Active","InActive"]),):
#     document = client.subsequent_admin.subsequent_collection.find_one_and_update({"user_id":user_id},
#                         {"$set": {"status":status}},return_document=True)
#     document["_id"] = str(document["_id"])
#     return document

# @app.get("/get_active_user")
# def get_All_active_admin():
#     document = client.subsequent_admin.subsequent_collection.find({"status":"Active"})
#     result = []
#     for doc in document:
#         doc["_id"] = str(doc["_id"])
#         result.append(doc)
#     return result

# @app.get("/get_all_users")
# def get_all_admin():
#     documents = client.subsequent_admin.subsequent_collection.find({})
#     result = []
#     for doc in documents:
#         doc["_id"] = str(doc["_id"])
#         result.append(doc)
#     return result




#-------------------------------------------------ROLE MANAGEMENT----------------------------------------------------------------------

# MongoDB connection details
# MONGO_DETAILS = "mongodb+srv://somnath:somnath@cluster0.izhugny.mongodb.net/"
# client = MongoClient(MONGO_DETAILS)
# db1 = client.Role_Management
# role_collection = db1.role
# role_sequence_collection = db1.role_sequence

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic model for role creation
class RoleModel(BaseModel):
    Role_Name: str
    Org_ID: str
    isActive: str = "Active"

    @validator('Role_Name')
    def validate_role_name(cls, value):
        if value.isdigit():
            raise ValueError('Role name cannot be only numeric.')
        if not value.strip():
            raise ValueError('Role name cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Role name must contain at least one alphanumeric character.')
        return value

    @validator('Org_ID')
    def validate_org_id(cls, value):
        if not value.strip():
            raise ValueError('Org ID cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Org ID must contain at least one alphanumeric character.')
        return value

# Function to generate a unique Role_ID with the prefix "rid-"
def generate_role_id(org_id: str):
    max_role_id = role_sequence_collection.find_one({"Org_ID": org_id}, sort=[("Role_ID", -1)])
    if max_role_id:
        max_id_numeric = int(max_role_id["Role_ID"].split('-')[1])
        next_id_numeric = max_id_numeric + 1
    else:
        next_id_numeric = 1
    next_id_formatted = f"{next_id_numeric:06}"
    role_id = f"rid-{next_id_formatted}"
    return role_id

# Define route to insert a record into the MongoDB collection
@app.post("/Org-Role-Create/")
def insert_record(role: RoleModel):
    # Normalize role name for uniqueness check and consistent storage
    normalized_name = role.Role_Name.strip().lower()
    
    # Check if a role with the same normalized name exists in the same organization
    existing_role = role_collection.find_one({"Role_Name": normalized_name, "Org_ID": role.Org_ID})
    if existing_role:
        raise HTTPException(status_code=400, detail="Role name already exists for this organization")

    # Generate a new role ID
    current_max_id = generate_role_id(role.Org_ID)
    
    # Create the record with the normalized name
    record_dict = {
        "Role_ID": current_max_id,
        "Org_ID": role.Org_ID,
        "Role_Name": normalized_name,  # Store the normalized name
        "Creation_Date": datetime.now(),
        "isActive": role.isActive
    }
    
    # Insert into the collections
    role_sequence_collection.insert_one({"Org_ID": role.Org_ID, "Role_ID": current_max_id})
    role_collection.insert_one(record_dict)
    
    return {"message": "Record inserted successfully", "Role_ID": current_max_id, "Role_Name": role.Role_Name, "Org_ID": role.Org_ID, "isActive": role.isActive}

# Define route to update a record in the MongoDB collection
@app.put("/Org-Role-Edit/")
def update_record(Org_ID: str, Role_ID: str, Role_Name: str): 
    normalized_name = Role_Name.strip().lower()
    existing_role = role_collection.find_one({"Role_Name": normalized_name, "Org_ID": Org_ID, "Role_ID": {"$ne": Role_ID}})
    if existing_role:
        raise HTTPException(status_code=400, detail="Role name already exists for this organization")
    myquery = {'Org_ID': Org_ID, 'Role_ID': Role_ID}
    newvalues = {
        '$set': {
            "Role_Name": Role_Name, 
            "Last_Update_Date": datetime.now()
        }
    }
    result = role_collection.update_one(myquery, newvalues)
    if result.modified_count == 1:
        return {"message": "Record updated successfully", "Role_Name": Role_Name, "Role_ID": Role_ID, 'Org_ID': Org_ID, "Last_Update_Date": datetime.now()}
    else:
        raise HTTPException(status_code=404, detail="Record not found")

# Define route to update the status of a record based on Org_ID and Role_ID
@app.put("/Org-Role-status/")
def update_status(Org_ID: str, Role_ID: str, new_status: str):
    query = {"Org_ID": Org_ID, "Role_ID": Role_ID}
    record = role_collection.find_one(query)
    if record:
        role_collection.update_one(query, {"$set": {"isActive": new_status}})
        return {"Org_ID": Org_ID, "Role_ID": Role_ID, "isActive": new_status}
    else:
        raise HTTPException(status_code=404, detail="Record not found")

# Define route to fetch active records based on Org_ID
@app.get("/Org-Role-Show/")
def get_active_records_by_org_id(Org_ID: str):
    query = {"Org_ID": Org_ID, "isActive": "Active"}
    records = list(role_collection.find(query))
    if records:
        formatted_records = []
        for record in records:
            role_id = record.get("Role_ID", "Unknown")
            role_name = record.get("Role_Name", "Unknown")
            creation_date = record.get("Creation_Date", "Unknown")
            status = record.get("isActive", "Unknown")
            formatted_record = {
                "Org_ID": Org_ID,
                "Role_ID": role_id,
                "Role_Name": role_name,
                "Creation_Date": creation_date,
                "Status": status
            }
            formatted_records.append(formatted_record)
        response_data = {
            "message": f"All active records for Org_ID {Org_ID} retrieved successfully",
            "active_records": formatted_records
        }
        return response_data
    else:
        raise HTTPException(status_code=404, detail=f"No active records found for Org_ID {Org_ID}")


# Define route to fetch all records
@app.get("/Org-Role-Show/all")
def get_all_records():
    query = {}
    records = list(role_collection.find(query))
    if records:
        formatted_records = []
        for record in records:
            role_id = record.get("Role_ID", "Unknown")
            role_name = record.get("Role_Name", "Unknown")
            creation_date = record.get("Creation_Date", "Unknown")
            status = record.get("isActive", "Unknown")
            org_id = record.get("Org_ID", "Unknown")
            formatted_record = {
                "Org_ID": org_id,
                "Role_ID": role_id,
                "Role_Name": role_name,
                "Creation_Date": creation_date,
                "Status": status
            }
            formatted_records.append(formatted_record)
        response_data = {
            "message": "All records retrieved successfully",
            "records": formatted_records
        }
        return response_data
    else:
        raise HTTPException(status_code=404, detail="No records found")




#------------------------------------------------USER MANAGEMENT-----------------------------------------------------------

# db1 = client.Role_Management
# mycol1 = db1.users
# user_sequence_collection = db1.user_sequence

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Validation function
def validate_non_numeric_blank_special(value: str):
    if value.isdigit() or not value.strip() or not re.search(r'[a-zA-Z0-9]', value):
        raise ValueError('Input must contain at least one alphanumeric character and should not be only numeric, blank spaces, or special characters.')
    return value

# Pydantic model for user creation
class UserCreate(BaseModel):
    organisation_id: str
    name: str
    gender: str
    dob: str
    email: EmailStr
    address: str
    aadhar: str
    pan: str
    mobile: str
    city: str
    state: str
    department: str
    role: str
    password: str

    @validator('name', 'gender', 'email', 'address', 'city', 'state', 'department', 'role')
    def validate_fields(cls, value):
        return validate_non_numeric_blank_special(value)
    

# Pydantic model for user update
class UserUpdate(BaseModel):
    organisation_id: str
    uid: str
    name: str
    gender: str
    dob: str
    email: EmailStr
    address: str
    aadhar: str
    pan: str
    mobile: str
    city: str
    state: str
    department: str
    role: str
    password: str

    @validator('name', 'gender', 'email', 'address', 'city', 'state', 'department', 'role')
    def validate_fields(cls, value):
        return validate_non_numeric_blank_special(value)

def find_users_count(org_id):
    cnt = mycol1.count_documents({"organisation_id": org_id})
    return cnt

def create_uid(str_org, n):
    user_num = n + 1
    print(user_num)
    str1 = ""
    if user_num < 10:
        str1 = f'00000{user_num}'
    elif 10 <= user_num < 100:
        str1 = f'0000{user_num}'
    elif 100 <= user_num < 1000:
        str1 = f'000{user_num}'
    elif 1000 <= user_num < 10000:
        str1 = f'00{user_num}'
    elif 10000 <= user_num < 100000:
        str1 = f'0{user_num}'
    else:
        str1 = f'{user_num}'
    uid_str = "U-" + str_org + "-" + str1
    return uid_str

from bson import ObjectId

def convert_objectid_to_str(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    return obj


# --------------/users_get_by_organisation------------
@app.get("/org-all_users/{org_id}")
def get_all_users(org_id: str):
    query = {"organisation_id": org_id, "status": "active"}
    result = mycol1.find(query)
    if result:
        row_data = []
        for document in result:
            document = convert_objectid_to_str(document)  # Convert ObjectId to string
            row_data.append({
                "uid": document["uid"],
                "name": document["name"],
                "email": document["email"],
                "mobile": document["mobile"],
                "Aadhar": document["aadhar_no"],
                "PAN": document["PAN"],
                "gender": document["gender"],
                "dob": document["dob"],
                "address": document["address"],
                "city": document["city"],
                "state": document["state"],
                "department": document["department"],
                "role": document["role"],
                "joining_date": document["joining_date"]
            })
        return row_data
    else:
        raise HTTPException(status_code=404, detail="Candidate not found")
    
# --------------/users_get_all------------
@app.get("/all_users")
def get_all_users():
    query = {}
    result = mycol1.find(query)
    if result:
        row_data = []
        for document in result:
            document = convert_objectid_to_str(document)  # Convert ObjectId to string
            row_data.append({
                "uid": document["uid"],
                "name": document["name"],
                "email": document["email"],
                "mobile": document["mobile"],
                "Aadhar": document["aadhar_no"],
                "PAN": document["PAN"],
                "gender": document["gender"],
                "dob": document["dob"],
                "address": document["address"],
                "city": document["city"],
                "state": document["state"],
                "department": document["department"],
                "role": document["role"],
                "joining_date": document["joining_date"]
            })
        return row_data
    else:
        raise HTTPException(status_code=404, detail="No records found")

# ----------- /user_post_new_user -----------------
@app.post('/org-create_user')
def create_data(user: UserCreate):
    today = datetime.utcnow()
    user_count = find_users_count(user.organisation_id)

    # Increment UID based on the maximum UID value from the user_sequence collection
    max_uid_record = user_sequence_collection.find_one({"organisation_id": user.organisation_id}, sort=[("uid", -1)])
    if max_uid_record:
        max_uid = max_uid_record["uid"]
        max_user_num = int(max_uid.split("-")[-1])
    else:
        max_user_num = 0

    uid = create_uid(user.organisation_id, max_user_num)

    query1 = {"email": user.email}
    query2 = {"mobile": user.mobile}

    if mycol1.find_one(query1) is None and mycol1.find_one(query2) is None:
        # Insert user record into the user collection
        doc = {
            "organisation_id": user.organisation_id,
            "uid": uid,
            "name": user.name,
            "gender": user.gender,
            "dob": user.dob,
            "email": user.email,
            "mobile": user.mobile,
            "address": user.address,
            "aadhar_no": user.aadhar,
            "PAN": user.pan,
            "city": user.city,
            "state": user.state,
            "department": user.department,
            "role": user.role,
            "password": user.password,
            "joining_date": today,
            "status": "active",
            "last_update": datetime.now(),
        }
        inserted_id = mycol1.insert_one(doc).inserted_id

        # Update the user_sequence collection with the new UID
        user_sequence_collection.insert_one({"organisation_id": user.organisation_id, "uid": uid})

        # Retrieve the inserted document and convert ObjectId to string
        inserted_doc = mycol1.find_one({"_id": inserted_id})
        inserted_doc = convert_objectid_to_str(inserted_doc)

        return {"message": "User created successfully", "user": inserted_doc}
    else:
        raise HTTPException(status_code=409, detail="Record already exists!")


# -------/user_update -----------
@app.put('/org-update_user')
def update_data(user: UserUpdate):
    user_record = mycol1.find_one({"organisation_id": user.organisation_id, "uid": user.uid, "status": "active"})
    if user_record:  
        updated_doc = {
            "name": user.name,
            "dob": user.dob,
            "gender": user.gender,
            "email": user.email,
            "mobile": user.mobile,
            "aadhar_no": user.aadhar,
            "PAN": user.pan,
            "city": user.city,
            "state": user.state,
            "department": user.department,
            "password": user.password,
            "role": user.role,
            "last_update": datetime.now()
        }
        mycol1.update_one({"uid": user.uid}, {"$set": updated_doc})
        return {"message": f'User record updated successfully: {user.uid}'}
    else:
        raise HTTPException(status_code=404, detail=f'Record does not exist - UID {user.uid}')


# deactivate user
# --------/user_deactivate
@app.patch('/org-deactivate_user/{uid}')
def deactivate(uid: str):
    res = mycol1.find_one({"uid": uid})
    if res:
        new_status = "inactive" if res["status"] == "active" else "active"
        mycol1.update_one({"uid": uid}, {"$set": {"status": new_status, "last_update": datetime.now()}})
        return {"message": f'User record status updated to {new_status} successfully: {uid}'}
    else:
        raise HTTPException(status_code=404, detail=f'Record does not exist - UID {uid}')

    
#---------------------------------------DEPART MANAGEMENT-------------------------------------------------------

# db1 = client.Role_Management
# mycol2 = db1.departments
# dept_sequence_collection = db1.dept_sequence


class Status(Enum):
    Active = "Active"
    Inactive = "Inactive"

# Function to validate non-numeric, non-blank, and non-special character strings
def validate_non_numeric_blank_special(value: str):
    if value.isdigit() or not value.strip() or not re.search(r'[a-zA-Z0-9]', value):
        raise ValueError('Input must contain at least one alphanumeric character and should not be only numeric, blank spaces, or special characters.')
    return value

# Function to get the next department_id for a given organisation_id
def get_next_department_id(organisation_id):
    sequence = dept_sequence_collection.find_one({"organisation_id": str(organisation_id)})
    if sequence:
        next_department_id = sequence["department_id"] + 1
    else:
        next_department_id = 1  # Start from 1 if no sequence exists
    return next_department_id

# Route to insert a department
@app.post('/org-insert-department')
def create_department(organisation_id: str, department_name: str):
    try:
        validate_non_numeric_blank_special(department_name)  # Validate department_name
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Check if department_name is unique within the same organisation_id
    existing_department = mycol2.find_one({"organisation_id": organisation_id, "department_name": department_name})
    if existing_department:
        raise HTTPException(status_code=409, detail="Department name already exists in this organisation")

    next_department_id = get_next_department_id(organisation_id)
    today = datetime.now()
    status = Status.Active.value  # Get the value of the enum
    department = {
        "organisation_id": organisation_id,
        "department_id": str(next_department_id),
        "department_name": department_name,
        "creation_date": today,
        "update_date": today,
        "status": status  # Store the value of the enum as a string
    }
    mycol2.insert_one(department)
    
    # Update dept_sequence with the new maximum department_id
    dept_sequence_collection.update_one(
        {"organisation_id": organisation_id},
        {"$set": {"department_id": next_department_id}},
        upsert=True  # Insert if not exists
    )
    
    return {"message": "Department created successfully"}


# Route to edit a department
@app.put('/org-edit-department/{organisation_id}/{department_id}')
def edit_department(organisation_id: str, department_id: str, department_name: str):
    department = mycol2.find_one({"organisation_id": str(organisation_id), "department_id": str(department_id)})
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")
    
    # Validate department_name
    try:
        validate_non_numeric_blank_special(department_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Ensure the new department_name is not already present in the same organisation
    existing_department = mycol2.find_one({"organisation_id": str(organisation_id), "department_name": department_name})
    if existing_department and existing_department["department_id"] != department_id:
        raise HTTPException(status_code=409, detail="Department name already exists in this organisation")
    
    previous_department = department.copy()
    today = datetime.now()
    result = mycol2.update_one(
        {"organisation_id": str(organisation_id), "department_id": str(department_id)},
        {"$set": {"department_name": department_name, "update_date": today}}
    )
    if result.modified_count == 1:
        # Convert ObjectId to string for JSON serialization
        previous_department['_id'] = str(previous_department['_id'])
        return {"message": "Department updated successfully", "previous_department": previous_department}
    else:
        return {"message": "Department not updated"}

# Route to update department status
@app.put('/org-update-department-status/{organisation_id}/{department_id}')
def update_department_status(organisation_id: str, department_id: str, status: Status):
    department = mycol2.find_one({"organisation_id": str(organisation_id), "department_id": str(department_id)})
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")
    previous_department = department.copy()
    previous_department['_id'] = str(previous_department['_id'])  # Convert ObjectId to string
    today = datetime.now()
    result = mycol2.update_one(
        {"organisation_id": str(organisation_id), "department_id": str(department_id)},
        {"$set": {"status": status.value, "update_date": today}}
    )
    if result.modified_count == 1:
        return {"message": f"Department status updated to {status.value}", "previous_department": previous_department}
    else:
        return {"message": "Department status not updated"} 

# Route to get active departments
@app.get('/org-get-departments')
def get_departments(organisation_id: str = Query(None, description="Select organisation ID")):
    query = {"status": Status.Active.value}
    if organisation_id:
        query["organisation_id"] = str(organisation_id)
        
    departments = list(mycol2.find(query))

    for department in departments:
        department['_id'] = str(department['_id'])
        department['organisation_id'] = str(department['organisation_id'])
        department['department_id'] = str(department['department_id'])
        
    if departments:
        min_department_id = min(department['department_id'] for department in departments)
        organization_ids = set(department['organisation_id'] for department in departments)
    else:
        min_department_id = None
        organization_ids = set()

    return {"departments": departments, "min_department_id": min_department_id, "organisation_ids": list(organization_ids), "status": "active"}

# Route to get all departments
@app.get('/all-departments')
def get_all_departments():
    query = {}
    departments = list(mycol2.find(query))
    
    for department in departments:
        department['_id'] = str(department['_id'])
        department['organisation_id'] = str(department['organisation_id'])
        department['department_id'] = str(department['department_id'])
    
    if departments:
        min_department_id = min(department['department_id'] for department in departments)
        organization_ids = set(department['organisation_id'] for department in departments)
    else:
        min_department_id = None
        organization_ids = set()
    
    return {"departments": departments, "min_department_id": min_department_id, "organisation_ids": list(organization_ids)}

#----------------------------------------------JOB DESCRIPTION------------------------------------------------------------

# # MongoDB connection details
# MONGO_DETAILS = "mongodb+srv://somnath:somnath@cluster0.izhugny.mongodb.net/"
# client = MongoClient(MONGO_DETAILS)
# db = client.Role_Management
# job_collection = db.job_descriptions
# organization_collection = db.organizations

# Function to generate a unique job ID with the format "jid-000001"
def generate_custom_job_id():
    random_number = random.randint(1, 999999)
    job_id_numeric = f"{random_number:06}"
    custom_job_id = f"jid-{job_id_numeric}"
    return custom_job_id

# Pydantic model for job creation and updates
class JobDescription(BaseModel):
    org_id: str
    job_title: str
    city: str
    salary_range: str
    job_description: str
    required_skills: str
    functional_area: str
    company_info: str
    experience_years: int
    state: str
    employee_type: str
    responsibility: str
    status: str = "active"
    additional_skills: Optional[str] = None
    education: Optional[str] = None
    benefits: Optional[str] = None

    @validator('job_title', 'city', 'job_description', 'required_skills', 'functional_area', 'company_info', 'state', 'employee_type', 'responsibility')
    def validate_non_numeric(cls, value):
        if value.isdigit():
            raise ValueError('Value cannot be only numeric.')
        if not value.strip():
            raise ValueError('Value cannot be only blank spaces.')
        if not re.search(r'[a-zA-Z0-9]', value):
            raise ValueError('Value must contain at least one alphanumeric character.')
        return value

@app.post("/org-insert-job/")
def insert_job_description(job: JobDescription):
    try:
        job_id = generate_custom_job_id()
        job_data = job.dict()
        job_data.update({
            "Job_ID": job_id,
            "Creation_Date": datetime.now(),
            "Deleted": False
        })
        
        job_result = job_collection.insert_one(job_data)
        org_result = organization_collection.update_one(
            {"Org_ID": job.org_id},
            {"$setOnInsert": {"Org_ID": job.org_id, "Name": job.company_info}},
            upsert=True
        )

        if job_result.inserted_id:
            return {"message": "Job description and organization inserted successfully", "Job_ID": job_id, "Org_ID": job.org_id}
        else:
            raise HTTPException(status_code=500, detail="Failed to insert job description and organization")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/org-update-job/")
def update_job_description(
    Job_ID: str,
    org_id: str,
    job_title: Optional[str] = None,
    city: Optional[str] = None,
    salary_range: Optional[str] = None,
    job_description: Optional[str] = None,
    required_skills: Optional[str] = None,
    functional_area: Optional[str] = None,
    company_info: Optional[str] = None,
    experience_years: Optional[int] = None,
    state: Optional[str] = None,
    employee_type: Optional[str] = None,
    responsibility: Optional[str] = None,
    additional_skills: Optional[str] = None,
    education: Optional[str] = None,
    benefits: Optional[str] = None
):
    try:
        job_data = job_collection.find_one({"Job_ID": Job_ID, "org_id": org_id})
        if job_data and job_data["status"] == "active":
            update_fields = {}
            if job_title is not None:
                update_fields["job_title"] = job_title
            if city is not None:
                update_fields["city"] = city
            if salary_range is not None:
                update_fields["salary_range"] = salary_range
            if job_description is not None:
                update_fields["job_description"] = job_description
            if required_skills is not None:
                update_fields["required_skills"] = required_skills
            if functional_area is not None:
                update_fields["functional_area"] = functional_area
            if company_info is not None:
                update_fields["company_info"] = company_info
            if experience_years is not None:
                update_fields["experience_years"] = experience_years
            if state is not None:
                update_fields["state"] = state
            if employee_type is not None:
                update_fields["employee_type"] = employee_type
            if responsibility is not None:
                update_fields["responsibility"] = responsibility
            if additional_skills is not None:
                update_fields["additional_skills"] = additional_skills
            if education is not None:
                update_fields["education"] = education
            if benefits is not None:
                update_fields["benefits"] = benefits

            if not update_fields:
                raise HTTPException(status_code=400, detail="No fields provided for update")

            update_fields["Last_Update_Date"] = datetime.now()
            result = job_collection.update_one({"Job_ID": Job_ID, "org_id": org_id}, {"$set": update_fields})
            if result.modified_count == 1:
                return {"message": "Job description updated successfully", "Job_ID": Job_ID, "Org_ID": org_id}
            else:
                raise HTTPException(status_code=404, detail="Job description not found")
        else:
            raise HTTPException(status_code=400, detail="Job status is not active, cannot update job description")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/org-update-job-status/")
def update_job_status(Job_ID: str, org_id: str, status: str):
    try:
        query = {'Job_ID': Job_ID, 'org_id': org_id}
        
        if status not in ["active", "inactive"]:
            raise HTTPException(status_code=400, detail="Invalid status value. Allowed values: active, inactive")
        
        newvalues = {"$set": {"status": status}}
        result = job_collection.update_one(query, newvalues)
        
        if result.modified_count == 1:
            return {"message": "Job status updated successfully", "Job_ID": Job_ID, "Org_ID": org_id, "Status": status}
        else:
            raise HTTPException(status_code=404, detail="Job description not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/org-job-status/")
def get_job_status(org_id: str) -> List[dict]:
    try:
        job_descriptions = job_collection.find({"org_id": org_id, "status": "active"}, {"_id": 0, "Job_ID": 1, "status": 1})
        job_statuses = [job for job in job_descriptions]
        return job_statuses
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/all-job-statuses/")
def get_all_job_statuses() -> List[dict]:
    try:
        job_descriptions = job_collection.find({}, {"_id": 0, "Job_ID": 1, "status": 1})
        job_statuses = [job for job in job_descriptions]
        return job_statuses
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)




# Run the FastAPI application
#if __name__ == "__main__":
#    import uvicorn
#    uvicorn.run(app, host="0.0.0.0", port=8000)
