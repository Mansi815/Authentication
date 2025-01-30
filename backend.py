from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import validator
from pydantic import BaseModel, EmailStr, constr, validator
from typing import Optional
import mysql.connector
import bcrypt
import jwt
from datetime import datetime, timedelta
import re

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root",
    "database": "user_management"
}

# JWT configuration
SECRET_KEY = "f06a04f47e3d2e65f3e2dcab44250ef74c36b331253e7bcbee87ec0e4a3d431728fdb1b91735ba948ac58c74bb6e3c31cb1381482cf4fbf9fc397b4c419750dd95742557383d021899f1b39e7f2f788b812dda5f91d8f8cbe245bc0431524efecf3c906e87e94186d9c2785df3dab08048e844eea15250884add4e6665bacb55c2b835e4951ce22ee1b8c6eaef18c5d25a9bb5150b7bffbe4bb9b013855ebe35fd4ab5ba5b0b6cc40665a5f7ddcf98e8c93fab9354226009159d78bbd299d9e90445731c6f9f64ff7f5801e953235dd8f3976a3c5c6f19da898078d3507c23069fbe61af8b8d30e54a30a991cfb4ca27aee899529be292e907ce6cc8139c3f86"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

class UserCreate(BaseModel):
    username: str

    @validator('username')
    def username_length(cls, v):
        if not (3 <= len(v) <= 50):
            raise ValueError('Username must be between 3 and 50 characters')
        return v
    password: str

    @validator('password')
    def password_length(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v
    email: EmailStr
    role_id: int

class Token(BaseModel):
    access_token: str
    token_type: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def validate_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.get("/")
async def read_root():
    return {"message": "Welcome to the FastAPI application!"}

@app.get("/favicon.ico")
async def favicon():
    return {"message": "No favicon found."}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute(
            "SELECT user_id, username, password_hash, role_id FROM users WHERE username = %s",
            (form_data.username,)
        )
        user = cursor.fetchone()
        
        if not user or not verify_password(form_data.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        access_token = create_access_token(
            data={"sub": user["username"], "role_id": user["role_id"]}
        )
        return Token(access_token=access_token, token_type="bearer")
    
    finally:
        cursor.close()
        conn.close()

@app.post("/users/create")
async def create_user(user: UserCreate, token: str = Depends(oauth2_scheme)):
    # Verify admin token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role_id") != 1:  # Admin role_id = 1
            raise HTTPException(status_code=403, detail="Only admins can create users")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not validate_password(user.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long and contain uppercase, lowercase, and numbers"
        )
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role_id) VALUES (%s, %s, %s, %s)",
            (user.username, get_password_hash(user.password), user.email, user.role_id)
        )
        conn.commit()
        return {"message": "User created successfully"}
    except mysql.connector.IntegrityError as e:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    finally:
        cursor.close()
        conn.close()
