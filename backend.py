from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import mysql.connector
from mysql.connector import Error
import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr, constr

app = FastAPI()

# Database configuration - REPLACE with your actual credentials
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Mansi@0304",  # Replace with your MySQL password
    "database": "user_management"
}

# JWT configuration - Use a secure key
SECRET_KEY = "956fdd7902341c26b517f39cdfab0fc718c7a4a74b4557d96eea04274eb9aa08b79d22cbe7d264b8037366002b7ba50ad2494adcf4ac0fe99589cd28d19c1271dc31ca5cfa9af17a6e46ad7421836ae6401346c4f2539d9a743405ac6d796520def6373a57669fe3110d9d046aa079867489a0c06da19e72f786506b386b651a98b47c43e52d02275b28e7899c683c908cc54f0024c9f537812aff3fc272eabcd5794a5fca5e196d1569fef4917c2f856db099b485a6312ab8de3e722761908039ce023f56ee466fe232ba5f01202261e643809ab8122e8f8177b506d176aae74c762afbf75b0414fcc6ac19ac04610440b15f9cf04d686d63970d994f23ec9f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Function to initialize database
def init_db():
    try:
        conn = mysql.connector.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"]
        )
        cursor = conn.cursor()

        # Create database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS user_management")
        cursor.execute("USE user_management")

        # Create roles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                role_id INT PRIMARY KEY AUTO_INCREMENT,
                role_name VARCHAR(50) NOT NULL UNIQUE
            )
        """)

        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100) NOT NULL UNIQUE,
                role_id INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (role_id) REFERENCES roles(role_id)
            )
        """)

        # Insert roles if they don't exist
        cursor.execute("INSERT IGNORE INTO roles (role_id, role_name) VALUES (1, 'admin'), (2, 'user')")

        # Create default admin user if it doesn't exist
        admin_username = "admin"
        admin_password = "Admin123"  # Change this to a strong admin password
        admin_email = "admin@example.com"

        # Hash the password
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor.execute("""
            INSERT IGNORE INTO users (username, password_hash, email, role_id)
            VALUES (%s, %s, %s, 1)
        """, (admin_username, hashed_password, admin_email))

        conn.commit()
        print("Database initialized successfully!")

    except Error as e:
        print(f"Error initializing database: {e}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Initialize database on startup
init_db()

# Get the absolute path to the static and templates directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
templates_dir = os.path.join(BASE_DIR, "templates")

# Mount static files
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=8)
    email: EmailStr
    role_id: int

class Token(BaseModel):
    access_token: str
    token_type: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Serve the main page
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Function to connect to the database
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

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/api/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT user_id, username, password_hash, role_id FROM users WHERE username = %s", (form_data.username,))
        user = cursor.fetchone()
        print(f"User fetched from DB: {user}")

        if not user or not verify_password(form_data.password, user["password_hash"]):
            print("Login failed: Incorrect username or password")
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        access_token = create_access_token(data={"sub": user["username"], "role_id": user["role_id"]})
        return Token(access_token=access_token, token_type="bearer")

    finally:
        cursor.close()
        conn.close()


@app.post("/api/users/create")
async def create_user(user: UserCreate, token: str = Depends(oauth2_scheme)):
    # Verify admin token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role_id") != 1:  # Admin role_id = 1
            raise HTTPException(status_code=403, detail="Only admins can create users")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role_id) VALUES (%s, %s, %s, %s)",
            (user.username, get_password_hash(user.password), user.email, user.role_id)
        )
        conn.commit()
        return {"message": "User created successfully"}
    except mysql.connector.IntegrityError:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    finally:
        cursor.close()
        conn.close()
