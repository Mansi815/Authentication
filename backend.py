from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import mysql.connector
import os
import bcrypt
import jwt  # Ensure you have PyJWT installed
from pydantic import BaseModel, EmailStr, constr
from typing import Optional
import datetime

app = FastAPI()

# Database configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Pratham@2102",  # Replace with actual MySQL password
    "database": "user_management"
}

# Get the absolute path to the static and templates directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
templates_dir = os.path.join(BASE_DIR, "templates")

# Mount static files (for CSS, JS, images)
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

class LoginRequest(BaseModel):
    username: str
    password: str

# Function to connect to the database
def get_db():
    """ Creates and returns a database connection """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

SECRET_KEY = "99f6d476abe0263605e31a2a1c45661738beec626b7b1e7c9113767da11565ac40d59e23041ebb0f35963edbbace059ba256bf370f703ee40f62dc5f863d4dd0edc45d67e0ee50915cbdbf8b562a7b68c150f41fb562592c4233fbaddbd5fe7abeea8ccb3b099a2acc6d17275d59299173d2415faac8b922d3aa77d52f8fdc9422d4c65c0f58fc585b2dc19293d030eb19f7d47e890df715ad51e4b475a85e136971cc8eeedcf3f6ca41eecb414ac18ffac4e1cc23feb41f249a31618f041808c3c87f56233f37daddef651fe5b61abea39bb09bb2b54b887946114aea928e90a81a543272162bac6afa1a61fd19438d774375c4fb1638aeaf46cd44caae653c"  # Use a strong secret key
ALGORITHM = "HS256"  # Algorithm for encoding the token

def create_token(user_id: int):
    """ Create a JWT token for the user """
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token valid for 1 hour
    token = jwt.encode({"user_id": user_id, "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_token(token: str):
    """ Verify the JWT token and return the user ID """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload['user_id']  # Return the user ID from the token
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """ Verifies password with bcrypt hash """
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    """ Hashes password using bcrypt """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """ Render the 'index.html' template """
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/token")
async def login(request: LoginRequest):
    """ Handles login via JSON body """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT user_id, username, password_hash, role_id FROM users WHERE username = %s", (request.username,))
        user = cursor.fetchone()

        if not user or not verify_password(request.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        # Create a token for the user
        token = create_token(user["user_id"])
        return {"access_token": token, "role_id": user["role_id"]}

    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    finally:
        cursor.close()
        conn.close()

@app.get("/api/dashboard")
async def get_dashboard_data(authorization: str = Header(...)):
    """ Returns dashboard data for the logged-in user """
    token = authorization.split(" ")[1]  # Extract the token from the header
    user_id = verify_token(token)  # Verify the token and get the user ID

    # Here you can fetch user-specific data from the database
    # For demonstration, we'll return a simple message
    return {"message": "Welcome to your dashboard!", "user_id": user_id}

@app.post("/api/users/create")
async def create_user(user: UserCreate, authorization: str = Header(...)):
    """ Allows admins to create new users """
    # Verify the token and extract user information
    token = authorization.split(" ")[1]  # Extract the token from the header
    user_id = verify_token(token)  # Verify the token and get the user ID

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if the user is an admin
        cursor.execute("SELECT role_id FROM users WHERE user_id = %s", (user_id,))
        user_role = cursor.fetchone()

        if user_role is None or user_role['role_id'] != 1:  # Assuming role_id 1 is for admin
            raise HTTPException(status_code=403, detail="Access denied. Only admins can create users.")

        # Hash the password before storing it
        hashed_password = get_password_hash(user.password)

        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role_id) VALUES (%s, %s, %s, %s)",
            (user.username, hashed_password, user.email, user.role_id)
        )
        conn.commit()
        return {"message": "User  created successfully"}

    except mysql.connector.IntegrityError as e:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        cursor.close()
        conn.close()