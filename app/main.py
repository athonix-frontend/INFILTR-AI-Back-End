from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text  # <-- Added import for text
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import subprocess
import sys
from fastapi import WebSocket, WebSocketDisconnect
from fastapi import Body

# Import database and models
from app.database import Base, engine, get_db
from app.models import User

# Initialize FastAPI app
app = FastAPI()

# Allow CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8000"],  # Update with actual frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
Base.metadata.create_all(bind=engine)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "b43d25f0c3fa7bc3a2d6b5982c841bcf0e1dcf2c56e6c4a3d0fc4b60467822b3"  # Use a strong secret key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Pydantic schemas
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

# Function to hash passwords
def hash_password(password: str):
    return pwd_context.hash(password)

# Function to verify passwords
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Function to create JWT
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to create a user in the database
def create_user(db: Session, user: UserCreate):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = hash_password(user.password)
    new_user = User(name=user.name, email=user.email, password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Function to authenticate user
def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        return False
    return user

# API endpoint for user registration
@app.post("/api/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    user = create_user(db, user)
    return {"message": "User registered successfully!", "user_id": user.user_id}

# API endpoint for user login
@app.post("/api/login", response_model=Token)
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# API endpoint to execute /opt/infiltr-ai/insert_data.py
@app.post("/api/run-script")
def run_insert_script():
    try:
        result = subprocess.run(
            [sys.executable, "/opt/infiltr-ai/new-cli.py"],  # Uses the same Python interpreter as FastAPI
            capture_output=True, text=True
        )

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Script failed: {result.stderr}")

        return {"message": "Script executed successfully", "output": result.stdout}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# *********************************************************************
# New API endpoint: Aggregated Data per Month
#
# This endpoint returns:
#   - Average risk per month
#   - Total vulnerabilities per month
#   - Average compliance per month
#
# The SQL query uses date_trunc('month', report_date) to group data by month.
# *********************************************************************
@app.get("/api/aggregated-data")
def get_aggregated_data(db: Session = Depends(get_db)):
    try:
        query = text("""
            SELECT
                date_trunc('month', report_date) as month,
                AVG(risk_score) as avg_risk,
                SUM(vulnerability_count) as total_vulnerabilities,
                AVG(compliance_score) as avg_compliance
            FROM reports
            GROUP BY month
            ORDER BY month;
        """)
        # Use the mappings() method to iterate over rows as dictionaries.
        result = db.execute(query).mappings()
        data = []
        for row in result:
            # Format the month as "YYYY-MM" for clarity in the frontend chart
            data.append({
                "month": row["month"].strftime("%Y-%m") if row["month"] is not None else None,
                "avg_risk": float(row["avg_risk"]) if row["avg_risk"] is not None else None,
                "total_vulnerabilities": int(row["total_vulnerabilities"]) if row["total_vulnerabilities"] is not None else None,
                "avg_compliance": float(row["avg_compliance"]) if row["avg_compliance"] is not None else None,
            })
        return {"data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/status")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # The server can listen for messages if necessary.
            data = await websocket.receive_text()
            # Optionally process client messages.
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/update-status")
async def update_status(phase: str = Body(..., embed=True)):
    # Broadcast the current phase to all WebSocket clients
    await manager.broadcast(phase)
    return {"message": "Status updated", "phase": phase}

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to the backend API!"}
