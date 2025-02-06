from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Body
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
import logging

# Import database and models
from app.database import Base, engine, get_db
from app.models import User

# ---------------------------
# Logging Setup
# ---------------------------
def setup_logging():
    logger = logging.getLogger("GPT_Script")
    logger.setLevel(logging.DEBUG)
    
    # Create a console handler (prints to stdout)
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(logging.INFO)
    
    # Create a file handler (writes to GPT.log)
    f_handler = logging.FileHandler("GPT.log")
    f_handler.setLevel(logging.DEBUG)
    
    # Create formatters for both handlers
    c_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    f_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)
    
    # Add the handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)
    
    return logger

# Instantiate logger for the whole module
logger = setup_logging()

# ---------------------------
# FastAPI Application Setup
# ---------------------------
app = FastAPI()

# Allow CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8000"],
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

# ---------------------------
# Pydantic Schemas
# ---------------------------
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

# ---------------------------
# Connection Manager for WebSockets
# ---------------------------
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

# Instantiate the connection manager outside the class definition
manager = ConnectionManager()

# ---------------------------
# Helper Functions
# ---------------------------
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_user(db: Session, user: UserCreate):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = hash_password(user.password)
    new_user = User(name=user.name, email=user.email, password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        return False
    return user

# ---------------------------
# API Endpoints
# ---------------------------

# User registration endpoint
@app.post("/api/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    user = create_user(db, user)
    return {"message": "User registered successfully!", "user_id": user.user_id}

# User login endpoint
@app.post("/api/login", response_model=Token)
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoint to run new-cli.py script
@app.post("/api/run-script")
def run_insert_script():
    try:
        result = subprocess.run(
            [sys.executable, "/opt/infiltr-ai/new-cli.py"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            error_msg = f"Script failed: {result.stderr}"
            logger.error(error_msg)
            raise HTTPException(status_code=500, detail=error_msg)
        return {"message": "Script executed successfully", "output": result.stdout}
    except Exception as e:
        logger.exception("Error executing script")
        raise HTTPException(status_code=500, detail=str(e))

# Aggregated data endpoint
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
        result = db.execute(query).mappings()
        data = []
        for row in result:
            data.append({
                "month": row["month"].strftime("%Y-%m") if row["month"] is not None else None,
                "avg_risk": float(row["avg_risk"]) if row["avg_risk"] is not None else None,
                "total_vulnerabilities": int(row["total_vulnerabilities"]) if row["total_vulnerabilities"] is not None else None,
                "avg_compliance": float(row["avg_compliance"]) if row["avg_compliance"] is not None else None,
            })
        return {"data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket endpoint for status updates
@app.websocket("/ws/status")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Wait for client messages (if needed)
            data = await websocket.receive_text()
            # You can process incoming messages here if required.
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Endpoint to update status (sends message to all connected WebSocket clients)
@app.post("/api/update-status")
async def update_status(phase: str = Body(..., embed=True)):
    await manager.broadcast(phase)
    return {"message": "Status updated", "phase": phase}

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to the backend API!"}
