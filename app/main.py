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
    
    # Console handler: outputs to stdout
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(logging.INFO)
    
    # File handler: outputs to GPT.log
    f_handler = logging.FileHandler("GPT.log")
    f_handler.setLevel(logging.DEBUG)
    
    # Formatters
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)
    return logger

# Create logger instance
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

# ---------------------------
# Password Hashing and JWT Settings
# ---------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "b43d25f0c3fa7bc3a2d6b5982c841bcf0e1dcf2c56e6c4a3d0fc4b60467822b3"
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
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

# Instantiate the connection manager
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
@app.post("/api/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    user = create_user(db, user)
    return {"message": "User registered successfully!", "user_id": user.user_id}

@app.post("/api/login", response_model=Token)
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/run-script")
def run_insert_script(target_url: str = Body(..., embed=True)):
    try:
        # Pass the target_url as a command-line argument to new-cli.py
        result = subprocess.run(
            [sys.executable, "/opt/infiltr-ai/new-cli.py", target_url],
            capture_output=True, text=True
        )
        # Log stdout and stderr for debugging
        logger.debug("Script stdout: " + result.stdout)
        logger.debug("Script stderr: " + result.stderr)

        if result.returncode != 0:
            error_msg = f"Script failed: return code {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
            logger.error(error_msg)
            raise HTTPException(status_code=500, detail=error_msg)
        return {"message": "Script executed successfully", "output": result.stdout}
    except Exception as e:
        logger.exception("Error executing script")
        raise HTTPException(status_code=500, detail=str(e))

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

@app.websocket("/ws/status")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Wait for messages from the client if needed
            data = await websocket.receive_text()
            # (Optional: Process incoming messages)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/update-status")
async def update_status(phase: str = Body(..., embed=True)):
    # Broadcast the phase to all connected WebSocket clients
    await manager.broadcast(phase)
    return {"message": "Status updated", "phase": phase}

@app.get("/")
async def root():
    return {"message": "Welcome to the backend API!"}
