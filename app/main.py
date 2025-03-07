from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import subprocess
import sys
import logging
import asyncio
import httpx
import base64

# Import database and models
from app.database import Base, engine, get_db
from app.models import User

# ---------------------------
# Logging Setup
# ---------------------------
def setup_logging():
    logger = logging.getLogger("GPT_Script")
    logger.setLevel(logging.DEBUG)
    
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(logging.ERROR)
    
    f_handler = logging.FileHandler("GPT.log")
    f_handler.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)
    
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)
    return logger

logger = setup_logging()

# ---------------------------
# FastAPI Application Setup
# ---------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
async def run_insert_script(target_url: str = Body(..., embed=True)):
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "/opt/infiltr-ai/new-cli.py", target_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            decoded_line = line.decode("utf-8").strip()
            logger.debug("Broadcasting: " + decoded_line)
            await manager.broadcast(decoded_line)
        stderr = await process.stderr.read()
        if stderr:
            error_output = stderr.decode("utf-8").strip()
            logger.debug("Broadcasting stderr: " + error_output)
            await manager.broadcast("Error: " + error_output)
        await process.wait()
        return {"message": "Script executed successfully"}
    except Exception as e:
        logger.exception("Error executing script")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/risk-ot")
def risk_ot(db: Session = Depends(get_db)):
    try:
        query = text("""
            SELECT t.test_id, t.test_date, r.risk_score
            FROM tests t
            JOIN reports r ON t.test_id = r.test_id
            ORDER BY t.test_date ASC;
        """)
        result = db.execute(query).mappings().all()
        data = []
        for row in result:
            data.append({
                "test_id": row["test_id"],
                "test_date": row["test_date"].isoformat() if row["test_date"] is not None else None,
                "risk_score": float(row["risk_score"]) if row["risk_score"] is not None else None,
            })
        return {"data": data}
    except Exception as e:
        logger.exception("Error fetching risk data")
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/status")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/update-status")
async def update_status(phase: str = Body(..., embed=True)):
    await manager.broadcast(phase)
    return {"message": "Status updated", "phase": phase}

@app.get("/api/vulnerability-summary")
def vulnerability_summary(db: Session = Depends(get_db)):
    try:
        query = text("""
            SELECT 
                v.vulnerability_name, 
                v.endpoint, 
                v.severity, 
                v.cvss_score, 
                v.potential_loss, 
                t.test_name, 
                t.test_date
            FROM vulnerabilities v
            JOIN tests t ON v.test_id = t.test_id
            ORDER BY v.cvss_score DESC;
        """)
        result = db.execute(query).mappings().all()
        summary = []
        for row in result:
            summary.append({
                "vulnerability_name": row["vulnerability_name"],
                "endpoint": row["endpoint"],
                "severity": row["severity"],
                "cvss_score": float(row["cvss_score"]) if row["cvss_score"] is not None else None,
                "potential_loss": float(row["potential_loss"]) if row["potential_loss"] is not None else None,
                "test_name": row["test_name"],
                "test_date": row["test_date"].isoformat() if row["test_date"] is not None else None,
            })
        return {"data": summary}
    except Exception as e:
        logger.exception("Error fetching vulnerability summary")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/compliance-scores-ot")
def compliance_scores_ot(db: Session = Depends(get_db)):
    try:
        query = text("""
            SELECT t.test_id, t.test_date, r.compliance_score
            FROM tests t
            JOIN reports r ON t.test_id = r.test_id
            ORDER BY t.test_date ASC;
        """)
        result = db.execute(query).mappings().all()
        data = []
        for row in result:
            data.append({
                "test_id": row["test_id"],
                "test_date": row["test_date"].isoformat() if row["test_date"] is not None else None,
                "compliance_score": float(row["compliance_score"]) if row["compliance_score"] is not None else None
            })
        return {"data": data}
    except Exception as e:
        logger.exception("Error fetching compliance scores")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/potential-loss-per-vuln")
def potential_loss_per_vuln(db: Session = Depends(get_db)):
    try:
        query = text("""
            SELECT v.vulnerability_name, v.potential_loss
            FROM vulnerabilities v
            JOIN tests t ON v.test_id = t.test_id
            WHERE t.test_date = (SELECT MAX(test_date) FROM tests)
        """)
        result = db.execute(query).mappings().all()
        data = []
        for row in result:
            data.append({
                "vulnerability_name": row["vulnerability_name"],
                "potential_loss": float(row["potential_loss"]) if row["potential_loss"] is not None else None,
            })
        return {"data": data}
    except Exception as e:
        logger.exception("Error fetching potential loss per vulnerability")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/prev-assessments")
def prev_assessments(db: Session = Depends(get_db)):
    try:
        query = text("""
            SELECT 
                t.test_id,
                t.test_name, 
                t.test_date, 
                t.test_status, 
                COUNT(v.vulnerability_id) AS vulnerability_count
            FROM tests t
            LEFT JOIN vulnerabilities v ON t.test_id = v.test_id
            GROUP BY t.test_id, t.test_name, t.test_date, t.test_status
            ORDER BY t.test_date DESC;
        """)
        result = db.execute(query).mappings().all()
        data = []
        for row in result:
            data.append({
                "test_id": row["test_id"],
                "test_name": row["test_name"],
                "test_date": row["test_date"].isoformat() if row["test_date"] is not None else None,
                "vulnerability_count": row["vulnerability_count"],
                "test_status": row["test_status"]
            })
        return {"data": data}
    except Exception as e:
        logger.exception("Error fetching previous assessments")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/suggestions")
def get_suggestions(db: Session = Depends(get_db)):
    try:
        query = text("""
            SELECT DISTINCT ON (v.test_id, v.vulnerability_name)
                v.test_id,
                v.vulnerability_name,
                s.suggestion_text,
                s.cwe_id
            FROM suggestions s
            JOIN vulnerabilities v ON s.vulnerability_id = v.vulnerability_id
            ORDER BY v.test_id, v.vulnerability_name, s.suggestion_text;
        """)
        result = db.execute(query).mappings().all()
        suggestions = []
        for row in result:
            suggestions.append({
                "vulnerability_name": row["vulnerability_name"],
                "suggestion_text": row["suggestion_text"],
                "cwe_id": row["cwe_id"]
            })
        return {"data": suggestions}
    except Exception as e:
        logger.exception("Error fetching suggestions")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cards")
def test_summary(db: Session = Depends(get_db)):
    tests = db.execute(
        text("SELECT test_id, test_date FROM tests ORDER BY test_date DESC LIMIT 2")
    ).mappings().all()

    if not tests:
        raise HTTPException(status_code=404, detail="No tests found.")

    current_test = tests[0]
    previous_test = tests[1] if len(tests) > 1 else None

    current_vulns = db.execute(
        text("SELECT COUNT(*) FROM vulnerabilities WHERE test_id = :tid"),
        {"tid": current_test["test_id"]}
    ).scalar()

    previous_vulns = (
        db.execute(
            text("SELECT COUNT(*) FROM vulnerabilities WHERE test_id = :tid"),
            {"tid": previous_test["test_id"]}
        ).scalar() if previous_test else None
    )

    current_suggestions = db.execute(
        text("""
            SELECT COUNT(*) 
            FROM suggestions s 
            JOIN vulnerabilities v ON s.vulnerability_id = v.vulnerability_id 
            WHERE v.test_id = :tid
        """),
        {"tid": current_test["test_id"]}
    ).scalar()

    previous_suggestions = (
        db.execute(
            text("""
                SELECT COUNT(*) 
                FROM suggestions s 
                JOIN vulnerabilities v ON s.vulnerability_id = v.vulnerability_id 
                WHERE v.test_id = :tid
            """),
            {"tid": previous_test["test_id"]}
        ).scalar() if previous_test else None
    )

    current_report = db.execute(
        text("SELECT risk_score, compliance_score FROM reports WHERE test_id = :tid"),
        {"tid": current_test["test_id"]}
    ).mappings().first()

    previous_report = (
        db.execute(
            text("SELECT risk_score, compliance_score FROM reports WHERE test_id = :tid"),
            {"tid": previous_test["test_id"]}
        ).mappings().first() if previous_test else None
    )

    current_risk = float(current_report["risk_score"]) if current_report and current_report["risk_score"] is not None else None
    current_compliance = float(current_report["compliance_score"]) if current_report and current_report["compliance_score"] is not None else None

    previous_risk = float(previous_report["risk_score"]) if previous_report and previous_report["risk_score"] is not None else None
    previous_compliance = float(previous_report["compliance_score"]) if previous_report and previous_report["compliance_score"] is not None else None

    def calc_percentage_diff(current, previous):
        if previous is None or previous == 0:
            return None
        return ((current - previous) / previous) * 100

    vuln_diff = calc_percentage_diff(current_vulns, previous_vulns) if previous_vulns is not None else None
    sugg_diff = calc_percentage_diff(current_suggestions, previous_suggestions) if previous_suggestions is not None else None
    risk_diff = calc_percentage_diff(current_risk, previous_risk) if previous_risk is not None else None
    compliance_diff = calc_percentage_diff(current_compliance, previous_compliance) if previous_compliance is not None else None

    summary = {
        "vulnerabilities": {
            "count": current_vulns,
            "percentage_difference": vuln_diff
        },
        "suggestions": {
            "count": current_suggestions,
            "percentage_difference": sugg_diff
        },
        "risk_score": {
            "score": current_risk,
            "percentage_difference": risk_diff
        },
        "compliance_score": {
            "score": current_compliance,
            "percentage_difference": compliance_diff
        }
    }

    return {"data": summary}

@app.get("/api/report-summary")
def report_summary(test_id: int, db: Session = Depends(get_db)):
    try:
        query = text("SELECT summary, detailed_findings FROM reports WHERE test_id = :tid")
        result = db.execute(query, {"tid": test_id}).mappings().first()
        if not result or result["summary"] is None:
            raise HTTPException(status_code=404, detail="Report summary not found")
        return {
            "summary": result["summary"],
            "detailed_findings": result["detailed_findings"]
        }
    except Exception as e:
        logger.exception("Error fetching report summary")
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------
# Zoom OAuth Callback Endpoint
# ---------------------------
@app.get("/oauth/callback")
async def zoom_oauth_callback(code: str):
    """
    This endpoint handles the OAuth callback from Zoom.
    It exchanges the authorization code for an access token,
    then redirects the user back to the React app with the token.
    """
    client_id = "CHPwG7tiSZKVp9BzkSIeSA"       # Your Zoom Client ID
    client_secret = "Loth7n2ZizZM1krL7coI5aaiUhkusICX"  # Your Zoom Client Secret
    token_url = "https://zoom.us/oauth/token"
    
    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://172.235.49.182:8000/oauth/callback"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data, headers=headers)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Failed to exchange token: {response.text}")
        
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        # Redirect to the React app with the access_token as a query parameter.
        const_frontend_url = f"http://localhost:3000/?access_token={access_token}"
        return RedirectResponse(url=const_frontend_url)
    
    except Exception as e:
        logger.exception("Error during OAuth callback")
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------
# Zoom Create Meeting Endpoint
# ---------------------------
@app.post("/api/create-meeting")
async def create_meeting(
    token: str = Body(..., embed=True),
    meeting_topic: str = Body(..., embed=True),
    start_time: str = Body(..., embed=True),
    duration: int = Body(..., embed=True),
    timezone: str = Body(..., embed=True)
):
    """
    Create a scheduled Zoom meeting using the provided access token.
    - token: Zoom access token
    - meeting_topic: Topic of the meeting
    - start_time: Start time in ISO 8601 format (UTC)
    - duration: Duration in minutes
    - timezone: Timezone (e.g., "UTC")
    """
    meeting_payload = {
        "topic": meeting_topic,
        "type": 2,
        "start_time": start_time,
        "duration": duration,
        "timezone": timezone,
        "agenda": "Demo meeting",
        "settings": {
            "host_video": True,
            "participant_video": True,
            "join_before_host": False
        }
    }
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post("https://api.zoom.us/v2/users/me/meetings", json=meeting_payload, headers=headers)
    
    if response.status_code != 201:
        raise HTTPException(status_code=response.status_code, detail=f"Failed to create meeting: {response.text}")
    
    return response.json()

# ---------------------------
# Zoom Refresh Token Endpoint (Optional)
# ---------------------------
@app.post("/api/refresh-token")
async def refresh_token(refresh_token: str = Body(..., embed=True)):
    """
    Refresh the Zoom access token using the provided refresh token.
    """
    token_url = "https://zoom.us/oauth/token"
    client_id = "CHPwG7tiSZKVp9BzkSIeSA"
    client_secret = "Loth7n2ZizZM1krL7coI5aaiUhkusICX"
    
    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data, headers=headers)
    
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=f"Failed to refresh token: {response.text}")
    
    return response.json()

@app.get("/")
async def root():
    return {"message": "Welcome to the backend API!"}
