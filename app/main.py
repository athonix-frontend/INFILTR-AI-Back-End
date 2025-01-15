from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.routers import users  # Assuming this exists
from app.database import Base, engine, get_db  # Assuming these exist
from app.models import User  # Assuming this is your SQLAlchemy User model

# Initialize FastAPI app
app = FastAPI()

# Database setup
Base.metadata.create_all(bind=engine)

# Include additional routers (from your pre-existing code)
app.include_router(users.router)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic schema for user input validation
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

# Function to hash passwords
def hash_password(password: str):
    return pwd_context.hash(password)

# Function to create a user in the database
def create_user(db: Session, user: UserCreate):
    # Check if email already exists
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create and save user
    hashed_pw = hash_password(user.password)
    new_user = User(name=user.name, email=user.email, password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# API endpoint for user registration
@app.post("/api/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    user = create_user(db, user)
    return {"message": "User registered successfully!", "user_id": user.id}

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to the backend API!"}
