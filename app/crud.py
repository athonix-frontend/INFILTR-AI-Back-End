from sqlalchemy.orm import Session
from app.models import User
from app.schemas import UserCreate
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)  # Hash password
    db_user = User(name=user.name, email=user.email, password=hashed_password, google_oauth=user.google_oauth)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
