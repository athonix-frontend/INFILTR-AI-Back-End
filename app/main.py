from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from . import models, schemas
from .database import engine, get_db

app = FastAPI()

# Create Tables in Database
models.Base.metadata.create_all(bind=engine)

# Endpoint to Create a New User
@app.post("/users/")
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = models.User(email=user.email, password=user.password, name=user.name, google_oauth=user.google_oauth)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Endpoint to Create a New Test
@app.post("/tests/")
def create_test(test: schemas.TestCreate, db: Session = Depends(get_db)):
    db_test = models.Test(
        user_id=test.user_id,
        test_date=test.test_date,
        test_status=test.test_status,
        test_name=test.test_name
    )
    db.add(db_test)
    db.commit()
    db.refresh(db_test)
    return db_test
