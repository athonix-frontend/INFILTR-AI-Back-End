from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from . import models, schemas, crud
from .database import engine, get_db

app = FastAPI()

# Create Tables in Database
models.Base.metadata.create_all(bind=engine)

@app.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    return crud.create_user(db=db, user=user)

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
