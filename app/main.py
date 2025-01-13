from fastapi import FastAPI
from app.routers import users
from app.database import Base, engine
from app.models import User

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(users.router)

@app.get("/")
async def root():
    return {"message": "Welcome to the backend API!"}
