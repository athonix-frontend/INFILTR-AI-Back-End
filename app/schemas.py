from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import date

class TestCreate(BaseModel):
    user_id: int
    test_date: date
    test_status: str
    test_name: str
    
    class Config:
        from_attributes = True  # ✅ Fix for Pydantic V2

class UserCreate(BaseModel):
    google_oauth: Optional[bool] = False
    email: EmailStr
    password: str
    name: str

class UserResponse(BaseModel):
    user_id: int
    email: EmailStr
    name: str
    google_oauth: bool

    class Config:
        orm_mode = True
