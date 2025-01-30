from pydantic import BaseModel
from typing import Optional
from datetime import date, datetime

# Schema for Creating a User
class UserCreate(BaseModel):
    google_oauth: Optional[bool] = False
    email: str
    password: str
    name: str

# Schema for Creating a Test
class TestCreate(BaseModel):
    user_id: int
    test_date: date
    test_status: str
    test_name: str
