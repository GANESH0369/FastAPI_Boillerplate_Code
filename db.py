from datetime import datetime
from typing import Optional
from pydantic import BaseModel
class StudentCreate(BaseModel):
    lname: str
    fname: str
    email: str
    password:str

class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str

class ChangePasswordSchema(BaseModel):
    email: str
    old_password:str
    new_password: str

class TokenData(BaseModel):
    username: Optional[str] = None
    expires: datetime


class LoginRequest(BaseModel):
    username: str
    password: str