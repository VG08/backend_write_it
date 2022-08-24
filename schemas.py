from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str

class PostCreate(BaseModel):
    title:str
    content:str
class Post(PostCreate):
    id: int
    title: str
    content: str
    owner_id: int
    created_at: datetime

    class Config:
        orm_mode = True
class User(UserBase):
    id: int
    disabled: bool
    posts: list[Post] = []
    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
