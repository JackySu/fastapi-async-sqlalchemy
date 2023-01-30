from typing import Optional
from uuid import UUID
from sqlmodel import SQLModel, Field


class UserBase(SQLModel):
    email: str = Field(default=None, primary_key=True)
    username: Optional[str] = None
    phone: Optional[str] = None


class UserSignup(UserBase):
    password: str = Field(default=None)


# table = True => in database
class Users(UserBase, table=True):
    hashed_password: str = None
    id: UUID = Field(default=None)
    is_active: bool = Field(default=True)


class Token(SQLModel):
    access_token: str
    token_type: str
