"""
Schemas
"""

# pylint: disable=no-name-in-module, too-few-public-methods, missing-class-docstring,
# pylint: disable=missing-function-docstring, no-self-argument, use-a-generator
from pydantic import BaseModel, model_validator


class Response(BaseModel):
    success: bool
    detail: str = None


class CreateUser(BaseModel):
    username: str
    firstname: str
    lastname: str
    email: str
    password: str
    admin: bool

    class Config:
        from_attributes = True


class UserOut(BaseModel):
    id: int
    username: str
    firstname: str
    lastname: str
    email: str
    admin: bool

    class Config:
        from_attributes = True


class ModifyUser(BaseModel):
    firstname: str = None
    lastname: str = None
    email: str = None
    password: str = None
    admin: bool = None

    @model_validator(mode="before")
    @classmethod
    def check_at_least_one(cls, values):
        if all([value is None for value in values.values()]):
            raise ValueError("The request body should contain at least one field.")
        return values
