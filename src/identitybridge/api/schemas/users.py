from pydantic import BaseModel, ConfigDict, Field


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)


class UserStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


class RoleAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
