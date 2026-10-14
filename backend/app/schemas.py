from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import datetime
from typing import Literal
Role = Literal["administrator", "soc_member", "security_analyst", "researcher"]
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    full_name: str = Field(min_length=2, max_length=120)
    role: Role = "researcher"
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    role: Role | None = None
class UserOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id: int; email: EmailStr; full_name: str; role: Role; active: bool; created_at: datetime; last_login_at: datetime|None=None
class TokenResponse(BaseModel):
    access_token: str; token_type: str="bearer"; user: UserOut
class AdminCreateUser(BaseModel):
    email: EmailStr; password: str=Field(min_length=10,max_length=128); full_name: str=Field(min_length=2,max_length=120); role: Role
class RoleUpdate(BaseModel): role: Role
class StatusUpdate(BaseModel): active: bool


class IncidentCreate(BaseModel):
    scan_id: int = Field(gt=0)
    title: str = Field(min_length=3,max_length=255)
    notes: str = Field(default="",max_length=10000)
class IncidentUpdate(BaseModel):
    status: Literal["open","investigating","resolved","false_positive"] | None = None
    assigned_to: int | None = None
    notes: str | None = Field(default=None,max_length=10000)
class AnnotationCreate(BaseModel):
    scan_id: int = Field(gt=0)
    ground_truth: Literal["benign","malware","unknown"] = "unknown"
    family: str | None = Field(default=None,max_length=120)
    dataset_source: str = Field(default="local scan",min_length=1,max_length=255)
    notes: str = Field(default="",max_length=10000)
class ExperimentNoteCreate(BaseModel):
    title: str = Field(min_length=2,max_length=255)
    content: str = Field(min_length=1,max_length=10000)
    tags: str = Field(default="",max_length=500)
