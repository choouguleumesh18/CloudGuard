from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
class ScanCreate(BaseModel): subscription_id: str = Field(min_length=8,max_length=100)
class ScanRead(BaseModel):
    id: str; subscription_id: str; status: str; started_at: datetime | None = None; completed_at: datetime | None = None; error_message: str | None = None
    model_config=ConfigDict(from_attributes=True)
