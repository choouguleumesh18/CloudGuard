from datetime import datetime
from pydantic import BaseModel, ConfigDict
class FindingRead(BaseModel):
    id:str; scan_id:str; resource_id:str; resource_name:str; rule_id:str; severity:str; description:str; status:str; details:dict; created_at:datetime
    model_config=ConfigDict(from_attributes=True)
