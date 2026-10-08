from typing import List, Dict, Literal
from pydantic import BaseModel

class TargetCapabilities(BaseModel):
    chat: bool = True
    rag: bool = False
    tools: bool = False
    data_access: bool = False
    tool_names: List[str] = []

class TargetContract(BaseModel):
    name: str
    base_url: str
    model_name: str = "qwen-flash"
    target_type: str = "INTERNAL_RAG"
    target_mode: Literal["INSTRUMENTED", "BLACK_BOX"] = "INSTRUMENTED"
    capabilities: TargetCapabilities

class TargetResponse(BaseModel):
    id: int
    name: str
    base_url: str
    model_name: str
    target_type: str
    target_mode: str
    capabilities: TargetCapabilities
