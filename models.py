from pydantic import BaseModel


class ServerInfoSchema(BaseModel):
    python_version: str
    platform: str
    architecture: list | tuple
    processor: str


class ClientInfoSchema(BaseModel):
    client_ip: str
    user_agent: str


class DatabaseInfoSchema(BaseModel):
    database_type: str
