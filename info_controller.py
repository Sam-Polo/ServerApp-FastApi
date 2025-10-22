from models import ServerInfoSchema, ClientInfoSchema, DatabaseInfoSchema

from fastapi import APIRouter, Request
import platform

router = APIRouter()


@router.get("/info/server", tags=['Инфо'])
def get_server_info():
    server_info = ServerInfoSchema(
        python_version=platform.python_version(),
        platform=platform.system(),
        architecture=platform.architecture(),
        processor=platform.processor()
    )
    return server_info


@router.get("/info/client", tags=['Инфо'])
async def get_client_info(request: Request):
    client_info = ClientInfoSchema(
        client_ip=request.client.host,
        user_agent=request.headers.get('User-Agent'),
    )
    return client_info


@router.get("/info/database", tags=['Инфо'])
def get_database_info():
    database_info = DatabaseInfoSchema(
        database_type='SQLAlchemy',
    )
    return database_info

