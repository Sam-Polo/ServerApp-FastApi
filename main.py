# main.py:
import asyncio

from info_controller import router as info_router
from auth_controller import router as auth_router, cleanup_expired_tokens
from roles_controller import roles_router, logs_router
from seed import router as seed_router

from db import new_session, router as db_router
from auth_controller import ACCESS_TOKEN_EXPIRE_MINUTES

import os

from fastapi import FastAPI

os.environ["TZ"] = "Europe/Moscow"

app = FastAPI()

# подключаем маршруты из других файла
app.include_router(info_router)
app.include_router(auth_router)
app.include_router(roles_router)
app.include_router(logs_router)
app.include_router(seed_router)
app.include_router(db_router)


async def cleanup_expired_tokens_periodically():
    """
    Периодически очищает истёкшие токены каждые две минуты
    """
    while True:
        async with new_session() as session:
            await cleanup_expired_tokens(session)
        await asyncio.sleep(ACCESS_TOKEN_EXPIRE_MINUTES * 60)  # время в сек.


@app.on_event('startup')
async def startup_event():
    """
    Запускает периодическую задачу при старте приложения.
    """
    _ = asyncio.create_task(cleanup_expired_tokens_periodically())

