# main.py:
import asyncio

from info_controller import router as info_router
from auth_controller import router as auth_router, cleanup_expired_tokens
from db import setup_database, get_session, new_session

import os

from fastapi import FastAPI


os.environ["TZ"] = "Europe/Moscow"

app = FastAPI()

# подключаем маршруты из других файла
app.include_router(info_router)
app.include_router(auth_router)


async def cleanup_expired_tokens_periodically():
    """
    Периодически очищает истёкшие токены каждые две минуты
    """
    while True:
        async with new_session() as session:
            await cleanup_expired_tokens(session)
        await asyncio.sleep(120)  # время в сек.


@app.on_event("startup")
async def startup_event():
    """
    Запускает периодическую задачу при старте приложения.
    """
    _ = asyncio.create_task(cleanup_expired_tokens_periodically())


@app.post('/setup_database', tags=['База данных'])  # ручка для инициализации базы данных
async def setup_db():
    await setup_database()
    return {'msg': 'База данных успешно инициализирована'}
