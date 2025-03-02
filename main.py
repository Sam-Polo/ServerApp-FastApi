from info_controller import router as info_router

import os

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from fastapi import FastAPI


os.environ["TZ"] = "Europe/Moscow"

app = FastAPI()

# подключаем маршруты из другого файла
app.include_router(info_router)

# создаем асинхронный движок для базы данных SQLite с использованием aiosqlite
engine = create_async_engine('sqlite+aiosqlite:///database.db')

# создаем фабрику для создания сессий для работы с базой данных
new_session = async_sessionmaker(engine, expire_on_commit=False)


# функция, которая предоставляет сессии для работы с базой данных
async def get_session():
    async with new_session() as session:
        yield session


class Base(DeclarativeBase):
    pass


# ручка для настройки базы данных
@app.post("/setup_database", tags=['База данных'])
async def setup_database():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    return {'message': True}
