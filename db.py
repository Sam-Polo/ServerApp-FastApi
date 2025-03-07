# db.py:
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from fastapi import Depends
from typing import Annotated


# создаем асинхронный движок для базы данных SQLite с использованием aiosqlite
engine = create_async_engine('sqlite+aiosqlite:///database.db')

# создаем фабрику для создания сессий для работы с базой данных
new_session = async_sessionmaker(engine, expire_on_commit=False)


# функция, которая предоставляет сессии для работы с базой данных
async def get_session():
    async with new_session() as session:
        yield session

SessionDep = Annotated[AsyncSession, Depends(get_session)]


class Base(DeclarativeBase):
    pass


async def setup_database():     # инициализация базы данных
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    return {'success': True}
