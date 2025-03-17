# db.py:
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from fastapi import Depends, APIRouter
from typing import Annotated

DATABASE_URL = 'sqlite+aiosqlite:///database.db'


# создаем асинхронный движок для базы данных SQLite с использованием aiosqlite
engine = create_async_engine(DATABASE_URL)

# создаем фабрику для создания сессий для работы с базой данных
new_session = async_sessionmaker(engine, expire_on_commit=False)


# функция, которая предоставляет сессии для работы с базой данных
async def get_session():
    async with new_session() as session:
        yield session

SessionDep = Annotated[AsyncSession, Depends(get_session)]

router = APIRouter(prefix='/database', tags=['База данных'])


class Base(DeclarativeBase):
    pass


@router.post('/setup')
async def setup_database():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    return {'success': True, 'message': 'БД инициализирована'}


@router.post('/create_tables')
async def create_tables():
    """
    Создание таблиц в базе данных (без удаления существующих)
    """
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return {'success': True, 'message': 'Таблицы созданы'}


@router.post('/drop_tables')
async def drop_tables():
    """
    Удаление всех таблиц из базы данных
    """
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
    return {'success': True, 'message': 'Все таблицы удалены'}
