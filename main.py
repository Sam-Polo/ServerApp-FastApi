from typing import Annotated

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pydantic import BaseModel
from fastapi import FastAPI, Depends

app = FastAPI()


engine = create_async_engine('sqlite+aiosqlite:///database.db')

new_session = async_sessionmaker(engine, expire_on_commit=False)


async def get_session():
    async with new_session() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str] = mapped_column(unique=True)


@app.post("/setup_database", tags=['База данных'])
async def setup_database():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    return {'message': True}


class UserAddSchema(BaseModel):
    username: str
    email: str


class UserSchema(UserAddSchema):
    id: int


@app.post('/')
async def add_user(data: UserAddSchema, session: SessionDep):
    new_user = UserModel(
        username=data.username,
        email=data.email,
    )
    session.add(new_user)
    await session.commit()
    return {'message': True}


@app.get('/')
async def get_users(session: SessionDep):
    query = select(UserModel)
    result = await session.execute(query)
    return result.scalars().all()
