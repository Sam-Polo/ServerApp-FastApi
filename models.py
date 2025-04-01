# models.py:
from datetime import datetime, date
from pydantic import BaseModel
from sqlalchemy import String, Integer, Date, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from db import Base


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


class AuthRequestSchema(BaseModel):
    username: str
    password: str  # пароль пользователя

    def to_response(self, token, ttype: str):
        return AuthResponseSchema(access_token=token, token_type=ttype)


class RegisterRequestSchema(BaseModel):
    username: str
    password: str
    c_password: str  # подтверждение пароля
    email: str
    birthday: date

    def to_response(self):
        return RegisterResponseSchema(username=self.username, message='Регистрация успешна')


class AuthResponseSchema(BaseModel):
    access_token: str  # токен доступа
    refresh_token: str  # токен обновления
    token_type: str    # тип токена (по умолчанию bearer)


class RegisterResponseSchema(BaseModel):
    username: str
    message: str  # сообщение об успешной регистрации


class UserResponseSchema(BaseModel):
    id: int
    username: str
    email: str
    birthday: str
    role: str | None


class UserModel(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    email: Mapped[str] = mapped_column(String(64), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    birthday: Mapped[datetime] = mapped_column(Date)
    role: Mapped[str | None]


class ActiveTokenModel(Base):
    __tablename__ = 'active_tokens'

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    jti: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)


class RevokedTokenModel(Base):
    __tablename__ = 'revoked_tokens'

    id: Mapped[int] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)


class RefreshTokenModel(Base):
    __tablename__ = 'refresh_tokens'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
