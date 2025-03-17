# models.py:
from datetime import datetime, date
from typing import Optional

from pydantic import BaseModel, ConfigDict
import sqlalchemy
from sqlalchemy import String, Integer, Date, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

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

    def to_response(self, token, ttype: str) -> 'AuthResponseSchema':
        return AuthResponseSchema(access_token=token, token_type=ttype)


class RegisterRequestSchema(BaseModel):
    username: str
    password: str
    c_password: str  # подтверждение пароля
    email: str
    birthday: date

    def to_response(self) -> 'RegisterResponseSchema':
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
    birthday: date
    role_id: int | None = None

    model_config = ConfigDict(from_attributes=True)


class UserCollectionSchema(BaseModel):
    users: list[UserResponseSchema]


class PermissionSchema(BaseModel):
    id: int
    name: str
    code: str
    description: str | None
    created_at: datetime
    created_by: int

    class Config:
        from_attributes = True


class CreatePermissionRequestSchema(BaseModel):
    name: str
    code: str
    description: str | None = None

    def to_response(self, permission: 'PermissionModel') -> PermissionSchema:
        return PermissionSchema.model_validate(permission)


class PermissionCollectionSchema(BaseModel):
    permissions: list[PermissionSchema]


class RoleSchema(BaseModel):
    id: int
    name: str
    description: str | None
    code: str
    created_at: datetime
    created_by: int
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[int] = None
    permissions: list[PermissionSchema] = []

    model_config = ConfigDict(from_attributes=True)


class RoleCollectionSchema(BaseModel):
    roles: list[RoleSchema]


class CreateRoleRequestSchema(BaseModel):
    name: str
    description: str | None = None
    code: str

    def to_response(self, role: 'RoleModel') -> RoleSchema:
        return RoleSchema.model_validate(role)


class UpdateRoleRequestSchema(BaseModel):
    """Схема запроса обновления роли"""
    name: str | None = None
    description: str | None = None
    code: str | None = None

    def to_response(self, role: 'RoleModel') -> 'RoleSchema':
        """Преобразование запроса в схему ответа"""
        return RoleSchema(
            id=role.id,
            name=self.name if self.name is not None else role.name,
            description=self.description,
            code=self.code if self.code is not None else role.code,
            created_at=role.created_at,
            created_by=role.created_by,
            deleted_at=role.deleted_at,
            deleted_by=role.deleted_by
        )


class AssignRoleRequestSchema(BaseModel):
    role_id: int


class UserModel(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    email: Mapped[str] = mapped_column(String(64), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    birthday: Mapped[datetime] = mapped_column(Date)
    role_id: Mapped[int | None] = mapped_column(Integer, ForeignKey('roles.id', use_alter=True), nullable=True)  # связь с RoleModel

    # отношение к роли
    role = relationship('RoleModel', back_populates='users', foreign_keys=[role_id])

    def __repr__(self) -> str:
        return f'<UserModel(id={self.id}, username={self.username!r})>'


class ActiveTokenModel(Base):
    __tablename__ = 'active_tokens'

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    token: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)


class RevokedTokenModel(Base):
    __tablename__ = 'revoked_tokens'

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)


class RefreshTokenModel(Base):
    __tablename__ = 'refresh_tokens'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    token: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)


class RoleModel(Base):
    __tablename__ = 'roles'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    code: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False, server_default=sqlalchemy.func.now())
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey('users.id', use_alter=True), nullable=True)
    deleted_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    deleted_by: Mapped[int | None] = mapped_column(Integer, ForeignKey('users.id', use_alter=True), nullable=True)

    users = relationship('UserModel', back_populates='role', foreign_keys=[UserModel.role_id])
    permissions = relationship('PermissionModel',
                               secondary='role_permissions',
                               back_populates='roles')

    def __repr__(self) -> str:
        return f'<RoleModel(id={self.id}, name={self.name!r})>'


class PermissionModel(Base):
    __tablename__ = 'permissions'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    code: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=sqlalchemy.func.now())
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deleted_by: Mapped[int | None] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)

    # связь с ролями через таблицу role_permissions
    roles = relationship('RoleModel',
                         secondary='role_permissions',
                         back_populates='permissions')

    def __repr__(self) -> str:
        return f'<PermissionModel(id={self.id}, code={self.code!r})>'


class RolePermissionModel(Base):
    __tablename__ = 'role_permissions'

    role_id: Mapped[int] = mapped_column(Integer, ForeignKey('roles.id'), primary_key=True)
    permission_id: Mapped[int] = mapped_column(Integer, ForeignKey('permissions.id'), primary_key=True)
