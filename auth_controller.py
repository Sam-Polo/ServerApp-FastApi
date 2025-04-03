# auth_controller.py:
import asyncio
import hashlib
import os
import random
import uuid
from datetime import datetime, timedelta
import re
from typing import Union

from fastapi import APIRouter, HTTPException, Depends, Body, Request, Path
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import select, delete
import jwt
from passlib.context import CryptContext
from sqlalchemy.orm import selectinload

from models import (RegisterRequestSchema, AuthRequestSchema,
                    RegisterResponseSchema, AuthResponseSchema,
                    UserModel, ActiveTokenModel, RevokedTokenModel,
                    UserResponseSchema, RefreshTokenModel, RoleModel, TemporaryTokenModel, TwoFactorCodeModel,
                    TemporaryTokenResponse)
from db import SessionDep
from utils import log_mutation

router = APIRouter(prefix='/auth', tags=['Авторизация'])

# настройка хеширования паролей
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# извлечение токена из заголовка запроса
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')

# настройка JWT
SECRET_KEY = 'secret-asf'  # секретный ключ
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # время жизни токена в минутах
REFRESH_TOKEN_EXPIRE_DAYS = 7  # время жизни токена обновления
MAX_ACTIVE_TOKENS_PER_USER = 5  # макс. кол-во активных токенов


def hash_password(password: str) -> str:
    """
    Хеширует пароль с использованием bcrypt.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет, соответствует ли plain_password хешированному паролю.
    """
    return pwd_context.verify(plain_password, hashed_password)


def validate_username(username: str) -> bool:
    """
    Требования к username:
    - только латинские буквы
    - начинается с большой буквы
    - минимальная длина 7 символов
    """
    return bool(re.match(r'^[A-Z][a-zA-Z]{6,31}$', username))


def validate_email(email: str) -> bool:
    """
    email-формат.
    """
    return bool(re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email))


def validate_password(password: str) -> bool:
    """
    Требования к password:
    - минимальная длина 8 символов
    - содержит не менее 1 цифры
    - содержит не менее 1 символа
    - содержит не менее чем по 1 символу в верхнем и нижнем регистре
    """
    return bool(re.match(r'^(?=.*[0-9])(?=.*[^a-zA-Z0-9])(?=.*[A-Z])(?=.*[a-z]).{8,32}$', password))


@router.post('/register', status_code=201, response_model=RegisterResponseSchema)
async def register(user_data: RegisterRequestSchema, session: SessionDep):
    """
    Маршрут для регистрации пользователя.
    Принимает данные о пользователе и возвращает сообщение об успешной регистрации.
    """
    async with session.begin_nested():  # одна транзакция (автоматически коммитится при успешном выходе из блока)
        user_data.email = user_data.email.lower()

        # проверка username
        if not validate_username(user_data.username):
            raise HTTPException(
                status_code=400,
                detail='Имя пользователя должно содержать только латинские буквы, '
                       'начинаться с большой буквы и иметь длину не менее 7 символов.'
            )

        # проверка email
        if not validate_email(user_data.email):
            raise HTTPException(
                status_code=400,
                detail='Некорректный формат email.'
            )

        # проверка password
        if not validate_password(user_data.password):
            raise HTTPException(
                status_code=400,
                detail='Пароль должен содержать минимум 8 символов, '
                       'хотя бы одну цифру, один символ и буквы в верхнем и нижнем регистре.'
            )

        # проверка совпадения паролей
        if user_data.password != user_data.c_password:
            raise HTTPException(status_code=400,
                                detail='Пароли не совпадают')

        # проверка на существующего пользователя или email
        existing_user = await session.execute(
            select(UserModel).where(
                (UserModel.username == user_data.username) | (UserModel.email == user_data.email)
            )
        )
        if existing_user.scalar():
            raise HTTPException(status_code=400,
                                detail='Пользователь с таким именем или email уже существует')

        hashed_password = hash_password(user_data.password)  # хеширование пароля перед сохранением

        #   добавление нового пользователя в БД
        new_user = UserModel(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            birthday=user_data.birthday,
            is_2fa_enabled=False,
        )
        session.add(new_user)
        await session.flush()

        # логируем создание пользователя
        new_value = {
            'username': new_user.username,
            'email': new_user.email,
            'birthday': new_user.birthday.isoformat(),
            'role_ids': []
        }
        await log_mutation(
            session=session,
            entity_type='user',
            entity_id=new_user.id,
            operation='create',
            old_value=None,
            new_value=new_value,
            user_id=new_user.id,
        )

    return user_data.to_response()


@router.post('/login', response_model=Union[AuthResponseSchema, TemporaryTokenResponse])
async def login(session: SessionDep, request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Маршрут для авторизации пользователя
    принимает логин и пароль, возвращает jwt-токен
    """
    async with session.begin_nested():
        # поиск пользователя в бд
        user = await session.execute(select(UserModel).where(UserModel.username == form_data.username))
        user = user.scalar()

        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail='Неверное имя пользователя или пароль')

        if not user.is_2fa_enabled:
            # Если 2FA выключена, выдаём полноценные токены
            access_token, access_jti = create_access_token(data={'sub': user.username})
            refresh_token = create_refresh_token(data={'sub': user.username})
            await add_active_token(user.id, access_jti, session)
            await add_refresh_token(user.id, refresh_token, session)

            await session.flush()

            return AuthResponseSchema(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type='bearer'
            )
        else:
            # Если 2FA включена, выдаём временный токен
            temp_token = create_temporary_token(user.id)
            payload = jwt.decode(temp_token, SECRET_KEY, algorithms=[ALGORITHM])  # Декодируем для получения exp
            expire = datetime.fromtimestamp(payload['exp'])  # Преобразуем exp в datetime
            temp_token_model = TemporaryTokenModel(
                user_id=user.id,
                token=temp_token,
                expires_at=expire
            )

            session.add(temp_token_model)
            await session.flush()
            await session.refresh(temp_token_model)
            return {"temporary_token": temp_token, "message": "Требуется код 2FA. Запросите его через /auth/2fa/request"}


@router.post('/2fa/generate', response_model=dict)
async def generate_2fa_code(
    session: SessionDep,
    request: Request,
    temp_token: str = Body(...),
):
    """
    Запрос нового кода 2FA
    """
    async with session.begin():
        # Проверяем временный токен
        try:
            payload = jwt.decode(temp_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get('type') != 'temporary':
                raise HTTPException(status_code=400, detail="Неверный тип токена")
            user_id = int(payload['sub'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            raise HTTPException(status_code=401, detail="Временный токен истёк или недействителен")

        stmt = select(TemporaryTokenModel).where(
            TemporaryTokenModel.token == temp_token,
            TemporaryTokenModel.user_id == user_id,
            TemporaryTokenModel.is_used == False,
            TemporaryTokenModel.expires_at > datetime.utcnow()
        )
        temp_token_record = (await session.execute(stmt)).scalar_one_or_none()
        if not temp_token_record:
            raise HTTPException(status_code=400, detail="Временный токен недействителен")

        # Проверяем существующий код
        user_agent_hash = hashlib.sha256(request.headers.get('User-Agent', '').encode()).hexdigest()
        stmt = select(TwoFactorCodeModel).where(
            TwoFactorCodeModel.user_id == user_id,
            TwoFactorCodeModel.user_agent_hash == user_agent_hash
        )
        existing_code = (await session.execute(stmt)).scalar_one_or_none()

        if existing_code and existing_code.request_count >= 3:
            await asyncio.sleep(30)  # Задержка 30 секунд при >3 запросах

        # Генерируем новый код
        new_code = str(random.randint(100000, 999999))
        expiry_minutes = int(os.getenv('TWO_FACTOR_CODE_EXPIRY_MINUTES', 5))
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)

        if existing_code:
            existing_code.code = new_code
            existing_code.expires_at = expires_at
            existing_code.is_used = False
            existing_code.request_count += 1
        else:
            new_2fa = TwoFactorCodeModel(
                user_id=user_id,
                code=new_code,
                user_agent_hash=user_agent_hash,
                expires_at=expires_at,
                request_count=1
            )
            session.add(new_2fa)

        await session.flush()
        return {"code": new_code}


@router.post('/2fa/verify', response_model=AuthResponseSchema)
async def verify_2fa_code(
    session: SessionDep,
    request: Request,
    temp_token: str = Body(...),
    two_factor_code: str = Body(...),
):
    """Подтверждение кода 2FA и выдача полноценных токенов"""
    async with session.begin():
        # Проверяем временный токен
        try:
            payload = jwt.decode(temp_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get('type') != 'temporary':
                raise HTTPException(status_code=400, detail="Неверный тип токена")
            user_id = int(payload['sub'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            raise HTTPException(status_code=401, detail="Временный токен истёк или недействителен")

        stmt = select(TemporaryTokenModel).where(
            TemporaryTokenModel.token == temp_token,
            TemporaryTokenModel.user_id == user_id,
            TemporaryTokenModel.is_used == False,
            TemporaryTokenModel.expires_at > datetime.utcnow()
        )
        temp_token_record = (await session.execute(stmt)).scalar_one_or_none()
        if not temp_token_record:
            raise HTTPException(status_code=400, detail="Временный токен недействителен")

        # Проверяем 2FA-код
        user_agent_hash = hashlib.sha256(request.headers.get('User-Agent', '').encode()).hexdigest()
        stmt = select(TwoFactorCodeModel).where(
            TwoFactorCodeModel.user_id == user_id,
            TwoFactorCodeModel.user_agent_hash == user_agent_hash,
            TwoFactorCodeModel.code == two_factor_code,
            TwoFactorCodeModel.is_used == False,
            TwoFactorCodeModel.expires_at > datetime.utcnow()
        )
        code_record = (await session.execute(stmt)).scalar_one_or_none()

        if not code_record:
            raise HTTPException(status_code=400, detail="Неверный или истёкший код 2FA")

        # Помечаем временный токен и код как использованные
        temp_token_record.is_used = True
        code_record.is_used = True

        # Выдаём полноценные токены
        user = await session.get(UserModel, user_id)
        access_token, access_jti = create_access_token(data={'sub': user.username})
        refresh_token = create_refresh_token(data={'sub': user.username})
        await add_active_token(user.id, access_jti, session)
        await add_refresh_token(user.id, refresh_token, session)
        await session.commit()

        return AuthResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type='bearer'
        )


def create_refresh_token(data: dict) -> str:
    """
    Создает refresh-токен на основе переданных данных
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_access_token(data: dict) -> tuple[str, str]:
    """
    Создает JWT-токен на основе переданных данных.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    to_encode.update({'exp': expire, 'jti': jti})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, jti


def create_temporary_token(user_id: int) -> str:
    """
    Создаёт временный токен для 2FA
    """
    expire = datetime.utcnow() + timedelta(minutes=5)  # временный токен живёт 5 минут
    jti = str(uuid.uuid4())
    payload = {'sub': str(user_id), 'exp': expire, 'jti': jti, 'type': 'temporary'}

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def verify_token(token: str, session: SessionDep):
    """
    Проверяет JWT-токен и возвращает его payload, если токен валиден.
    Также проверяет, не отозван ли токен.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail='Токен истёк',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail='Неверный токен',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    jti = payload.get('jti')
    if not jti:
        raise HTTPException(
            status_code=401,
            detail='Токен не содержит jti',
            headers={'WWW-Authenticate': 'Bearer'}
        )

    # чек, не отозван ли токен
    revoked_token = await session.execute(
        select(RevokedTokenModel).where(RevokedTokenModel.jti == jti)
    )
    if revoked_token.scalar():
        raise HTTPException(
            status_code=401,
            detail='Токен отозван',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    # получаем пользователя по имени из payload
    user = await session.execute(
        select(UserModel).where(UserModel.username == payload['sub'])
    )
    user = user.scalar()
    if not user:
        raise HTTPException(status_code=404, detail='Пользователь не найден')

    # если 2FA включена, проверяем, что это не временный токен
    if user.is_2fa_enabled and payload.get('type') == 'temporary':
        raise HTTPException(status_code=403, detail='Требуется подтверждение 2FA')

    return payload


async def add_active_token(user_id: int, jti: str, session: SessionDep):
    """
    Добавляет новый активный токен для пользователя.
    Если количество токенов превышает лимит, удаляет самый старый токен.
    """
    # получаем текущие активные токены пользователя
    active_tokens = await session.execute(
        select(ActiveTokenModel)
        .where(ActiveTokenModel.user_id == user_id)
        .order_by(ActiveTokenModel.created_at)
    )
    active_tokens = active_tokens.scalars().all()

    # если достигнут лимит, удаляем самый старый токен
    if len(active_tokens) >= MAX_ACTIVE_TOKENS_PER_USER:
        oldest_token = active_tokens[0]
        await session.delete(oldest_token)
        await session.flush()

    # Добавляем новый токен
    new_token = ActiveTokenModel(
        user_id=user_id,
        jti=jti,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    session.add(new_token)
    await session.flush()


async def add_refresh_token(user_id: int, token: str, session: SessionDep):
    """
    Добавляет новый токен обновления в БД
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    new_token = RefreshTokenModel(
        user_id=user_id,
        token_hash=token_hash,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    session.add(new_token)
    await session.flush()


@router.get('/tokens')
async def get_active_tokens(session: SessionDep, token: str = Depends(oauth2_scheme)):
    """
    Маршрут для получения списка активных токенов пользователя.
    """
    payload = await verify_token(token, session)
    user = await session.execute(select(UserModel).where(UserModel.username == payload['sub']))
    user = user.scalar()

    if not user:
        raise HTTPException(status_code=404, detail='Пользователь не найден')

    active_tokens = await session.execute(
        select(ActiveTokenModel).where(ActiveTokenModel.user_id == user.id)
    )
    active_tokens = active_tokens.scalars().all()

    # собираем токены заново на основе данных из базы
    token_list = [
        {
            'token': jwt.encode(
                {'sub': user.username, 'exp': t.expires_at, 'jti': t.jti},
                SECRET_KEY,
                algorithm=ALGORITHM
            ),
            'created_at': t.created_at,
            'expires_at': t.expires_at,
        }
        for t in active_tokens
    ]
    return token_list


async def cleanup_expired_tokens(session: SessionDep):
    """
    Удаляет истёкшие токены из таблицы active_tokens.
    """
    models = [ActiveTokenModel, RevokedTokenModel, RefreshTokenModel]
    for model in models:
        await session.execute(delete(model).where(model.expires_at < datetime.utcnow()))
    await session.commit()


@router.post('/out')
async def logout(session: SessionDep, token: str = Depends(oauth2_scheme)):
    """
    Маршрут для разлогирования пользователя.
    Отзывает текущий токен доступа.
    """
    async with session.begin():
        # проверяем валидность токена
        payload = await verify_token(token, session)
        jti = payload['jti']

        # проверяем, не отозван ли токен уже
        existing_token = await session.execute(select(RevokedTokenModel).where(RevokedTokenModel.jti == jti))
        if existing_token.scalar():
            raise HTTPException(status_code=400, detail='Токен уже отозван')

        # добавляем токен в список отозванных
        revoked_token = RevokedTokenModel(
            jti=jti,
            expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        session.add(revoked_token)

        # удаляем из активных токенов
        await session.execute(delete(ActiveTokenModel).where(ActiveTokenModel.jti == jti))

    return {'message': 'Вы успешно разлогинились'}


@router.post('/out_all')
async def revoke_all_tokens(session: SessionDep, token: str = Depends(oauth2_scheme)):
    """
    Маршрут для отзыва всех активных токенов пользователя.
    """
    async with session.begin():
        payload = await verify_token(token, session)
        user = await session.execute(select(UserModel).where(UserModel.username == payload['sub']))
        user = user.scalar()

        if not user:
            raise HTTPException(status_code=404, detail='Пользователь не найден')

        # отзываем все access-токены
        active_tokens = await session.execute(
            select(ActiveTokenModel).where(ActiveTokenModel.user_id == user.id)
        )
        active_tokens = active_tokens.scalars().all()
        for t in active_tokens:
            session.add(RevokedTokenModel(
                jti=t.jti,
                expires_at=t.expires_at
            ))
        await session.execute(delete(ActiveTokenModel).where(ActiveTokenModel.user_id == user.id))
        await session.execute(delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id))

    return {'message': 'Все токены успешно отозваны'}


@router.post('/refresh', response_model=AuthResponseSchema)
async def refresh_token(session: SessionDep, refresh_token: str = Body(..., embed=True)):
    """
    Маршрут для обновления access-токена с помощью refresh-токена
    """
    async with session.begin():
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Refresh-токен истёк')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Неверный refresh-токен')

        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        # проверяем, существует ли refresh-токен в базе
        token_in_db = await session.execute(
            select(RefreshTokenModel).where(RefreshTokenModel.token_hash == token_hash)
        )
        token_in_db = token_in_db.scalar()
        if not token_in_db or token_in_db.expires_at < datetime.utcnow():
            raise HTTPException(status_code=401, detail='Refresh-токен недействителен или истёк')

        # получаем пользователя
        user = await session.execute(
            select(UserModel).where(UserModel.username == payload['sub'])
        )
        user = user.scalar()
        if not user:
            raise HTTPException(status_code=404, detail='Пользователь не найден')

        # генерируем новый access-токен
        new_access_token, new_jti = create_access_token(data={'sub': user.username})
        await add_active_token(user_id=user.id, jti=new_jti, session=session)

    # возвращаем оба токена (refresh_token остаётся тем же)
    return AuthResponseSchema(
        access_token=new_access_token,
        refresh_token=refresh_token,
        token_type='bearer'
    )


@router.get('/me', response_model=UserResponseSchema)
async def get_my_info(session: SessionDep, token: str = Depends(oauth2_scheme)):
    """
    Маршрут для получения информации о пользователе
    """
    payload = await verify_token(token, session)
    stmt = select(UserModel).where(UserModel.username == payload['sub']).options(
        selectinload(UserModel.roles)
    )
    user = (await session.execute(stmt)).scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail='Пользователь не найден')

    return UserResponseSchema(
        id=user.id,
        username=user.username,
        email=user.email,
        birthday=user.birthday,
        role_ids=[role.id for role in user.roles]  # Список ID ролей
    )


@router.post('/change_password')
async def change_password(
        session: SessionDep,
        old_password: str = Body(...),
        new_password: str = Body(...),
        token: str = Depends(oauth2_scheme),
):
    """
    Маршрут для смены пароля
    """
    async with session.begin():
        payload = await verify_token(token, session)
        user = await session.execute(select(UserModel).where(UserModel.username == payload['sub']))
        user = user.scalar()
        if not user or not verify_password(old_password, user.hashed_password):
            raise HTTPException(status_code=400, detail='Старый пароль неверный')

        if not validate_password(new_password):
            raise HTTPException(status_code=400, detail='Новый пароль не соответствует требованиям')

        old_value = {'hashed_password': 'hidden'}
        user.hashed_password = hash_password(new_password)
        new_value = {'hashed_password': 'hidden'}

        await log_mutation(
            session=session,
            entity_type='user',
            entity_id=user.id,
            operation='update',
            old_value=old_value,
            new_value=new_value,
            user_id=user.id,
        )

    return {'message': 'Пароль успешно изменен'}


async def get_current_user(session: SessionDep, token: str = Depends(oauth2_scheme)) -> UserModel:
    """
    Получение текущего пользователя по токену
    """
    # проверяем валидность токена и получаем payload
    payload = await verify_token(token, session)

    # извлекаем jti из payload
    jti = payload.get('jti')
    if not jti:
        raise HTTPException(
            status_code=401,
            detail='Токен не содержит jti',
            headers={'WWW-Authenticate': 'Bearer'}
        )

    # ищем пользователя по username из payload
    stmt = select(UserModel).where(UserModel.username == payload['sub']).options(
        selectinload(UserModel.roles).selectinload(RoleModel.permissions)  # загружаем роли и разрешения
    )
    user = (await session.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=401,
            detail='Пользователь не найден',
            headers={'WWW-Authenticate': 'Bearer'}
        )

    # проверяем, что токен активен
    stmt_token = select(ActiveTokenModel).where(ActiveTokenModel.jti == jti)
    active_token = (await session.execute(stmt_token)).scalar_one_or_none()
    if not active_token or active_token.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=401,
            detail='Токен недействителен или истёк',
            headers={'WWW-Authenticate': 'Bearer'}
        )

    return user


async def check_permission(
        permission_code: str,
        session: SessionDep,
        current_user: UserModel = Depends(get_current_user)
) -> UserModel:
    """
    Проверка наличия разрешения у текущего пользователя
    """
    if not current_user.roles:
        raise HTTPException(status_code=403, detail='У пользователя нет роли')

    # проверяем, есть ли нужное разрешение хотя бы в одной роли
    has_permission = any(
        any(perm.code == permission_code for perm in role.permissions)
        for role in current_user.roles if role.deleted_at is None
    )
    if not has_permission:
        raise HTTPException(status_code=403, detail=f'Нет разрешения "{permission_code}"')

    return current_user


# фабрика зависимостей
def require_permission(permission_code: str):
    """
    Создаёт зависимость для проверки конкретного разрешения
    """
    async def permission_dependency(session: SessionDep, current_user: UserModel = Depends(get_current_user)):
        return await check_permission(permission_code, session, current_user)

    return permission_dependency


@router.post('/2fa/toggle', response_model=dict)
async def toggle_2fa(
    session: SessionDep,
    enabled: bool = Body(...),
    password: str = Body(...),
    current_user: UserModel = Depends(get_current_user)
):
    """
    Включение/отключение 2FA
    """
    async with session.begin_nested():
        if not verify_password(password, current_user.hashed_password):
            raise HTTPException(status_code=400, detail="Неверный пароль")

        old_value = {"is_2fa_enabled": current_user.is_2fa_enabled}
        current_user.is_2fa_enabled = enabled
        new_value = {"is_2fa_enabled": enabled}

        await log_mutation(
            session=session,
            entity_type='user',
            entity_id=current_user.id,
            operation='update',
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id
        )
    await session.flush()

    return {"message": f"2FA {'включена' if enabled else 'отключена'}"}

