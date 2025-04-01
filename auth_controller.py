# auth_controller.py:
import hashlib
import uuid
from datetime import datetime, timedelta
import re

from fastapi import APIRouter, HTTPException, Depends, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
import jwt
from passlib.context import CryptContext

from models import (RegisterRequestSchema, AuthRequestSchema,
                    RegisterResponseSchema, AuthResponseSchema,
                    UserModel, ActiveTokenModel, RevokedTokenModel,
                    UserResponseSchema, RefreshTokenModel)
from db import SessionDep, get_session


router = APIRouter(prefix='/auth', tags=["Авторизация"])

# настройка хеширования паролей
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# извлечение токена из заголовка запроса
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')

# настройка JWT
SECRET_KEY = 'secret-asf'  # секретный ключ
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # время жизни токена в минутах
REFRESH_TOKEN_EXPIRE_DAYS = 7    # время жизни токена обновления
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

    hashed_password = hash_password(user_data.password)     # хеширование пароля перед сохранением

    #   добавление нового пользователя в БД
    new_user = UserModel(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        birthday=user_data.birthday,
    )
    session.add(new_user)
    await session.commit()

    return user_data.to_response()


@router.post('/login', response_model=AuthResponseSchema)
async def login(session: SessionDep, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Маршрут для авторизации пользователя
    принимает логин и пароль, возвращает jwt-токен
    """
    # поиск пользователя в бд
    user = await session.execute(select(UserModel).where(UserModel.username == form_data.username))
    user = user.scalar()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail='Неверное имя пользователя или пароль')

    access_token, access_jti = create_access_token(data={'sub': user.username})
    refresh_token = create_refresh_token(data={'sub': user.username})
    await add_active_token(user_id=user.id, jti=access_jti, session=session)
    await add_refresh_token(user_id=user.id, token=refresh_token, session=session)

    return AuthResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type='bearer')


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
        await session.commit()

    # Добавляем новый токен
    new_token = ActiveTokenModel(
        user_id=user_id,
        jti=jti,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    session.add(new_token)
    await session.commit()


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
    await session.commit()


async def cleanup_expired_tokens(session: SessionDep):
    """
    Удаляет истёкшие токены из таблицы active_tokens.
    """
    models = [ActiveTokenModel, RevokedTokenModel, RefreshTokenModel]
    for model in models:
        await session.execute(delete(model).where(model.expires_at < datetime.utcnow()))
    await session.commit()


@router.get('/tokens')
async def get_active_tokens(session: SessionDep, token: str = Depends(oauth2_scheme),
):
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
    token_list = []
    for t in active_tokens:
        # формируем payload для токена
        token_payload = {
            'sub': user.username,
            'exp': t.expires_at,
            'jti': t.jti
        }
        # кодируем токен
        reconstructed_token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)
        token_list.append({
            'token': reconstructed_token,
            'created_at': t.created_at,
            'expires_at': t.expires_at,
        })

    return token_list


@router.post('/out')
async def logout(session: SessionDep, token: str = Depends(oauth2_scheme)):
    """
    Маршрут для разлогирования пользователя.
    Отзывает текущий токен доступа.
    """
    # проверяем валидность токена
    payload = await verify_token(token, session)

    jti = payload['jti']

    # проверяем, не отозван ли токен уже
    existing_token = await session.execute(
        select(RevokedTokenModel).where(RevokedTokenModel.jti == jti)
    )
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
    await session.commit()

    return {'message': 'Вы успешно разлогинились'}


@router.post('/out_all')
async def revoke_all_tokens(session: SessionDep, token: str = Depends(oauth2_scheme)):
    """
    Маршрут для отзыва всех активных токенов пользователя.
    """
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

    # отзываем все refresh-токены
    await session.execute(delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id))

    await session.commit()
    return {'message': 'Все токены успешно отозваны'}


@router.post('/refresh', response_model=AuthResponseSchema)
async def refresh_token(session: SessionDep, refresh_token: str = Body(..., embed=True)):
    """
    Маршрут для обновления access-токена с помощью refresh-токена
    """
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
    user = await session.execute(select(UserModel).where(UserModel.username == payload['sub']))
    user = user.scalar()

    if not user:
        raise HTTPException(status_code=404, detail='Пользователь не найден')
    return UserResponseSchema(
        id=user.id,
        username=user.username,
        email=user.email,
        birthday=user.birthday.strftime('%Y-%m-%d'),
        role=user.role,
    )


@router.post('/change_password')
async def change_password(
    session: SessionDep,
    old_password: str,
    new_password: str,
    token: str = Depends(oauth2_scheme),
):
    """
    Маршрут для смены пароля
    """
    payload = await verify_token(token, session)
    user = await session.execute(select(UserModel).where(UserModel.username == payload['sub']))
    user = user.scalar()

    if not user or not verify_password(old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail='Старый пароль неверный')

    if not validate_password(new_password):
        raise HTTPException(status_code=400, detail='Новый пароль не соответствует требованиям')

    user.hashed_password = hash_password(new_password)
    await session.commit()

    return {'message': 'Пароль успешно изменен'}
