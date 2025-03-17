from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from auth_controller import hash_password
from models import RoleModel, PermissionModel, UserModel
from db import setup_database, SessionDep
from datetime import datetime


router = APIRouter(tags=['База данных'])


@router.post("/seed", response_model=dict)
async def run_seed(session: SessionDep):
    # чистка БД
    await setup_database()

    # список ролей
    roles = [
        {'name': 'Admin', 'description': 'администратор', 'code': 'admin'},
        {'name': 'User', 'description': 'обычный пользователь', 'code': 'user'},
        {'name': 'Guest', 'description': 'гость', 'code': 'guest'},
    ]

    # добавляем роли и сохраняем их ID
    for role_data in roles:
        stmt = select(RoleModel).where(RoleModel.code == role_data['code'])
        result = await session.execute(stmt)
        role = result.scalar_one_or_none()
        if not role:
            role = RoleModel(
                name=role_data['name'],
                description=role_data['description'],
                code=role_data['code'],
                created_by=None,  # Пока нет админа, ставим None
                created_at=datetime.utcnow()
            )
            session.add(role)
    await session.commit()

    # получаем роли после создания
    admin_role = (await session.execute(select(RoleModel).where(RoleModel.code == 'admin'))).scalar_one()
    user_role = (await session.execute(select(RoleModel).where(RoleModel.code == 'user'))).scalar_one()
    guest_role = (await session.execute(select(RoleModel).where(RoleModel.code == 'guest'))).scalar_one()

    # пользователь Aleksandr (админ)
    stmt_user = select(UserModel).where(UserModel.username == 'Aleksandr')
    result_user = await session.execute(stmt_user)
    if not result_user.scalar_one_or_none():
        user = UserModel(
            username='Aleksandr',
            email='alex@mail.ru',
            hashed_password=hash_password('String1234!'),
            birthday=datetime.utcnow(),
            role_id=admin_role.id  # Назначаем роль Admin сразу
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        admin_id = user.id
    else:
        admin_id = (await session.execute(select(UserModel).where(UserModel.username == 'Aleksandr'))).scalar_one().id

    # обновляем created_by для ролей, теперь когда есть admin_id
    for role in [admin_role, user_role, guest_role]:
        if role.created_by is None:
            role.created_by = admin_id
    await session.commit()

    # пользователь Useruser (обычный пользователь)
    stmt_useruser = select(UserModel).where(UserModel.username == 'Useruser')
    result_useruser = await session.execute(stmt_useruser)
    if not result_useruser.scalar_one_or_none():
        useruser = UserModel(
            username='Useruser',
            email='useruser@mail.ru',
            hashed_password=hash_password('String1234!'),
            birthday=datetime.utcnow(),
            role_id=user_role.id  # Назначаем роль User сразу
        )
        session.add(useruser)

    await session.commit()

    # список разрешений
    entities = ['user', 'role', 'permission']
    permissions = [
        {'name': 'Просмотр роли пользователя', 'code': 'view-user-role', 'description': 'Разрешение на просмотр роли пользователя'},
        {'name': 'Назначение роли пользователю', 'code': 'assign-role', 'description': 'Разрешение на назначение роли пользователю'},
    ]
    for entity in entities:
        permissions.extend([
            {'name': f'Получение списка {entity}', 'code': f'get-list-{entity}', 'description': f'Разрешение на получение списка {entity}'},
            {'name': f'Чтение {entity}', 'code': f'read-{entity}', 'description': f'Разрешение на чтение {entity}'},
            {'name': f'Создание {entity}', 'code': f'create-{entity}', 'description': f'Разрешение на создание {entity}'},
            {'name': f'Обновление {entity}', 'code': f'update-{entity}', 'description': f'Разрешение на обновление {entity}'},
            {'name': f'Удаление {entity}', 'code': f'delete-{entity}', 'description': f'Разрешение на удаление {entity}'},
            {'name': f'Восстановление {entity}', 'code': f'restore-{entity}', 'description': f'Разрешение на восстановление {entity}'}
        ])

    # добавляем разрешения
    for perm_data in permissions:
        stmt = select(PermissionModel).where(PermissionModel.code == perm_data['code'])
        result = await session.execute(stmt)
        if not result.scalar_one_or_none():
            perm = PermissionModel(
                name=perm_data['name'],
                code=perm_data['code'],
                description=perm_data['description'],
                created_by=admin_id,
                created_at=datetime.utcnow()
            )
            session.add(perm)
    await session.commit()

    # привязываем разрешения к ролям
    # Admin: все разрешения
    stmt_admin = select(RoleModel).where(RoleModel.code == 'admin').options(selectinload(RoleModel.permissions))
    admin_role = (await session.execute(stmt_admin)).scalar_one()
    stmt_perms = select(PermissionModel)
    all_perms = (await session.execute(stmt_perms)).scalars().all()
    for perm in all_perms:
        if perm not in admin_role.permissions:
            admin_role.permissions.append(perm)

    await session.commit()

    return {'seeding-success': True}
