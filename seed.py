# seed.py:
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
                created_by=None,  # пока нет админа, ставим None
                created_at=datetime.utcnow()
            )
            session.add(role)
    await session.commit()

    # получаем роли после создания
    admin_role = (await session.execute(select(RoleModel).where(RoleModel.code == 'admin'))).scalar_one()
    user_role = (await session.execute(select(RoleModel).where(RoleModel.code == 'user'))).scalar_one()
    guest_role = (await session.execute(select(RoleModel).where(RoleModel.code == 'guest'))).scalar_one()

    # пользователь Aleksandr (админ + пользователь))
    stmt_user = select(UserModel).where(UserModel.username == 'Aleksandr').options(selectinload(UserModel.roles))
    result_user = await session.execute(stmt_user)
    user = result_user.scalar_one_or_none()
    if not user:
        user = UserModel(
            username='Aleksandr',
            email='alex@mail.ru',
            hashed_password=hash_password('String1234!'),
            birthday=datetime.utcnow(),
            is_2fa_enabled=False,
        )
        user.roles.extend([admin_role, user_role])  # назначаем Admin и User
        session.add(user)
        await session.commit()
        await session.refresh(user)
        admin_id = user.id
    else:
        admin_id = user.id
        if admin_role not in user.roles:
            user.roles.append(admin_role)
        if user_role not in user.roles:
            user.roles.append(user_role)
        if user.is_2fa_enabled is None:
            user.is_2fa_enabled = False
        await session.commit()

    # обновляем created_by для ролей, теперь когда есть admin_id
    for role in [admin_role, user_role, guest_role]:
        if role.created_by is None:
            role.created_by = admin_id
    await session.commit()

    # пользователь User_user (обычный пользователь)
    stmt_user_user = select(UserModel).where(UserModel.username == 'user_user').options(selectinload(UserModel.roles))
    result_user_user = await session.execute(stmt_user_user)
    user_user = result_user_user.scalar_one_or_none()

    if not user_user:
        user_user = UserModel(
            username='User_user',
            email='user_user@mail.ru',
            hashed_password=hash_password('String1234!'),
            birthday=datetime.utcnow(),
            is_2fa_enabled=False,
        )
        user_user.roles.extend([user_role])  # назначаем User
        session.add(user_user)
    else:
        if user_role not in user_user.roles:
            user_user.roles.append(user_role)
        if guest_role not in user_user.roles:
            user_user.roles.append(guest_role)
        if user_user.is_2fa_enabled is None:
            user_user.is_2fa_enabled = False

    await session.commit()

    # список разрешений
    entities = ['user', 'role', 'permission']
    permissions = [
        {'name': 'Просмотр роли пользователя', 'code': 'view-user-role',
         'description': 'Разрешение на просмотр текущих ролей пользователя'},
        {'name': 'Получение истории изменений пользователя', 'code': 'get-story-user',
         'description': 'Разрешение на просмотр истории изменений пользователя'},
        {'name': 'Получение истории изменений роли', 'code': 'get-story-role',
         'description': 'Разрешение на просмотр истории изменений роли'},
        {'name': 'Получение истории изменений разрешения', 'code': 'get-story-permission',
         'description': 'Разрешение на просмотр истории изменений разрешения'},
        {'name': 'Назначение роли пользователю', 'code': 'assign-role',
         'description': 'Разрешение на назначение роли пользователю'},
        {'name': 'Назначение разрешения пользователю', 'code': 'assign-permission',
         'description': 'Добавление разрешения к роли'},
        {'name': 'Восстановление из лога', 'code': 'restore-from-log',
         'description': 'Разрешение на восстановление old_value из логирования'},
        {'name': 'Проверка посещаемости', 'code': 'check-visits',
         'description': 'Проверка посещаемости студентов'},
    ]
    for entity in entities:
        permissions.extend([
            {'name': f'Получение списка {entity}', 'code': f'get-list-{entity}',
             'description': f'Разрешение на получение списка {entity}'},
            {'name': f'Чтение {entity}', 'code': f'read-{entity}', 'description': f'Разрешение на чтение {entity}'},
            {'name': f'Создание {entity}', 'code': f'create-{entity}',
             'description': f'Разрешение на создание {entity}'},
            {'name': f'Обновление {entity}', 'code': f'update-{entity}',
             'description': f'Разрешение на обновление {entity}'},
            {'name': f'Удаление {entity}', 'code': f'delete-{entity}',
             'description': f'Разрешение на удаление {entity}'},
            {'name': f'Восстановление {entity}', 'code': f'restore-{entity}',
             'description': f'Разрешение на восстановление {entity}'}
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

    return {'ok': True}
