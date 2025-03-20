# roles_controller.py:
from datetime import datetime

from fastapi import HTTPException, APIRouter, Depends, Path, Body
import json
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from db import SessionDep
from auth_controller import require_permission
from models import (RoleSchema, RoleCollectionSchema, RoleModel, UpdateRoleRequestSchema,
                    CreateRoleRequestSchema, UserModel, PermissionModel, RolePermissionModel,
                    PermissionCollectionSchema, PermissionSchema, CreatePermissionRequestSchema, UserCollectionSchema,
                    UserResponseSchema, ChangeLogCollectionSchema, ChangeLogModel, ChangeLogSchema)
from utils import log_mutation

roles_router = APIRouter(tags=['Роли и Привилегии'])
logs_router = APIRouter(tags=['Логирование'])


@roles_router.get('/api/ref/user/', response_model=UserCollectionSchema)
async def get_users(session: SessionDep):
    stmt = select(UserModel)
    result = await session.execute(stmt)
    users = result.scalars().all()
    return UserCollectionSchema(users=[UserResponseSchema.model_validate(user) for user in users])


@roles_router.post('/api/ref/policy/role', response_model=RoleSchema)
async def create_role(request: CreateRoleRequestSchema,
                      session: SessionDep,
                      current_user: UserModel = Depends(require_permission('create-role'))):
    """
    Создание новой роли
    """
    async with session.begin():

        # проверяем, существует ли роль с таким кодом или именем
        stmt_code = select(RoleModel).where(RoleModel.code == request.code)
        stmt_name = select(RoleModel).where(RoleModel.name == request.name)

        result_code = await session.execute(stmt_code)
        result_name = await session.execute(stmt_name)

        existing_role_by_code = result_code.scalar_one_or_none()
        existing_role_by_name = result_name.scalar_one_or_none()

        if existing_role_by_code:
            if existing_role_by_code.deleted_at is None:
                raise HTTPException(status_code=400, detail=f'Роль с кодом "{request.code}" уже существует')
            else:
                raise HTTPException(status_code=400,
                                    detail=f'Роль с кодом "{request.code}" была удалена ранее '
                                           f'и не может быть переиспользована')

        if existing_role_by_name:
            if existing_role_by_name.deleted_at is None:
                raise HTTPException(status_code=400, detail=f'Роль с именем "{request.name}" уже существует')
            else:
                raise HTTPException(status_code=400,
                                    detail=f'Роль с именем "{request.name}" была удалена ранее '
                                           f'и не может быть переиспользована')

        role = RoleModel(
            name=request.name,
            description=request.description,
            code=request.code,
            created_by=current_user.id
        )
        session.add(role)
        await session.flush()

        # логирование
        new_value = {
            'name': role.name,
            'description': role.description,
            'code': role.code,
            'created_by': role.created_by,
        }
        await log_mutation(
            session=session,
            entity_type='role',
            entity_id=role.id,
            operation='create',
            old_value=None,
            new_value=new_value,
            user_id=current_user.id,
        )

    await session.refresh(role)
    stmt = select(RoleModel).where(RoleModel.id == role.id).options(selectinload(RoleModel.permissions))
    result = await session.execute(stmt)
    role = result.scalar_one()
    return request.to_response(role)


@roles_router.get('/api/ref/policy/role', response_model=RoleCollectionSchema)
async def get_roles(
        session: SessionDep,
        current_user: UserModel = Depends(require_permission('get-list-role'))
):
    """
    Получение списка ролей
    """
    stmt = select(RoleModel).where(RoleModel.deleted_at.is_(None)).options(selectinload(RoleModel.permissions))
    result = await session.execute(stmt)
    roles = result.scalars().all()
    return RoleCollectionSchema(roles=[RoleSchema.model_validate(role) for role in roles])


@roles_router.get('/api/ref/policy/role/{id}', response_model=RoleSchema)
async def get_role(
        session: SessionDep,
        id: int = Path(description='ID роли'),
        current_user: UserModel = Depends(require_permission('read-role'))
):
    """
    Получение конкретной роли
    """
    stmt = select(RoleModel).where(RoleModel.id == id,
                                   RoleModel.deleted_at.is_(None)).options(selectinload(RoleModel.permissions))
    result = await session.execute(stmt)
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail=f'Роль с ID {id} не найдена')
    return RoleSchema.model_validate(role)


@roles_router.put('/api/ref/policy/role/{id}', response_model=RoleSchema)
async def update_role(
        request: UpdateRoleRequestSchema,
        session: SessionDep,
        id: int = Path(description='id роли'),
        current_user: UserModel = Depends(require_permission('update-role'))
):
    """
    Обновление роли
    """
    async with session.begin():
        # находим роль по id
        stmt = select(RoleModel).where(RoleModel.id == id, RoleModel.deleted_at.is_(None))
        result = await session.execute(stmt)
        role = result.scalar_one_or_none()

        if role is None:
            raise HTTPException(status_code=404, detail='Роль не найдена')

        # старое состояние
        old_value = {
            'name': role.name,
            'description': role.description,
            'code': role.code,
        }

        # обновляем только переданные поля
        if request.name is not None and request.name != 'string':
            role.name = request.name
        if request.description is not None and request.description != 'string':
            role.description = request.description
        if request.code is not None and request.code != 'string':
            role.code = request.code

        # новое состояние
        new_value = {
            'name': role.name,
            'description': role.description,
            'code': role.code,
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='role',
            entity_id=role.id,
            operation='update',
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id,
        )

    await session.refresh(role)
    return request.to_response(role=role)


@roles_router.delete('/api/ref/policy/role/{id}', response_model=dict)
async def delete_role_hard(
        session: SessionDep,
        id: int = Path(description='ID роли'),
        current_user: UserModel = Depends(require_permission('delete-role'))
):
    """
    Жёсткое удаление роли
    """
    async with session.begin():
        # находим роль
        stmt = select(RoleModel).where(RoleModel.id == id)
        result = await session.execute(stmt)
        role = result.scalar_one_or_none()
        if not role:
            raise HTTPException(status_code=404, detail=f'Роль с ID {id} не найдена')

        # старое значение
        old_value = {
            'name': role.name,
            'description': role.description,
            'code': role.code,
            'deleted_at': role.deleted_at.isoformat() if role.deleted_at else None,
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='role',
            entity_id=role.id,
            operation='delete',
            old_value=old_value,
            new_value={'status': 'DELETED_HARD'},
            user_id=current_user.id,
        )
        await session.delete(role)

    return {'message': f'Роль с ID {id} жёстко удалена'}


@roles_router.delete('/api/ref/policy/role/{id}/soft', response_model=RoleSchema)
async def delete_role_soft(
        session: SessionDep,
        id: int = Path(description='ID роли'),
        current_user: UserModel = Depends(require_permission('delete-role'))
):
    """
    Мягкое удаление роли
    """
    async with session.begin():
        # находим роль
        stmt = select(RoleModel).where(RoleModel.id == id,
                                       RoleModel.deleted_at.is_(None)).options(selectinload(RoleModel.permissions))
        result = await session.execute(stmt)
        role = result.scalar_one_or_none()
        if not role:
            raise HTTPException(status_code=404, detail=f'Роль с ID {id} не найдена')

        # старое состояние
        old_value = {
            'name': role.name,
            'description': role.description,
            'code': role.code,
            'deleted_at': None,
        }

        role.deleted_at = datetime.utcnow()
        role.deleted_by = current_user.id

        # новое состояние
        new_value = {
            'name': role.name,
            'description': role.description,
            'code': role.code,
            'deleted_at': role.deleted_at.isoformat(),
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='role',
            entity_id=role.id,
            operation='delete',
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id,
        )

    await session.refresh(role)
    return RoleSchema.model_validate(role)


@roles_router.post('/api/ref/policy/role/{role_id}/restore', response_model=RoleSchema)
async def restore_role(
    session: SessionDep,
    role_id: int = Path(description='ID роли'),
    current_user: UserModel = Depends(require_permission('restore-role'))
):
    """
    Восстановление мягко удалённой роли
    """
    async with session.begin():

        # Проверяем существование роли и её мягкое удаление
        stmt_role = select(RoleModel).where(
            RoleModel.id == role_id,
            RoleModel.deleted_at.is_not(None)  # Убеждаемся, что роль была мягко удалена
        ).options(selectinload(RoleModel.permissions))
        result_role = await session.execute(stmt_role)
        role = result_role.scalar_one_or_none()

        if not role:
            raise HTTPException(
                status_code=404,
                detail=f'Мягко удалённая роль с ID {role_id} не найдена'
            )

        # старое состояние
        old_value = {
            'name': role.name,
            'description': role.description,
            'code': role.code,
            'deleted_at': role.deleted_at.isoformat(),
        }

        # восстанавливаем роль
        role.deleted_at = None
        role.deleted_by = None

        # новое состояние
        new_value = {
            'name': role.name,
            'description': role.description,
            'code': role.code,
            'deleted_at': None,
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='role',
            entity_id=role.id,
            operation='update',  # восстановление как обновление
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id,
        )

    await session.refresh(role)

    # возвращаем данные восстановленной роли
    return RoleSchema.model_validate(role)


@roles_router.get('/api/ref/policy/permission', response_model=PermissionCollectionSchema)
async def get_permissions(
        session: SessionDep,
        current_user: UserModel = Depends(require_permission('read-permission'))
):
    """
    Получение списка всех разрешений
    """
    stmt = select(PermissionModel)
    result = await session.execute(stmt)
    permissions = result.scalars().all()
    return PermissionCollectionSchema(permissions=[PermissionSchema.model_validate(p) for p in permissions])


@roles_router.get('/api/ref/policy/permission/{id}', response_model=PermissionSchema)
async def get_permission(
        session: SessionDep,
        id: int = Path(description='ID разрешения'),
        current_user: UserModel = Depends(require_permission('read-permission'))
):
    """
    Получение конкретного разрешения
    """
    permission = await session.get(PermissionModel, id)
    if not permission:
        raise HTTPException(status_code=404, detail=f'Разрешение с ID {id} не найдено')
    return PermissionSchema.model_validate(permission)


@roles_router.post('/api/ref/policy/permission', response_model=PermissionSchema)
async def create_permission(
    request: CreatePermissionRequestSchema,
    session: SessionDep,
    current_user: UserModel = Depends(require_permission('create-permission'))
):
    """
    Создание нового разрешения
    """
    async with session.begin():

        # проверяем, существует ли разрешение с таким code или name
        stmt_code = select(PermissionModel).where(PermissionModel.code == request.code)
        stmt_name = select(PermissionModel).where(PermissionModel.name == request.name)

        result_code = await session.execute(stmt_code)
        result_name = await session.execute(stmt_name)

        existing_perm_by_code = result_code.scalar_one_or_none()
        existing_perm_by_name = result_name.scalar_one_or_none()

        if existing_perm_by_code:
            raise HTTPException(status_code=400, detail=f'Разрешение с кодом "{request.code}" уже существует')
        if existing_perm_by_name:
            raise HTTPException(status_code=400, detail=f'Разрешение с именем "{request.name}" уже существует')

        permission = PermissionModel(
            name=request.name,
            code=request.code,
            description=request.description,
            created_by=current_user.id
        )
        session.add(permission)
        await session.flush()

        # логирование
        new_value = {
            'name': permission.name,
            'code': permission.code,
            'description': permission.description,
            'created_by': permission.created_by,
        }
        await log_mutation(
            session=session,
            entity_type='permission',
            entity_id=permission.id,
            operation='create',
            old_value=None,
            new_value=new_value,
            user_id=current_user.id,
        )

    await session.refresh(permission)
    return request.to_response(permission)


@roles_router.put('/api/ref/policy/permission/{id}', response_model=PermissionSchema)
async def update_permission(
        session: SessionDep,
        id: int = Path(description='ID разрешения'),
        request: CreatePermissionRequestSchema = Body(...),
        current_user: UserModel = Depends(require_permission('update-permission'))
):
    """
    Обновление разрешения
    """
    async with session.begin():

        permission = await session.get(PermissionModel, id)
        if not permission:
            raise HTTPException(status_code=404, detail=f'Разрешение с ID {id} не найдено')

        # старое состояние
        old_value = {
            'name': permission.name,
            'code': permission.code,
            'description': permission.description,
        }

        permission.name = request.name
        permission.code = request.code
        permission.description = request.description

        # новое состояние
        new_value = {
            'name': permission.name,
            'code': permission.code,
            'description': permission.description,
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='permission',
            entity_id=permission.id,
            operation='update',
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id,
        )

    await session.refresh(permission)
    return PermissionSchema.model_validate(permission)


@roles_router.delete('/api/ref/policy/permission/{id}', response_model=dict)
async def delete_permission_hard(
        session: SessionDep,
        id: int = Path(description='ID разрешения'),
        current_user: UserModel = Depends(require_permission('delete-permission'))
):
    """
    Жёсткое удаление разрешения
    """
    async with session.begin():
        permission = await session.get(PermissionModel, id)
        if not permission:
            raise HTTPException(status_code=404, detail=f'Разрешение с ID {id} не найдено')

        # старое состояние
        old_value = {
            'name': permission.name,
            'code': permission.code,
            'description': permission.description,
            'deleted_at': permission.deleted_at.isoformat() if permission.deleted_at else None,
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='permission',
            entity_id=permission.id,
            operation='delete',
            old_value=old_value,
            new_value={'status': 'DELETED_HARD'},
            user_id=current_user.id,
        )

        await session.delete(permission)

    return {'message': f'Разрешение с ID {id} жёстко удалено'}


@roles_router.delete('/api/ref/policy/permission/{id}/soft', response_model=dict)
async def delete_permission_soft(
    session: SessionDep,
    id: int = Path(description='ID разрешения'),
    current_user: UserModel = Depends(require_permission('delete-permission'))
):
    """
    Мягкое удаление разрешения
    """
    async with session.begin():
        permission = await session.get(PermissionModel, id)
        if not permission:
            raise HTTPException(status_code=404, detail=f'Разрешение с ID {id} не найдено')

        # старое состояние
        old_value = {
            'name': permission.name,
            'code': permission.code,
            'description': permission.description,
            'deleted_at': None,
        }

        # удаление
        permission.deleted_at = datetime.utcnow()
        permission.deleted_by = current_user.id

        # новое состояние
        new_value = {
            'name': permission.name,
            'code': permission.code,
            'description': permission.description,
            'deleted_at': permission.deleted_at.isoformat(),
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='permission',
            entity_id=permission.id,
            operation='delete',
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id,
        )

    await session.refresh(permission)
    return {'message': f'Разрешение с ID {id} мягко удалено'}


@roles_router.post('/api/ref/policy/permission/{id}/restore', response_model=PermissionSchema)
async def restore_permission(
    session: SessionDep,
    id: int = Path(description='ID разрешения'),
    current_user: UserModel = Depends(require_permission('restore-permission'))
):
    """
    Восстановление мягко удалённого разрешения
    """
    async with session.begin():
        stmt = select(PermissionModel).where(PermissionModel.id == id, PermissionModel.deleted_at.is_not(None))
        result = await session.execute(stmt)
        permission = result.scalar_one_or_none()

        if not permission:
            raise HTTPException(status_code=404, detail=f'Мягко удалённое разрешение с ID {id} не найдено')
        
        # старое состояние
        old_value = {
            'name': permission.name,
            'description': permission.description,
            'code': permission.code,
            'deleted_at': permission.deleted_at.isoformat(),
        }

        # восстановление разрешения
        permission.deleted_at = None
        permission.deleted_by = None

        # новое состояние
        new_value = {
            'name': permission.name,
            'description': permission.description,
            'code': permission.code,
            'deleted_at': None,
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='permission',
            entity_id=permission.id,
            operation='update',  # восстановление как обновление
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id,
        )

    await session.refresh(permission)
    return PermissionSchema.model_validate(permission)


@roles_router.post('/api/ref/policy/role/{role_id}/permission/{permission_id}', response_model=RoleSchema)
async def assign_permission_to_role(
        session: SessionDep,
        role_id: int = Path(description='id роли'),
        permission_id: int = Path(description='id разрешения'),
        current_user: UserModel = Depends(require_permission('assign-role'))
):
    """
    Привязка разрешения к роли (доп функционал)
    """
    # проверяем существование роли
    role = await session.get(RoleModel, role_id)
    if not role or role.deleted_at is not None:
        raise HTTPException(status_code=404, detail=f'Роль с id {role_id} не найдена')

    # проверяем существование разрешения
    permission = await session.get(PermissionModel, permission_id)
    if not permission:
        raise HTTPException(status_code=404, detail=f'Разрешение с id {permission_id} не найдено')

    # проверяем, не привязано ли уже разрешение к роли
    stmt = select(RolePermissionModel).where(
        RolePermissionModel.role_id == role_id,
        RolePermissionModel.permission_id == permission_id
    )
    result = await session.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f'Разрешение уже привязано к роли')

    # привязываем разрешение к роли
    role_permission = RolePermissionModel(role_id=role_id, permission_id=permission_id)
    session.add(role_permission)
    await session.commit()
    await session.refresh(role)
    return RoleSchema.model_validate(role)


@roles_router.delete('/api/ref/user/{id}/role', response_model=dict)
async def remove_role_from_user(
        session: SessionDep,
        id: int = Path(description='ID пользователя'),
        current_user: UserModel = Depends(require_permission('delete-user'))
):
    """
    Удаление роли у пользователя
    """
    async with session.begin():
        stmt_user = select(UserModel).where(UserModel.id == id)
        result_user = await session.execute(stmt_user)
        user = result_user.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail=f'Пользователь с ID {id} не найден')

        if user.role_id is None:
            raise HTTPException(status_code=400, detail='У пользователя нет роли для удаления')

        # старое состояние
        old_value = {
            'role_id': user.role_id,  # текущая роль перед удалением
        }

        # удаляем роль
        user.role_id = None

        # новое состояние
        new_value = {
            'role_id': user.role_id,  # теперь None
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='user',
            entity_id=user.id,
            operation='update',  # это обновление записи пользователя
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id,  # кто выполнил действие
        )

    await session.refresh(user)

    return {'message': f'Роль удалена у пользователя с ID {id}'}


@roles_router.put('/api/ref/user/{user_id}/role/{role_id}', response_model=RoleSchema)
async def assign_role_to_user(
    session: SessionDep,
    user_id: int = Path(description='ID пользователя'),
    role_id: int = Path(description='ID роли'),
    current_user: UserModel = Depends(require_permission('assign-role'))
):
    """
    Назначение роли пользователю
    """
    async with session.begin():
        # Проверяем существование пользователя
        stmt_user = select(UserModel).where(UserModel.id == user_id)
        result_user = await session.execute(stmt_user)
        user = result_user.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail=f'Пользователь с ID {user_id} не найден')

        # проверяем существование роли
        stmt_role = select(RoleModel).where(RoleModel.id == role_id,
                                            RoleModel.deleted_at.is_(None)).options(selectinload(RoleModel.permissions))
        result_role = await session.execute(stmt_role)
        role = result_role.scalar_one_or_none()
        if not role:
            raise HTTPException(status_code=404, detail=f'Роль с ID {role_id} не найдена или удалена')

        # старое состояние
        old_value = {
            'role_id': user.role_id,  # предыдущая роль (может быть None)
        }

        # назначаем роль пользователю
        user.role_id = role_id

        # новое состояние
        new_value = {
            'role_id': user.role_id,  # новая роль
        }

        # логирование
        await log_mutation(
            session=session,
            entity_type='user',
            entity_id=user.id,
            operation='update',
            old_value=old_value,
            new_value=new_value,
            user_id=current_user.id,  # кто выполнил действие
        )

    await session.refresh(user)
    await session.refresh(role)

    return RoleSchema.model_validate(role)


@roles_router.get('/api/ref/user/{id}/role', response_model=RoleSchema | dict)
async def get_user_role(
    session: SessionDep,
    id: int = Path(description='ID пользователя'),
    current_user: UserModel = Depends(require_permission('view-user-role'))
):
    """
    Получение текущей роли пользователя
    """
    # Проверяем существование пользователя
    stmt_user = select(UserModel).where(UserModel.id == id)
    result_user = await session.execute(stmt_user)
    user = result_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail=f'Пользователь с ID {id} не найден')

    # Если роли нет, возвращаем сообщение
    if user.role_id is None:
        return {'message': f'У пользователя с ID {id} нет назначенной роли'}

    # Получаем данные роли
    stmt_role = select(RoleModel).where(RoleModel.id == user.role_id,
                                        RoleModel.deleted_at.is_(None)).options(selectinload(RoleModel.permissions))
    result_role = await session.execute(stmt_role)
    role = result_role.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail=f'Роль с ID {user.role_id} не найдена или удалена')

    # Возвращаем данные роли
    return RoleSchema(
        id=role.id,
        name=role.name,
        description=role.description,
        code=role.code,
        created_at=role.created_at,
        created_by=role.created_by,
        deleted_at=role.deleted_at,
        deleted_by=role.deleted_by,
        permissions=[PermissionSchema.model_validate(perm) for perm in role.permissions]
    )


@logs_router.get('/api/ref/user/{id}/story', response_model=ChangeLogCollectionSchema)
async def get_user_story(
    session: SessionDep,
    id: int = Path(description='ID пользователя'),
    current_user: UserModel = Depends(require_permission('get-story-user'))
):
    """
    Получение истории изменений пользователя
    """
    stmt = select(ChangeLogModel).where(
        ChangeLogModel.entity_type == 'user',
        ChangeLogModel.entity_id == id
    ).order_by(ChangeLogModel.created_at)
    result = await session.execute(stmt)
    logs = result.scalars().all()
    return ChangeLogCollectionSchema(logs=[ChangeLogSchema.model_validate(log) for log in logs])


@logs_router.get('/api/ref/policy/role/{id}/story', response_model=ChangeLogCollectionSchema)
async def get_role_story(
    session: SessionDep,
    id: int = Path(description='ID роли'),
    current_user: UserModel = Depends(require_permission('get-story-role'))
):
    """
    Получение истории изменений роли
    """
    stmt = select(ChangeLogModel).where(
        ChangeLogModel.entity_type == 'role',
        ChangeLogModel.entity_id == id
    ).order_by(ChangeLogModel.created_at)
    result = await session.execute(stmt)
    logs = result.scalars().all()
    return ChangeLogCollectionSchema(logs=[ChangeLogSchema.model_validate(log) for log in logs])


@logs_router.get('/api/ref/policy/permission/{id}/story', response_model=ChangeLogCollectionSchema)
async def get_permission_story(
    session: SessionDep,
    id: int = Path(description='ID разрешения'),
    current_user: UserModel = Depends(require_permission('get-story-permission'))
):
    """
    Получение истории изменений разрешения
    """
    stmt = select(ChangeLogModel).where(
        ChangeLogModel.entity_type == 'permission',
        ChangeLogModel.entity_id == id
    ).order_by(ChangeLogModel.created_at)
    result = await session.execute(stmt)
    logs = result.scalars().all()
    return ChangeLogCollectionSchema(logs=[ChangeLogSchema.model_validate(log) for log in logs])


@logs_router.post('/api/ref/log/{log_id}/restore', response_model=dict)
async def restore_from_log(
        session: SessionDep,
        log_id: int = Path(description='ID записи в логе изменений'),
        current_user: UserModel = Depends(require_permission('restore-from-log'))
):
    """
    Восстановление состояния сущности из записи в логе изменений
    """
    async with session.begin():
        # находим запись в логах по log_id
        stmt_log = select(ChangeLogModel).where(ChangeLogModel.id == log_id)
        result_log = await session.execute(stmt_log)
        log = result_log.scalar_one_or_none()
        if not log:
            raise HTTPException(status_code=404, detail=f'Запись с ID {log_id} не найдена')

        # определяем сущность и её модель
        entity_type = log.entity_type
        entity_id = log.entity_id
        old_value = json.loads(log.old_value) if log.old_value else None
        new_value = json.loads(log.new_value) if log.new_value else None

        if entity_type == 'user':
            model = UserModel
            schema = UserResponseSchema
        elif entity_type == 'role':
            model = RoleModel
            schema = RoleSchema
        elif entity_type == 'permission':
            model = PermissionModel
            schema = PermissionSchema
        else:
            raise HTTPException(status_code=400, detail=f'Неизвестный тип сущности: {entity_type}')

        # находим текущую сущность
        stmt_entity = select(model).where(model.id == entity_id)
        result_entity = await session.execute(stmt_entity)
        entity = result_entity.scalar_one_or_none()

        # если сущность удалена жёстко (нет в БД), создаём новую
        if entity is None and log.operation != 'delete' and new_value:
            entity = model(id=entity_id)  # создаём с тем же ID
            session.add(entity)
        elif entity is None:
            raise HTTPException(status_code=404, detail=f'Сущность {entity_type} с ID {entity_id} не найдена и не может быть восстановлена')

        # восстанавливаем состояние из new_value (если это не удаление) или old_value (если удаление)
        restore_value = new_value if log.operation != 'delete' else old_value
        if not restore_value:
            raise HTTPException(status_code=400, detail='Нет данных для восстановления')

        # обновляем только поля, которые есть в restore_value
        for key, value in restore_value.items():
            if hasattr(entity, key):
                setattr(entity, key, value)

        # сбрасываем deleted_at и deleted_by, если они есть
        if hasattr(entity, 'deleted_at'):
            entity.deleted_at = None
        if hasattr(entity, 'deleted_by'):
            entity.deleted_by = None

        # логируем восстановление
        old_state = {key: getattr(entity, key) for key in restore_value.keys() if hasattr(entity, key)}
        await session.flush()  # обновляем состояние в БД, чтобы получить актуальные данные
        new_state = {key: getattr(entity, key) for key in restore_value.keys() if hasattr(entity, key)}

        await log_mutation(
            session=session,
            entity_type=entity_type,
            entity_id=entity_id,
            operation='restore',
            old_value=old_state,
            new_value=new_state,
            user_id=current_user.id,
        )

    await session.refresh(entity)
    return {'message': f'Сущность {entity_type} с ID {entity_id} восстановлена из лога {log_id}'}
