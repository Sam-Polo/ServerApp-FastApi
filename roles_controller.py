# roles_controller.py:
from datetime import datetime

from fastapi import HTTPException, APIRouter, Depends, Path, Body
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from db import SessionDep
from auth_controller import require_permission
from models import (RoleSchema, RoleCollectionSchema, RoleModel, UpdateRoleRequestSchema,
                    CreateRoleRequestSchema, UserModel, PermissionModel, RolePermissionModel,
                    PermissionCollectionSchema, PermissionSchema, CreatePermissionRequestSchema, UserCollectionSchema,
                    UserResponseSchema)


router = APIRouter(tags=['Роли и Привилегии'])


@router.get('/api/ref/user/', response_model=UserCollectionSchema)
async def get_users(session: SessionDep):
    stmt = select(UserModel)
    result = await session.execute(stmt)
    users = result.scalars().all()
    return UserCollectionSchema(users=[UserResponseSchema.model_validate(user) for user in users])


@router.post('/api/ref/policy/role', response_model=RoleSchema)
async def create_role(request: CreateRoleRequestSchema,
                      session: SessionDep,
                      current_user: UserModel = Depends(require_permission('create-role'))):
    """
    Создание новой роли
    """
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
    await session.commit()
    await session.refresh(role)
    stmt = select(RoleModel).where(RoleModel.id == role.id).options(selectinload(RoleModel.permissions))
    result = await session.execute(stmt)
    role = result.scalar_one()
    return request.to_response(role)


@router.get('/api/ref/policy/role', response_model=RoleCollectionSchema)
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


@router.get('/api/ref/policy/role/{id}', response_model=RoleSchema)
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


@router.put('/api/ref/policy/role/{id}', response_model=RoleSchema)
async def update_role(
        request: UpdateRoleRequestSchema,
        session: SessionDep,
        id: int = Path(description='id роли'),
        current_user: UserModel = Depends(require_permission('update-role'))
):
    """
    Обновление роли
    """
    # находим роль по id
    stmt = select(RoleModel).where(RoleModel.id == id, RoleModel.deleted_at.is_(None))
    result = await session.execute(stmt)
    role = result.scalar_one_or_none()

    if role is None:
        raise HTTPException(status_code=404, detail='Роль не найдена')

    # обновляем только переданные поля
    if request.name is not None and request.name != 'string':
        role.name = request.name
    if request.description is not None and request.description != 'string':
        role.description = request.description
    if request.code is not None and request.code != 'string':
        role.code = request.code

    await session.commit()
    await session.refresh(role)
    return request.to_response(role=role)


@router.delete('/api/ref/policy/role/{id}', response_model=dict)
async def delete_role_hard(
        session: SessionDep,
        id: int = Path(description='ID роли'),
        current_user: UserModel = Depends(require_permission('delete-role'))
):
    """
    Жёсткое удаление роли
    """
    # находим роль
    stmt = select(RoleModel).where(RoleModel.id == id)
    result = await session.execute(stmt)
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail=f'Роль с ID {id} не найдена')

    await session.delete(role)
    await session.commit()
    return {'message': f'Роль с ID {id} жёстко удалена'}


@router.delete('/api/ref/policy/role/{id}/soft', response_model=RoleSchema)
async def delete_role_soft(
        session: SessionDep,
        id: int = Path(description='ID роли'),
        current_user: UserModel = Depends(require_permission('delete-role'))
):
    """
    Мягкое удаление роли
    """
    # находим роль
    stmt = select(RoleModel).where(RoleModel.id == id,
                                   RoleModel.deleted_at.is_(None)).options(selectinload(RoleModel.permissions))
    result = await session.execute(stmt)
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail=f'Роль с ID {id} не найдена')

    role.deleted_at = datetime.utcnow()
    role.deleted_by = current_user.id
    await session.commit()
    await session.refresh(role)
    return RoleSchema.model_validate(role)


@router.post('/api/ref/policy/role/{role_id}/restore', response_model=RoleSchema)
async def restore_role(
    session: SessionDep,
    role_id: int = Path(description='ID роли'),
    current_user: UserModel = Depends(require_permission('restore-role'))
):
    """
    Восстановление мягко удалённой роли
    """
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

    # Восстанавливаем роль
    role.deleted_at = None
    role.deleted_by = None
    await session.commit()
    await session.refresh(role)

    # Возвращаем данные восстановленной роли
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


@router.get('/api/ref/policy/permission', response_model=PermissionCollectionSchema)
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


@router.get('/api/ref/policy/permission/{id}', response_model=PermissionSchema)
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


@router.post('/api/ref/policy/permission', response_model=PermissionSchema)
async def create_permission(
    request: CreatePermissionRequestSchema,
    session: SessionDep,
    current_user: UserModel = Depends(require_permission('create-permission'))
):
    """
    Создание нового разрешения
    """
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
    await session.commit()
    await session.refresh(permission)
    return request.to_response(permission)


@router.put('/api/ref/policy/permission/{id}', response_model=PermissionSchema)
async def update_permission(
        session: SessionDep,
        id: int = Path(description='ID разрешения'),
        request: CreatePermissionRequestSchema = Body(...),
        current_user: UserModel = Depends(require_permission('update-permission'))
):
    """
    Обновление разрешения
    """
    permission = await session.get(PermissionModel, id)
    if not permission:
        raise HTTPException(status_code=404, detail=f'Разрешение с ID {id} не найдено')

    permission.name = request.name
    permission.code = request.code
    permission.description = request.description
    await session.commit()
    await session.refresh(permission)
    return PermissionSchema.model_validate(permission)


@router.delete('/api/ref/policy/permission/{id}', response_model=dict)
async def delete_permission_hard(
        session: SessionDep,
        id: int = Path(description='ID разрешения'),
        current_user: UserModel = Depends(require_permission('delete-permission'))
):
    """
    Жёсткое удаление разрешения
    """
    permission = await session.get(PermissionModel, id)
    if not permission:
        raise HTTPException(status_code=404, detail=f'Разрешение с ID {id} не найдено')

    await session.delete(permission)
    await session.commit()
    return {'message': f'Разрешение с ID {id} жёстко удалено'}


@router.delete('/api/ref/policy/permission/{id}/soft', response_model=dict)
async def delete_permission_soft(
    session: SessionDep,
    id: int = Path(description='ID разрешения'),
    current_user: UserModel = Depends(require_permission('delete-permission'))
):
    """
    Мягкое удаление разрешения
    """
    permission = await session.get(PermissionModel, id)
    if not permission:
        raise HTTPException(status_code=404, detail=f'Разрешение с ID {id} не найдено')

    permission.deleted_at = datetime.utcnow()
    permission.deleted_by = current_user.id
    await session.commit()
    await session.refresh(permission)
    return {'message': f'Разрешение с ID {id} мягко удалено'}


@router.post('/api/ref/policy/permission/{id}/restore', response_model=PermissionSchema)
async def restore_permission(
    session: SessionDep,
    id: int = Path(description='ID разрешения'),
    request: CreatePermissionRequestSchema = Body(...),
    current_user: UserModel = Depends(require_permission('restore-permission'))
):
    """
    Восстановление мягко удалённого разрешения
    """
    stmt = select(PermissionModel).where(PermissionModel.id == id, PermissionModel.deleted_at.is_not(None))
    result = await session.execute(stmt)
    permission = result.scalar_one_or_none()

    if not permission:
        raise HTTPException(status_code=404, detail=f'Мягко удалённое разрешение с ID {id} не найдено')

    permission.deleted_at = None
    permission.deleted_by = None

    await session.commit()
    await session.refresh(permission)
    return PermissionSchema.model_validate(permission)


@router.post('/api/ref/policy/role/{role_id}/permission/{permission_id}', response_model=RoleSchema)
async def assign_permission_to_role(
        session: SessionDep,
        role_id: int = Path(description='id роли'),
        permission_id: int = Path(description='id разрешения'),
        current_user: UserModel = Depends(require_permission('assign-permission'))
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


@router.delete('/api/ref/user/{id}/role', response_model=dict)
async def remove_role_from_user(
    session: SessionDep,
    id: int = Path(description='ID пользователя'),
    current_user: UserModel = Depends(require_permission('delete-user'))
):
    """
    Удаление роли у пользователя
    """
    stmt_user = select(UserModel).where(UserModel.id == id)
    result_user = await session.execute(stmt_user)
    user = result_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail=f'Пользователь с ID {id} не найден')

    if user.role_id is None:
        raise HTTPException(status_code=400, detail='У пользователя нет роли для удаления')

    user.role_id = None
    await session.commit()
    await session.refresh(user)

    return {'message': f'Роль удалена у пользователя с ID {id}'}


@router.put('/api/ref/user/{user_id}/role/{role_id}', response_model=RoleSchema)
async def assign_role_to_user(
    session: SessionDep,
    user_id: int = Path(description='ID пользователя'),
    role_id: int = Path(description='ID роли'),
    current_user: UserModel = Depends(require_permission('assign-role'))
):
    """
    Назначение роли пользователю
    """
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

    # назначаем роль пользователю
    user.role_id = role_id
    await session.commit()
    await session.refresh(user)
    await session.refresh(role)

    # возвращаем данные назначенной роли
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


@router.get('/api/ref/user/{id}/role', response_model=RoleSchema | dict)
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
