# utils.py
import json
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from models import ChangeLogModel


async def log_mutation(
    session: AsyncSession,
    entity_type: str,
    entity_id: int,
    operation: str,
    old_value: Optional[dict] = None,
    new_value: Optional[dict] = None,
    user_id: int = None,
):
    """
    Записывает мутацию сущности в таблицу change_logs
    """
    # преобразуем словари в JSON-строки, если они есть
    old_value_json = json.dumps(old_value, ensure_ascii=False) if old_value else None
    new_value_json = json.dumps(new_value, ensure_ascii=False) if new_value else None

    # создаем запись в change_logs
    log_entry = ChangeLogModel(
        entity_type=entity_type,
        entity_id=entity_id,
        operation=operation,
        old_value=old_value_json,
        new_value=new_value_json,
        created_at=datetime.utcnow(),
        created_by=user_id,
    )
    session.add(log_entry)
    await session.flush()  # фиксируем запись без коммита транзакции
