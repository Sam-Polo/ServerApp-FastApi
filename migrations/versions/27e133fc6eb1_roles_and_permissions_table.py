"""Create roles_and_permissions table

Revision ID: 27e133fc6eb1
Revises: 09a272c2bd83
Create Date: 2025-03-11 20:28:16.242961

"""
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '27e133fc6eb1'
down_revision: Union[str, None] = '09a272c2bd83'
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.create_table(
        'roles_and_permissions',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('role_id', sa.Integer, sa.ForeignKey('roles.id'), nullable=False),
        sa.Column('permission_id', sa.Integer, sa.ForeignKey('permissions.id'), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', sa.Integer, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('deleted_by', sa.Integer, nullable=True),
        sa.UniqueConstraint('role_id', 'permission_id', name='uq_roles_permissions')  # уникальность связки
    )


def downgrade() -> None:
    op.drop_table('roles_and_permissions')
