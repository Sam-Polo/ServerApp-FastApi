"""Create users_and_roles table

Revision ID: 09a272c2bd83
Revises: 079e004e0d1e
Create Date: 2025-03-11 16:09:06.227991

"""
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '09a272c2bd83'
down_revision: Union[str, None] = '079e004e0d1e'
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.create_table(
        'users_and_roles',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('role_id', sa.Integer, sa.ForeignKey('roles.id'), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', sa.Integer, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('deleted_by', sa.Integer, nullable=True),
        sa.UniqueConstraint('user_id', 'role_id', name='uq_users_roles')  # уникальность связки
    )


def downgrade() -> None:
    op.drop_table('users_and_roles')
