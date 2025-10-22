"""create permissions table

Revision ID: 079e004e0d1e
Revises: 8cd04bc0bdc3
Create Date: 2025-03-11 15:48:21.304522

"""
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '079e004e0d1e'
down_revision: Union[str, None] = '8cd04bc0bdc3'
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.create_table(
        'permissions',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String, nullable=False, unique=True),
        sa.Column('description', sa.String, nullable=True),
        sa.Column('code', sa.String, nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', sa.Integer, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('deleted_by', sa.Integer, nullable=True)
    )


def downgrade() -> None:
    op.drop_table('permissions')
