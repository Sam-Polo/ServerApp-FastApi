"""add change_logs table to db

Revision ID: b3218e3fb40a
Revises: 27e133fc6eb1
Create Date: 2025-03-19 21:42:06.628763

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3218e3fb40a'
down_revision: Union[str, None] = '27e133fc6eb1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'change_logs',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('entity_type', sa.String, nullable=False),
        sa.Column('entity_id', sa.Integer, nullable=False),
        sa.Column('operation', sa.String, nullable=False),
        sa.Column('old_value', sa.String, nullable=True),
        sa.Column('new_value', sa.String, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, default=sa.func.now()),
        sa.Column('created_by', sa.Integer, sa.ForeignKey('users.id'), nullable=False)
    )


def downgrade() -> None:
    op.drop_table('change_logs')
