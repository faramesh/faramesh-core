"""Initial schema

Revision ID: 001_initial
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create actions table
    op.create_table(
        'actions',
        sa.Column('id', sa.Text(), nullable=False),
        sa.Column('agent_id', sa.Text(), nullable=False),
        sa.Column('tool', sa.Text(), nullable=False),
        sa.Column('operation', sa.Text(), nullable=False),
        sa.Column('params_json', sa.Text(), nullable=False),
        sa.Column('context_json', sa.Text(), nullable=False),
        sa.Column('decision', sa.Text(), nullable=True),
        sa.Column('status', sa.Text(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('risk_level', sa.Text(), nullable=True),
        sa.Column('approval_token', sa.Text(), nullable=True),
        sa.Column('policy_version', sa.Text(), nullable=True),
        sa.Column('tenant_id', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('updated_at', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index('idx_actions_created_at', 'actions', ['created_at'])
    op.create_index('idx_actions_agent_tool', 'actions', ['agent_id', 'tool', 'operation'])
    op.create_index('idx_actions_status', 'actions', ['status'])


def downgrade() -> None:
    op.drop_index('idx_actions_status', table_name='actions')
    op.drop_index('idx_actions_agent_tool', table_name='actions')
    op.drop_index('idx_actions_created_at', table_name='actions')
    op.drop_table('actions')
