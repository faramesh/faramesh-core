"""Add execution gate fields

Revision ID: 002_execution_gate
Revises: 001_initial
Create Date: 2025-01-14 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_execution_gate"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add execution gate fields to actions table
    op.add_column("actions", sa.Column("outcome", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("reason_code", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("reason_details_json", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("request_hash", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("policy_hash", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("runtime_version", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("profile_id", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("profile_version", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("profile_hash", sa.Text(), nullable=True))
    op.add_column("actions", sa.Column("provenance_id", sa.Text(), nullable=True))
    
    # Add hash chain fields to action_events table
    op.add_column("action_events", sa.Column("prev_hash", sa.Text(), nullable=True))
    op.add_column("action_events", sa.Column("record_hash", sa.Text(), nullable=True))


def downgrade() -> None:
    # Remove hash chain fields from action_events
    op.drop_column("action_events", "record_hash")
    op.drop_column("action_events", "prev_hash")
    
    # Remove execution gate fields from actions
    op.drop_column("actions", "provenance_id")
    op.drop_column("actions", "profile_hash")
    op.drop_column("actions", "profile_version")
    op.drop_column("actions", "profile_id")
    op.drop_column("actions", "runtime_version")
    op.drop_column("actions", "policy_hash")
    op.drop_column("actions", "request_hash")
    op.drop_column("actions", "reason_details_json")
    op.drop_column("actions", "reason_code")
    op.drop_column("actions", "outcome")
