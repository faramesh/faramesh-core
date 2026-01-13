# src/faracore/server/storage_postgres.py
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional, List, Dict, Any

import psycopg2
import psycopg2.extras

from .models import Action


class PostgresStore:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self._initialized = False
        # Don't connect immediately - lazy initialization

    def _connect(self):
        return psycopg2.connect(
            self.dsn,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )

    def _ensure_initialized(self):
        """Lazy initialization - only connect when actually needed."""
        if self._initialized:
            return
        try:
            self._init_db()
            self._initialized = True
        except Exception as e:
            # This should never happen if get_store() tested the connection
            # But if it does, raise a clear error
            raise ConnectionError(
                f"Failed to connect to PostgreSQL: {e}. "
                f"PostgresStore should not have been created if connection fails. "
                f"Please set FARA_DB_BACKEND=sqlite to use SQLite instead."
            ) from e
    
    def _init_db(self):
        conn = self._connect()
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                operation TEXT NOT NULL,
                params_json TEXT NOT NULL,
                context_json TEXT NOT NULL,
                decision TEXT,
                status TEXT NOT NULL,
                reason TEXT,
                risk_level TEXT,
                approval_token TEXT,
                policy_version TEXT,
                tenant_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        cur.execute(
            """
            ALTER TABLE actions
            ADD COLUMN IF NOT EXISTS policy_version TEXT;
            """
        )

        cur.execute(
            """
            ALTER TABLE actions
            ADD COLUMN IF NOT EXISTS tenant_id TEXT;
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_actions_created_at
            ON actions (created_at);
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_actions_agent_tool
            ON actions (agent_id, tool, operation);
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_actions_status
            ON actions (status);
            """
        )
        
        # Create action_events table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS action_events (
                id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                meta_json TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_action_events_action_id
            ON action_events (action_id);
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_action_events_created_at
            ON action_events (created_at);
            """
        )

        conn.commit()
        conn.close()

    def create_action(self, action: Action) -> None:
        self._ensure_initialized()
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO actions (
                id, agent_id, tool, operation,
                params_json, context_json,
                decision, status, reason, risk_level,
                approval_token, policy_version, tenant_id,
                created_at, updated_at
            )
            VALUES (
                %(id)s, %(agent_id)s, %(tool)s, %(operation)s,
                %(params_json)s, %(context_json)s,
                %(decision)s, %(status)s, %(reason)s, %(risk_level)s,
                %(approval_token)s, %(policy_version)s, %(tenant_id)s,
                %(created_at)s, %(updated_at)s
            )
            """,
            {
                "id": action.id,
                "agent_id": action.agent_id,
                "tool": action.tool,
                "operation": action.operation,
                "params_json": json.dumps(action.params),
                "context_json": json.dumps(action.context),
                "decision": action.decision.value if action.decision else None,
                "status": action.status.value,
                "reason": action.reason,
                "risk_level": action.risk_level,
                "approval_token": action.approval_token,
                "policy_version": getattr(action, "policy_version", None),
                "tenant_id": getattr(action, "tenant_id", None),
                "created_at": action.created_at.isoformat(),
                "updated_at": action.updated_at.isoformat(),
            },
        )
        conn.commit()
        conn.close()

    def update_action(self, action: Action) -> None:
        self._ensure_initialized()
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE actions SET
                agent_id = %(agent_id)s,
                tool = %(tool)s,
                operation = %(operation)s,
                params_json = %(params_json)s,
                context_json = %(context_json)s,
                decision = %(decision)s,
                status = %(status)s,
                reason = %(reason)s,
                risk_level = %(risk_level)s,
                approval_token = %(approval_token)s,
                policy_version = %(policy_version)s,
                tenant_id = %(tenant_id)s,
                updated_at = %(updated_at)s
            WHERE id = %(id)s
            """,
            {
                "id": action.id,
                "agent_id": action.agent_id,
                "tool": action.tool,
                "operation": action.operation,
                "params_json": json.dumps(action.params),
                "context_json": json.dumps(action.context),
                "decision": action.decision.value if action.decision else None,
                "status": action.status.value,
                "reason": action.reason,
                "risk_level": action.risk_level,
                "approval_token": action.approval_token,
                "policy_version": getattr(action, "policy_version", None),
                "tenant_id": getattr(action, "tenant_id", None),
                "updated_at": action.updated_at.isoformat(),
            },
        )
        conn.commit()
        conn.close()

    def get_action(self, action_id: str) -> Optional[Action]:
        self._ensure_initialized()
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM actions WHERE id = %s", (action_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return Action.from_row(row)

    def list_actions(
        self,
        limit: int = 100,
        offset: int = 0,
        **filters: Dict[str, Any],
    ) -> List[Action]:
        """
        List actions with filtering support.
        Filters: agent_id, tool, status (tenant_id ignored in core)
        """
        self._ensure_initialized()
        conn = self._connect()
        cur = conn.cursor()
        
        where_clauses = []
        params = []
        
        if filters.get("agent_id"):
            where_clauses.append("agent_id = %s")
            params.append(filters["agent_id"])
        
        if filters.get("tool"):
            where_clauses.append("tool = %s")
            params.append(filters["tool"])
        
        if filters.get("status"):
            where_clauses.append("status = %s")
            params.append(filters["status"])
        
        # tenant_id filtering ignored in core (kept for compatibility)
        
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
        
        params.extend([limit, offset])
        
        query = f"""
            SELECT * FROM actions
            {where_sql}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """
        
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
        return [Action.from_row(r) for r in rows]

    def count_actions(self) -> int:
        """Count total actions in the database."""
        self._ensure_initialized()
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as count FROM actions")
        row = cur.fetchone()
        conn.close()
        return row['count'] if row else 0

    def seed_demo_actions(self, actions: List[Action]) -> None:
        """Insert demo actions. Assumes actions don't already exist."""
        for action in actions:
            self.create_action(action)

    def create_event(
        self,
        action_id: str,
        event_type: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create an event in the action_events table."""
        import uuid as uuid_module
        from datetime import datetime
        import json
        
        self._ensure_initialized()
        event_id = str(uuid_module.uuid4())
        now = datetime.utcnow().isoformat()
        meta_json = json.dumps(meta) if meta else None
        
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO action_events (id, action_id, event_type, meta_json, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (event_id, action_id, event_type, meta_json, now),
        )
        conn.commit()
        conn.close()

    def get_events(self, action_id: str) -> List[Dict[str, Any]]:
        """Get all events for an action, ordered by created_at."""
        import json
        
        self._ensure_initialized()
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, action_id, event_type, meta_json, created_at
            FROM action_events
            WHERE action_id = %s
            ORDER BY created_at ASC
            """,
            (action_id,),
        )
        rows = cur.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = {
                "id": row["id"],
                "action_id": row["action_id"],
                "event_type": row["event_type"],
                "meta": json.loads(row["meta_json"]) if row["meta_json"] else {},
                "created_at": row["created_at"],
            }
            events.append(event)
        return events
