# src/faramesh/server/storage.py
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Action
from .settings import get_settings
from .storage_postgres import PostgresStore

# --- SQLite implementation -------------------------------------------------


class SQLiteStore:
    def __init__(self, path: str = "data/actions.db"):
        self.path = Path(path) if path != ":memory:" else path
        if isinstance(self.path, Path):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        path = str(self.path) if isinstance(self.path, Path) else self.path
        # Add timeout to prevent indefinite hangs on locked database
        conn = sqlite3.connect(path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._connect()
        try:
            conn.execute(
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
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    approval_token TEXT,
                    policy_version TEXT,
                    tenant_id TEXT,
                    version INTEGER DEFAULT 1
                );
                """
            )
            # Add columns if they don't exist (for existing databases)
            new_columns = [
                "policy_version TEXT",
                "tenant_id TEXT",
                "version INTEGER DEFAULT 1",
                "outcome TEXT",
                "reason_code TEXT",
                "reason_details_json TEXT",
                "request_hash TEXT",
                "policy_hash TEXT",
                "runtime_version TEXT",
                "profile_id TEXT",
                "profile_version TEXT",
                "profile_hash TEXT",
                "provenance_id TEXT",
            ]
            for col_def in new_columns:
                try:
                    conn.execute(f"ALTER TABLE actions ADD COLUMN {col_def}")
                except sqlite3.OperationalError:
                    pass  # Column already exists
            
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_actions_created_at
                ON actions (created_at);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_actions_agent_tool
                ON actions (agent_id, tool, operation);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_actions_status
                ON actions (status);
                """
            )
            # Create action_events table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS action_events (
                    id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    meta_json TEXT,
                    created_at TEXT NOT NULL,
                    prev_hash TEXT,
                    record_hash TEXT,
                    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE
                );
                """
            )
            # Add hash chain columns if they don't exist
            try:
                conn.execute("ALTER TABLE action_events ADD COLUMN prev_hash TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE action_events ADD COLUMN record_hash TEXT")
            except sqlite3.OperationalError:
                pass
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_action_events_action_id
                ON action_events (action_id);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_action_events_created_at
                ON action_events (created_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def create_action(self, action: Action) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO actions (
                    id, agent_id, tool, operation,
                    params_json, context_json,
                    decision, status, reason, risk_level,
                    created_at, updated_at, approval_token,
                    policy_version, tenant_id, version,
                    outcome, reason_code, reason_details_json,
                    request_hash, policy_hash, runtime_version,
                    profile_id, profile_version, profile_hash, provenance_id
                )
                VALUES (
                    :id, :agent_id, :tool, :operation,
                    :params_json, :context_json,
                    :decision, :status, :reason, :risk_level,
                    :created_at, :updated_at, :approval_token,
                    :policy_version, :tenant_id, :version,
                    :outcome, :reason_code, :reason_details_json,
                    :request_hash, :policy_hash, :runtime_version,
                    :profile_id, :profile_version, :profile_hash, :provenance_id
                )
                """,
                {
                    "id": action.id,
                    "agent_id": action.agent_id,
                    "tool": action.tool,
                    "operation": action.operation,
                    "params_json": json.dumps(action.params, default=str),
                    "context_json": json.dumps(action.context, default=str),
                    "decision": action.decision.value if action.decision else None,
                    "status": action.status.value,
                    "reason": action.reason,
                    "risk_level": action.risk_level,
                    "created_at": action.created_at.isoformat() if hasattr(action.created_at, 'isoformat') else datetime.utcnow().isoformat(),
                    "updated_at": action.updated_at.isoformat() if hasattr(action.updated_at, 'isoformat') else datetime.utcnow().isoformat(),
                    "approval_token": action.approval_token,
                    "policy_version": getattr(action, "policy_version", None),
                    "tenant_id": getattr(action, "tenant_id", None),
                    "version": getattr(action, "version", 1),
                    "outcome": action.outcome.value if action.outcome else None,
                    "reason_code": action.reason_code,
                    "reason_details_json": json.dumps(action.reason_details, default=str) if action.reason_details else None,
                    "request_hash": action.request_hash,
                    "policy_hash": action.policy_hash,
                    "runtime_version": action.runtime_version,
                    "profile_id": action.profile_id,
                    "profile_version": action.profile_version,
                    "profile_hash": action.profile_hash,
                    "provenance_id": action.provenance_id,
                },
            )
            conn.commit()
        except sqlite3.Error as e:
            import logging
            logging.error(f"Database error in create_action: {e}")
            raise
        finally:
            conn.close()

    def update_action(self, action: Action, expected_version: Optional[int] = None) -> bool:
        """
        Update action with optimistic locking.
        
        Args:
            action: Action to update
            expected_version: Expected version for optimistic locking (None to skip check)
            
        Returns:
            True if update succeeded, False if version mismatch (optimistic lock failed)
        """
        conn = self._connect()
        try:
            # Increment version
            new_version = (action.version or 1) + 1
            
            # Build update query with optional version check
            if expected_version is not None:
                # Optimistic locking: only update if version matches
                result = conn.execute(
                    """
                    UPDATE actions
                    SET
                        agent_id = :agent_id,
                        tool = :tool,
                        operation = :operation,
                        params_json = :params_json,
                        context_json = :context_json,
                        decision = :decision,
                        status = :status,
                        reason = :reason,
                        risk_level = :risk_level,
                        updated_at = :updated_at,
                        approval_token = :approval_token,
                        policy_version = :policy_version,
                        tenant_id = :tenant_id,
                        version = :version,
                        outcome = :outcome,
                        reason_code = :reason_code,
                        reason_details_json = :reason_details_json,
                        request_hash = :request_hash,
                        policy_hash = :policy_hash,
                        runtime_version = :runtime_version,
                        profile_id = :profile_id,
                        profile_version = :profile_version,
                        profile_hash = :profile_hash,
                        provenance_id = :provenance_id
                    WHERE id = :id AND version = :expected_version
                    """,
                    {
                        "id": action.id,
                        "agent_id": action.agent_id,
                        "tool": action.tool,
                        "operation": action.operation,
                        "params_json": json.dumps(action.params, default=str),
                        "context_json": json.dumps(action.context, default=str),
                        "decision": action.decision.value if action.decision else None,
                        "status": action.status.value,
                        "reason": action.reason,
                        "risk_level": action.risk_level,
                        "updated_at": action.updated_at.isoformat() if hasattr(action.updated_at, 'isoformat') else datetime.utcnow().isoformat(),
                        "approval_token": action.approval_token,
                        "policy_version": getattr(action, "policy_version", None),
                        "tenant_id": getattr(action, "tenant_id", None),
                        "version": new_version,
                        "expected_version": expected_version,
                        "outcome": action.outcome.value if action.outcome else None,
                        "reason_code": action.reason_code,
                        "reason_details_json": json.dumps(action.reason_details, default=str) if action.reason_details else None,
                        "request_hash": action.request_hash,
                        "policy_hash": action.policy_hash,
                        "runtime_version": action.runtime_version,
                        "profile_id": action.profile_id,
                        "profile_version": action.profile_version,
                        "profile_hash": action.profile_hash,
                        "provenance_id": action.provenance_id,
                    },
                )
                # Check if any rows were updated
                if result.rowcount == 0:
                    return False  # Version mismatch
            else:
                # No version check, just update
                result = conn.execute(
                    """
                    UPDATE actions
                    SET
                        agent_id = :agent_id,
                        tool = :tool,
                        operation = :operation,
                        params_json = :params_json,
                        context_json = :context_json,
                        decision = :decision,
                        status = :status,
                        reason = :reason,
                        risk_level = :risk_level,
                        updated_at = :updated_at,
                        approval_token = :approval_token,
                        policy_version = :policy_version,
                        tenant_id = :tenant_id,
                        version = :version,
                        outcome = :outcome,
                        reason_code = :reason_code,
                        reason_details_json = :reason_details_json,
                        request_hash = :request_hash,
                        policy_hash = :policy_hash,
                        runtime_version = :runtime_version,
                        profile_id = :profile_id,
                        profile_version = :profile_version,
                        profile_hash = :profile_hash,
                        provenance_id = :provenance_id
                    WHERE id = :id
                    """,
                    {
                        "id": action.id,
                        "agent_id": action.agent_id,
                        "tool": action.tool,
                        "operation": action.operation,
                        "params_json": json.dumps(action.params, default=str),
                        "context_json": json.dumps(action.context, default=str),
                        "decision": action.decision.value if action.decision else None,
                        "status": action.status.value,
                        "reason": action.reason,
                        "risk_level": action.risk_level,
                        "updated_at": action.updated_at.isoformat() if hasattr(action.updated_at, 'isoformat') else datetime.utcnow().isoformat(),
                        "approval_token": action.approval_token,
                        "policy_version": getattr(action, "policy_version", None),
                        "tenant_id": getattr(action, "tenant_id", None),
                        "version": new_version,
                        "outcome": action.outcome.value if action.outcome else None,
                        "reason_code": action.reason_code,
                        "reason_details_json": json.dumps(action.reason_details, default=str) if action.reason_details else None,
                        "request_hash": action.request_hash,
                        "policy_hash": action.policy_hash,
                        "runtime_version": action.runtime_version,
                        "profile_id": action.profile_id,
                        "profile_version": action.profile_version,
                        "profile_hash": action.profile_hash,
                        "provenance_id": action.provenance_id,
                    },
                )
                # Check if action exists (rowcount > 0)
                if result.rowcount == 0:
                    return False  # Action not found
            
            # Update action object with new version
            action.version = new_version
            conn.commit()
            return True
        except sqlite3.Error as e:
            import logging
            logging.error(f"Database error in update_action: {e}")
            raise
        finally:
            conn.close()

    def get_action(self, action_id: str) -> Optional[Action]:
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT * FROM actions WHERE id = ?",
                (action_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return Action.from_row(row)
        except sqlite3.Error as e:
            import logging
            logging.error(f"Database error in get_action: {e}")
            return None
        finally:
            conn.close()

    def list_actions(
        self,
        limit: int = 100,
        offset: int = 0,
        **filters: Dict[str, Any],
    ) -> List[Action]:
        """
        List actions with optional filtering.
        Filters: agent_id, tool, status (tenant_id ignored in core)
        """
        conn = self._connect()
        try:
            where_clauses = []
            params = []
            
            if filters.get("agent_id"):
                where_clauses.append("agent_id = ?")
                params.append(filters["agent_id"])
            
            if filters.get("tool"):
                where_clauses.append("tool = ?")
                params.append(filters["tool"])
            
            if filters.get("status"):
                where_clauses.append("status = ?")
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
                LIMIT ? OFFSET ?
            """
            
            try:
                cur = conn.execute(query, params)
                rows = cur.fetchall()
                return [Action.from_row(r) for r in rows]
            except sqlite3.Error as e:
                import logging
                logging.error(f"Database error in list_actions query: {e}")
                raise
        except sqlite3.Error as e:
            import logging
            logging.error(f"Database error in list_actions: {e}")
            return []  # Return empty list on error rather than crashing
        finally:
            conn.close()

    def count_actions(self) -> int:
        """Count total actions in the database."""
        conn = self._connect()
        try:
            cur = conn.execute("SELECT COUNT(*) as count FROM actions")
            row = cur.fetchone()
            return row[0] if row else 0
        finally:
            conn.close()

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
        """Create an event in the action_events table with hash chaining."""
        import uuid as uuid_module
        from .canonicalization import canonicalize_event_payload, compute_event_hash
        
        event_id = str(uuid_module.uuid4())
        now = datetime.utcnow().isoformat()
        
        # Safe JSON serialization
        try:
            meta_dict = meta if meta else {}
            meta_json = json.dumps(meta_dict, default=str) if meta_dict else None
        except (TypeError, ValueError) as e:
            import logging
            logging.warning(f"Failed to serialize event meta: {e}, using empty dict")
            meta_dict = {}
            meta_json = json.dumps({}, default=str)
        
        conn = self._connect()
        try:
            # Get previous event's record_hash for chaining
            prev_hash = None
            try:
                prev_cur = conn.execute(
                    """
                    SELECT record_hash FROM action_events
                    WHERE action_id = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (action_id,),
                )
                prev_row = prev_cur.fetchone()
                if prev_row and prev_row[0]:
                    prev_hash = prev_row[0]
            except sqlite3.Error:
                # No previous event or column doesn't exist yet
                pass
            
            # Build event dict for canonicalization
            event_dict = {
                "id": event_id,
                "action_id": action_id,
                "event_type": event_type,
                "created_at": now,
                "meta": meta_dict,
            }
            
            # Compute record_hash
            record_hash = compute_event_hash(event_dict, prev_hash)
            
            # Insert with hash chain fields
            conn.execute(
                """
                INSERT INTO action_events (id, action_id, event_type, meta_json, created_at, prev_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, action_id, event_type, meta_json, now, prev_hash, record_hash),
            )
            conn.commit()
        except sqlite3.Error as e:
            import logging
            logging.error(f"Database error in create_event: {e}")
            # Don't raise - events are best-effort
        finally:
            conn.close()

    def get_events(self, action_id: str) -> List[Dict[str, Any]]:
        """Get all events for an action, ordered by created_at."""
        conn = self._connect()
        try:
            # Try to get hash fields if they exist
            try:
                cur = conn.execute(
                    """
                    SELECT id, action_id, event_type, meta_json, created_at, prev_hash, record_hash
                    FROM action_events
                    WHERE action_id = ?
                    ORDER BY created_at ASC
                    """,
                    (action_id,),
                )
            except sqlite3.Error:
                # Fallback if hash columns don't exist yet
                cur = conn.execute(
                    """
                    SELECT id, action_id, event_type, meta_json, created_at
                    FROM action_events
                    WHERE action_id = ?
                    ORDER BY created_at ASC
                    """,
                    (action_id,),
                )
            
            rows = cur.fetchall()
            events = []
            for row in rows:
                # Safe JSON parsing with bounds checking
                try:
                    # Check if row has hash fields (7 columns) or not (5 columns)
                    has_hash_fields = len(row) >= 7
                    meta = json.loads(row[3]) if row[3] else {}
                except (json.JSONDecodeError, TypeError, IndexError) as e:
                    import logging
                    logging.warning(f"Failed to parse event meta: {e}")
                    meta = {}
                
                try:
                    event = {
                        "id": row[0],
                        "action_id": row[1],
                        "event_type": row[2],
                        "meta": meta,
                        "created_at": row[4],
                    }
                    if has_hash_fields:
                        event["prev_hash"] = row[5] if len(row) > 5 else None
                        event["record_hash"] = row[6] if len(row) > 6 else None
                    events.append(event)
                except (IndexError, TypeError) as e:
                    import logging
                    logging.warning(f"Failed to construct event from row: {e}")
                    continue
            return events
        except sqlite3.Error as e:
            import logging
            logging.error(f"Database error in get_events: {e}")
            return []
        finally:
            conn.close()


# --- Factory ---------------------------------------------------------------


def get_store():
    """
    Return the appropriate store instance depending on env config.
    """
    settings = get_settings()
    db_backend = settings.db_backend.lower().strip() if settings.db_backend else "sqlite"
    
    # Only use Postgres if explicitly set
    if db_backend == "postgres":
        # Test connection before creating PostgresStore
        try:
            import psycopg2
            test_conn = psycopg2.connect(settings.postgres_dsn, connect_timeout=2)
            test_conn.close()
            # Connection successful, create PostgresStore
            return PostgresStore(settings.postgres_dsn)
        except Exception as e:
            # Connection failed, fall back to SQLite
            import warnings
            warnings.warn(
                f"Failed to connect to PostgreSQL: {e}. Falling back to SQLite. "
                f"Set FARA_DB_BACKEND=sqlite to suppress this warning.",
                UserWarning
            )
            return SQLiteStore(settings.sqlite_path)
    
    # Default to SQLite
    return SQLiteStore(settings.sqlite_path)
