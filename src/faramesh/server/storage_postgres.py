# src/faramesh/server/storage_postgres.py
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

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
            ALTER TABLE actions
            ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
            """
        )
        
        # Add execution gate columns
        new_columns = [
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
            col_name = col_def.split()[0]
            cur.execute(
                f"""
                ALTER TABLE actions
                ADD COLUMN IF NOT EXISTS {col_def};
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
                created_at TEXT NOT NULL,
                prev_hash TEXT,
                record_hash TEXT
            );
            """
        )
        cur.execute(
            """
            ALTER TABLE action_events
            ADD COLUMN IF NOT EXISTS prev_hash TEXT;
            """
        )
        cur.execute(
            """
            ALTER TABLE action_events
            ADD COLUMN IF NOT EXISTS record_hash TEXT;
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
        try:
            cur = conn.cursor()
            cur.execute(
            """
            INSERT INTO actions (
                id, agent_id, tool, operation,
                params_json, context_json,
                decision, status, reason, risk_level,
                approval_token, policy_version, tenant_id,
                created_at, updated_at, version,
                outcome, reason_code, reason_details_json,
                request_hash, policy_hash, runtime_version,
                profile_id, profile_version, profile_hash, provenance_id
            )
            VALUES (
                %(id)s, %(agent_id)s, %(tool)s, %(operation)s,
                %(params_json)s, %(context_json)s,
                %(decision)s, %(status)s, %(reason)s, %(risk_level)s,
                %(approval_token)s, %(policy_version)s, %(tenant_id)s,
                %(created_at)s, %(updated_at)s, %(version)s,
                %(outcome)s, %(reason_code)s, %(reason_details_json)s,
                %(request_hash)s, %(policy_hash)s, %(runtime_version)s,
                %(profile_id)s, %(profile_version)s, %(profile_hash)s, %(provenance_id)s
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
                "approval_token": action.approval_token,
                "policy_version": getattr(action, "policy_version", None),
                "tenant_id": getattr(action, "tenant_id", None),
                "created_at": action.created_at.isoformat() if hasattr(action.created_at, 'isoformat') else datetime.utcnow().isoformat(),
                "updated_at": action.updated_at.isoformat() if hasattr(action.updated_at, 'isoformat') else datetime.utcnow().isoformat(),
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
        except Exception as e:
            import logging
            logging.error(f"Database error in create_action: {e}")
            conn.rollback()
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
            True if update succeeded, False if version mismatch or action not found
        """
        self._ensure_initialized()
        conn = self._connect()
        try:
            # Increment version
            new_version = (action.version or 1) + 1
            
            # Build update query with optional version check
            if expected_version is not None:
                # Optimistic locking: only update if version matches
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE actions
                    SET
                        agent_id = %(agent_id)s,
                        tool = %(tool)s,
                        operation = %(operation)s,
                        params_json = %(params_json)s,
                        context_json = %(context_json)s,
                        decision = %(decision)s,
                        status = %(status)s,
                        reason = %(reason)s,
                        risk_level = %(risk_level)s,
                        updated_at = %(updated_at)s,
                        approval_token = %(approval_token)s,
                        policy_version = %(policy_version)s,
                        tenant_id = %(tenant_id)s,
                        version = %(version)s,
                        outcome = %(outcome)s,
                        reason_code = %(reason_code)s,
                        reason_details_json = %(reason_details_json)s,
                        request_hash = %(request_hash)s,
                        policy_hash = %(policy_hash)s,
                        runtime_version = %(runtime_version)s,
                        profile_id = %(profile_id)s,
                        profile_version = %(profile_version)s,
                        profile_hash = %(profile_hash)s,
                        provenance_id = %(provenance_id)s
                    WHERE id = %(id)s AND version = %(expected_version)s
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
                if cur.rowcount == 0:
                    conn.rollback()
                    return False  # Version mismatch or action not found
            else:
                # No version check, just update
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE actions
                    SET
                        agent_id = %(agent_id)s,
                        tool = %(tool)s,
                        operation = %(operation)s,
                        params_json = %(params_json)s,
                        context_json = %(context_json)s,
                        decision = %(decision)s,
                        status = %(status)s,
                        reason = %(reason)s,
                        risk_level = %(risk_level)s,
                        updated_at = %(updated_at)s,
                        approval_token = %(approval_token)s,
                        policy_version = %(policy_version)s,
                        tenant_id = %(tenant_id)s,
                        version = %(version)s,
                        outcome = %(outcome)s,
                        reason_code = %(reason_code)s,
                        reason_details_json = %(reason_details_json)s,
                        request_hash = %(request_hash)s,
                        policy_hash = %(policy_hash)s,
                        runtime_version = %(runtime_version)s,
                        profile_id = %(profile_id)s,
                        profile_version = %(profile_version)s,
                        profile_hash = %(profile_hash)s,
                        provenance_id = %(provenance_id)s
                    WHERE id = %(id)s
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
                if cur.rowcount == 0:
                    conn.rollback()
                    return False  # Action not found
            
            # Update action object with new version
            action.version = new_version
            conn.commit()
            return True
        except Exception as e:
            import logging
            logging.error(f"Database error in update_action: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_action(self, action_id: str) -> Optional[Action]:
        self._ensure_initialized()
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM actions WHERE id = %s", (action_id,))
            row = cur.fetchone()
            if not row:
                return None
            return Action.from_row(row)
        except Exception as e:
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
        List actions with filtering support.
        Filters: agent_id, tool, status (tenant_id ignored in core)
        """
        self._ensure_initialized()
        conn = self._connect()
        try:
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
            
            try:
                cur.execute(query, params)
                rows = cur.fetchall()
                return [Action.from_row(r) for r in rows]
            except Exception as e:
                import logging
                logging.error(f"Database error in list_actions query: {e}")
                raise
        except Exception as e:
            import logging
            logging.error(f"Database error in list_actions: {e}")
            return []  # Return empty list on error rather than crashing
        finally:
            conn.close()

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
        """Create an event in the action_events table with hash chaining."""
        import json
        import logging
        import uuid as uuid_module
        from datetime import datetime
        from .canonicalization import canonicalize_event_payload, compute_event_hash
        
        self._ensure_initialized()
        event_id = str(uuid_module.uuid4())
        now = datetime.utcnow().isoformat()
        
        # Safe JSON serialization
        try:
            meta_dict = meta if meta else {}
            meta_json = json.dumps(meta_dict, default=str) if meta_dict else None
        except (TypeError, ValueError) as e:
            logging.warning(f"Failed to serialize event meta: {e}, using empty dict")
            meta_dict = {}
            meta_json = json.dumps({}, default=str)
        
        conn = self._connect()
        try:
            cur = conn.cursor()
            
            # Get previous event's record_hash for chaining
            prev_hash = None
            try:
                cur.execute(
                    """
                    SELECT record_hash FROM action_events
                    WHERE action_id = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (action_id,),
                )
                prev_row = cur.fetchone()
                if prev_row:
                    # RealDictCursor returns dict-like object
                    prev_hash = prev_row.get("record_hash") if hasattr(prev_row, "get") else (prev_row[0] if prev_row else None)
            except Exception:
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
            cur.execute(
                """
                INSERT INTO action_events (id, action_id, event_type, meta_json, created_at, prev_hash, record_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (event_id, action_id, event_type, meta_json, now, prev_hash, record_hash),
            )
            conn.commit()
        except Exception as e:
            import logging
            logging.error(f"Database error in create_event: {e}")
            conn.rollback()
            # Don't raise - events are best-effort
        finally:
            conn.close()

    def get_events(self, action_id: str) -> List[Dict[str, Any]]:
        """Get all events for an action, ordered by created_at."""
        import json
        import logging
        
        self._ensure_initialized()
        conn = self._connect()
        try:
            cur = conn.cursor()
            # Try to get hash fields if they exist
            try:
                cur.execute(
                    """
                    SELECT id, action_id, event_type, meta_json, created_at, prev_hash, record_hash
                    FROM action_events
                    WHERE action_id = %s
                    ORDER BY created_at ASC
                    """,
                    (action_id,),
                )
            except Exception:
                # Fallback if hash columns don't exist yet
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
            
            events = []
            for row in rows:
                # Safe JSON parsing with error handling
                try:
                    meta = json.loads(row.get("meta_json") or "{}") if row.get("meta_json") else {}
                except (json.JSONDecodeError, TypeError, KeyError) as e:
                    logging.warning(f"Failed to parse event meta: {e}")
                    meta = {}
                
                try:
                    event = {
                        "id": row.get("id", ""),
                        "action_id": row.get("action_id", ""),
                        "event_type": row.get("event_type", ""),
                        "meta": meta,
                        "created_at": row.get("created_at", ""),
                    }
                    # Add hash fields if they exist
                    if "prev_hash" in row:
                        event["prev_hash"] = row.get("prev_hash")
                    if "record_hash" in row:
                        event["record_hash"] = row.get("record_hash")
                    events.append(event)
                except (KeyError, TypeError) as e:
                    logging.warning(f"Failed to construct event from row: {e}")
                    continue
            return events
        except Exception as e:
            import logging
            logging.error(f"Database error in get_events: {e}")
            return []
        finally:
            conn.close()
