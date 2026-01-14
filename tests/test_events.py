"""Tests for event ledger functionality."""


from faramesh.server.models import Action
from faramesh.server.storage import SQLiteStore


def test_create_event():
    """Test creating an event."""
    import os
    import tempfile
    
    # Use temp file instead of :memory: to ensure persistence
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
        db_path = f.name
    
    try:
        store = SQLiteStore(db_path)
        
        # Create an action first
        action = Action.new(
            agent_id="test",
            tool="http",
            operation="get",
            params={"url": "https://example.com"},
        )
        store.create_action(action)
        
        # Create event
        store.create_event(action.id, "created", {"test": "data"})
        
        # Retrieve events
        events = store.get_events(action.id)
        assert len(events) == 1
        assert events[0]["event_type"] == "created"
        assert events[0]["meta"]["test"] == "data"
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_multiple_events():
    """Test multiple events for an action."""
    import os
    import tempfile
    
    # Use temp file instead of :memory: to ensure persistence
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
        db_path = f.name
    
    try:
        store = SQLiteStore(db_path)
        
        action = Action.new(
            agent_id="test",
            tool="shell",
            operation="run",
            params={"cmd": "echo test"},
        )
        store.create_action(action)
        
        # Create multiple events
        store.create_event(action.id, "created", {})
        store.create_event(action.id, "decision_made", {"decision": "require_approval"})
        store.create_event(action.id, "approved", {"reason": "test"})
        
        events = store.get_events(action.id)
        assert len(events) == 3
        assert events[0]["event_type"] == "created"
        assert events[1]["event_type"] == "decision_made"
        assert events[2]["event_type"] == "approved"
        
        # Events should be ordered by created_at
        assert events[0]["created_at"] <= events[1]["created_at"]
        assert events[1]["created_at"] <= events[2]["created_at"]
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)
