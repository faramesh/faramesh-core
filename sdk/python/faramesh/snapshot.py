"""In-memory action snapshot store for convenience.

This module provides a simple in-memory store for tracking actions locally.
It's an optional utility and not required for SDK usage.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any
from collections import deque


class ActionSnapshotStore:
    """In-memory store for action snapshots.
    
    This is a convenience helper for tracking actions locally.
    It's not required for SDK usage and is provided as an optional utility.
    
    Example:
        >>> store = ActionSnapshotStore()
        >>> store.add_action(action_dict)
        >>> recent = store.list_recent(limit=10)
        >>> action = store.get_action(action_id)
    """
    
    def __init__(self, max_size: int = 1000):
        """Initialize the store.
        
        Args:
            max_size: Maximum number of actions to store (default: 1000)
        """
        self._actions: Dict[str, Dict[str, Any]] = {}
        self._recent: deque = deque(maxlen=max_size)
    
    def add_action(self, action: Dict[str, Any]) -> None:
        """Add an action to the store.
        
        Args:
            action: Action dict (must have 'id' field)
        """
        action_id = action.get("id")
        if not action_id:
            raise ValueError("Action must have 'id' field")
        
        self._actions[action_id] = action
        self._recent.append(action_id)
    
    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Get an action by ID.
        
        Args:
            action_id: Action ID
        
        Returns:
            Action dict or None if not found
        """
        return self._actions.get(action_id)
    
    def list_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent actions.
        
        Args:
            limit: Maximum number of actions to return (default: 50)
        
        Returns:
            List of action dicts, most recent first
        """
        recent_ids = list(self._recent)[-limit:]
        return [self._actions[aid] for aid in reversed(recent_ids) if aid in self._actions]
    
    def clear(self) -> None:
        """Clear all stored actions."""
        self._actions.clear()
        self._recent.clear()


# Optional singleton instance
_default_store: Optional[ActionSnapshotStore] = None


def get_default_store() -> ActionSnapshotStore:
    """Get the default singleton store instance."""
    global _default_store
    if _default_store is None:
        _default_store = ActionSnapshotStore()
    return _default_store
