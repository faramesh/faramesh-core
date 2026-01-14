# src/faramesh/server/events.py
from __future__ import annotations

import asyncio
import json
from collections import deque
from datetime import datetime
from typing import Any, Dict, Optional, Set

from fastapi import Request
from fastapi.responses import StreamingResponse

from .models import Action


class EventManager:
    """Manages SSE connections and event broadcasting."""
    
    def __init__(self):
        self.connections: Set[asyncio.Queue] = set()
        self.event_buffer: deque = deque(maxlen=1000)  # Keep last 1000 events
        self.connection_limits: Dict[str, int] = {}  # Track connections per IP
        self.max_connections_per_ip = 5
        self.max_queue_size = 100
    
    async def subscribe(self, request: Request, filters: Optional[Dict[str, Any]] = None) -> asyncio.Queue:
        """Subscribe a client to events with optional filters."""
        # Check connection limits with defensive None check
        try:
            client_ip = request.client.host if request.client and hasattr(request.client, 'host') else "unknown"
        except (AttributeError, TypeError):
            client_ip = "unknown"
        
        current_count = self.connection_limits.get(client_ip, 0)
        if current_count >= self.max_connections_per_ip:
            raise Exception(f"Connection limit exceeded for {client_ip}")
        
        queue = asyncio.Queue(maxsize=self.max_queue_size)
        queue.filters = filters or {}
        self.connections.add(queue)
        self.connection_limits[client_ip] = current_count + 1
        
        # Send recent events from buffer
        for event in list(self.event_buffer)[-10:]:  # Last 10 events
            if self._matches_filters(event, queue.filters):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    # Skip if queue is full (backpressure)
                    break
        
        return queue
    
    def unsubscribe(self, queue: asyncio.Queue, client_ip: str = "unknown") -> None:
        """Unsubscribe a client."""
        self.connections.discard(queue)
        current_count = self.connection_limits.get(client_ip, 0)
        if current_count > 0:
            self.connection_limits[client_ip] = current_count - 1
    
    def _matches_filters(self, event: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if event matches filters."""
        if not filters:
            return True
        
        data = event.get("data", {})
        
        if filters.get("action_id") and data.get("id") != filters["action_id"]:
            return False
        if filters.get("status") and data.get("status") != filters["status"]:
            return False
        if filters.get("agent_id") and data.get("agent_id") != filters["agent_id"]:
            return False
        
        return True
    
    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast an event to all subscribers."""
        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        
        # Add to buffer
        self.event_buffer.append(event)
        
        # Broadcast to all connections
        disconnected = set()
        for queue in self.connections:
            if self._matches_filters(event, getattr(queue, "filters", {})):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    # Queue full - disconnect this client (backpressure)
                    disconnected.add(queue)
        
        # Clean up disconnected clients
        for queue in disconnected:
            self.connections.discard(queue)
    
    async def stream_events(self, request: Request, filters: Optional[Dict[str, Any]] = None):
        """Stream events as Server-Sent Events."""
        queue = await self.subscribe(request, filters)
        try:
            client_ip = request.client.host if request.client and hasattr(request.client, 'host') else "unknown"
        except (AttributeError, TypeError):
            client_ip = "unknown"
        
        async def event_generator():
            try:
                while True:
                    # Check if client disconnected
                    if await request.is_disconnected():
                        break
                    
                    try:
                        # Wait for event with timeout
                        event = await asyncio.wait_for(queue.get(), timeout=30.0)
                        
                        # Format as SSE with safe JSON serialization
                        try:
                            event_json = json.dumps(event, default=str)
                        except (TypeError, ValueError) as e:
                            import logging
                            logging.warning(f"Failed to serialize event: {e}")
                            continue
                        yield f"data: {event_json}\n\n"
                        
                        # Send keep-alive
                        yield ": keepalive\n\n"
                    except asyncio.TimeoutError:
                        # Send keep-alive ping
                        yield ": ping\n\n"
                    except Exception as e:
                        import logging
                        logging.error(f"Error in event stream: {e}")
                        break
            finally:
                self.unsubscribe(queue, client_ip)
        
        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            }
        )


# Global event manager instance
_event_manager: Optional[EventManager] = None


def get_event_manager() -> EventManager:
    """Get or create the global event manager."""
    global _event_manager
    if _event_manager is None:
        _event_manager = EventManager()
    return _event_manager


async def emit_action_event(event_type: str, action: Action) -> None:
    """Emit an action event to all subscribers."""
    if not action:
        import logging
        logging.warning("Attempted to emit event for None action")
        return
    
    try:
        manager = get_event_manager()
        await manager.broadcast(
            event_type,
            {
                "id": getattr(action, "id", "unknown"),
                "status": action.status.value if hasattr(action, "status") and action.status else "unknown",
                "decision": action.decision.value if hasattr(action, "decision") and action.decision else None,
                "agent_id": getattr(action, "agent_id", "unknown"),
                "tool": getattr(action, "tool", "unknown"),
                "operation": getattr(action, "operation", "unknown"),
                "reason": getattr(action, "reason", None),
                "risk_level": getattr(action, "risk_level", None),
            }
        )
    except Exception as e:
        import logging
        logging.error(f"Failed to emit action event {event_type}: {e}")
        # Don't raise - events are best-effort
