"""
Minimal client for Faramesh integrations.

This is a lightweight client included in faramesh-core so integrations
can work without requiring the separate faramesh-sdk package.

For full SDK features, install: pip install faramesh-sdk
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests


class ExecutionGovernorClient:
    """
    Minimal client for Faramesh API.
    
    This is a simplified client for use by integrations.
    For full SDK features, use the faramesh-sdk package.
    """
    
    def __init__(self, base_url: str = "http://127.0.0.1:8000", token: Optional[str] = None):
        """
        Initialize client.
        
        Args:
            base_url: Faramesh server URL
            token: Optional authentication token
        """
        self.base_url = base_url.rstrip('/')
        self.token = token
        self._headers = {}
        if token:
            self._headers['Authorization'] = f'Bearer {token}'
    
    def submit_action(
        self,
        tool: str,
        operation: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Submit an action for governance evaluation.
        
        Args:
            tool: Tool name
            operation: Operation name
            params: Action parameters
            context: Optional context
            agent_id: Optional agent ID (can be in context)
        
        Returns:
            Action response dict
        """
        if agent_id and context:
            context['agent_id'] = agent_id
        elif agent_id:
            context = {'agent_id': agent_id}
        
        payload = {
            'tool': tool,
            'operation': operation,
            'params': params,
        }
        if context:
            payload['context'] = context
        
        response = requests.post(
            f'{self.base_url}/v1/actions',
            json=payload,
            headers=self._headers,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def get_action(self, action_id: str) -> Dict[str, Any]:
        """
        Get an action by ID.
        
        Args:
            action_id: Action ID
        
        Returns:
            Action dict
        """
        response = requests.get(
            f'{self.base_url}/v1/actions/{action_id}',
            headers=self._headers,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def report_result(
        self,
        action_id: str,
        success: bool,
        result: Any = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Report action execution result.
        
        Args:
            action_id: Action ID
            success: Whether execution succeeded
            result: Result data (if success)
            error: Error message (if not success)
        
        Returns:
            Updated action dict
        """
        payload = {
            'success': success,
        }
        if result is not None:
            payload['result'] = result
        if error:
            payload['error'] = error
        
        response = requests.post(
            f'{self.base_url}/v1/actions/{action_id}/result',
            json=payload,
            headers=self._headers,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
