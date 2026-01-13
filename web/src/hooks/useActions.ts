import { useState, useEffect, useCallback } from 'react';
import { Action } from '../types';

const config = (window as any).FARACORE_CONFIG || {
  apiBase: window.location.origin,
  eventsEndpoint: '/v1/events',
};

const apiBase = config.apiBase || window.location.origin;

export function useActions() {
  const [actions, setActions] = useState<Action[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchActions = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(`${apiBase}/v1/actions?limit=1000`);
      if (!response.ok) throw new Error('Failed to load actions');
      const data = await response.json();
      setActions(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load actions');
    } finally {
      setLoading(false);
    }
  }, []);

  const updateAction = useCallback((updatedAction: Action) => {
    setActions((prev) => {
      const index = prev.findIndex((a) => a.id === updatedAction.id);
      if (index === -1) {
        return [updatedAction, ...prev];
      }
      const newActions = [...prev];
      newActions[index] = updatedAction;
      return newActions;
    });
  }, []);

  const approveAction = useCallback(async (actionId: string, reason?: string) => {
    try {
      const response = await fetch(`${apiBase}/v1/actions/${actionId}`);
      if (!response.ok) throw new Error('Failed to fetch action');
      const action = await response.json();
      
      if (!action.approval_token) {
        throw new Error('No approval token found');
      }

      const approveResponse = await fetch(`${apiBase}/v1/actions/${actionId}/approval`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: action.approval_token, approve: true, reason }),
      });

      if (!approveResponse.ok) {
        const error = await approveResponse.json().catch(() => ({ detail: 'Failed to approve' }));
        throw new Error(error.detail || 'Failed to approve');
      }

      const updated = await approveResponse.json();
      updateAction(updated);
      return { success: true };
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : 'Failed to approve' };
    }
  }, [updateAction]);

  const denyAction = useCallback(async (actionId: string, reason?: string) => {
    try {
      const response = await fetch(`${apiBase}/v1/actions/${actionId}`);
      if (!response.ok) throw new Error('Failed to fetch action');
      const action = await response.json();
      
      if (!action.approval_token) {
        throw new Error('No approval token found');
      }

      const denyResponse = await fetch(`${apiBase}/v1/actions/${actionId}/approval`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: action.approval_token, approve: false, reason }),
      });

      if (!denyResponse.ok) {
        const error = await denyResponse.json().catch(() => ({ detail: 'Failed to deny' }));
        throw new Error(error.detail || 'Failed to deny');
      }

      const updated = await denyResponse.json();
      updateAction(updated);
      return { success: true };
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : 'Failed to deny' };
    }
  }, [updateAction]);

  const startAction = useCallback(async (actionId: string) => {
    try {
      const response = await fetch(`${apiBase}/v1/actions/${actionId}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Failed to start' }));
        throw new Error(error.detail || 'Failed to start');
      }

      const updated = await response.json();
      updateAction(updated);
      return { success: true };
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : 'Failed to start' };
    }
  }, [updateAction]);

  useEffect(() => {
    fetchActions();
  }, [fetchActions]);

  return {
    actions,
    loading,
    error,
    refetch: fetchActions,
    updateAction,
    approveAction,
    denyAction,
    startAction,
  };
}
