import { useState, useEffect } from 'react';

const config = (window as any).FARACORE_CONFIG || {
  apiBase: window.location.origin,
};

const apiBase = config.apiBase || window.location.origin;

export interface ActionEvent {
  id: string;
  action_id: string;
  event_type: string;
  meta: Record<string, any>;
  created_at: string;
}

export function useEvents(actionId: string | null) {
  const [events, setEvents] = useState<ActionEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!actionId) {
      setEvents([]);
      return;
    }

    const fetchEvents = async () => {
      try {
        setLoading(true);
        const response = await fetch(`${apiBase}/v1/actions/${actionId}/events`);
        if (!response.ok) throw new Error('Failed to load events');
        const data = await response.json();
        setEvents(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load events');
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
  }, [actionId]);

  return { events, loading, error };
}
