import { useEffect, useState, useRef } from 'react';
import { Action, SSEEvent } from '../types';

const config = (window as any).FARACORE_CONFIG || {
  apiBase: window.location.origin,
  eventsEndpoint: '/v1/events',
};

export function useSSE(onActionUpdate: (action: Action) => void) {
  const [isConnected, setIsConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const apiBase = config.apiBase || window.location.origin;
    const eventsUrl = `${apiBase}${config.eventsEndpoint}`;

    const connect = () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      const eventSource = new EventSource(eventsUrl);
      eventSourceRef.current = eventSource;

      eventSource.onopen = () => {
        setIsConnected(true);
      };

      eventSource.onmessage = (event) => {
        try {
          const data: SSEEvent = JSON.parse(event.data);
          if (data.type === 'action.created' || data.type === 'action.updated') {
            onActionUpdate(data.data);
          }
        } catch (error) {
          console.error('Error parsing SSE event:', error);
        }
      };

      eventSource.onerror = () => {
        setIsConnected(false);
        eventSource.close();
        // Reconnect after 5 seconds
        setTimeout(connect, 5000);
      };
    };

    connect();

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [onActionUpdate]);

  return { isConnected };
}
