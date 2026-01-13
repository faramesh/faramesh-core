import { Action } from '../types';
import StatusBadge from './StatusBadge';
import { useEvents } from '../hooks/useEvents';

interface ActionDetailsProps {
  action: Action | null;
  isOpen: boolean;
  onClose: () => void;
  onApprove: (id: string) => Promise<void>;
  onDeny: (id: string) => Promise<void>;
}

export default function ActionDetails({
  action,
  isOpen,
  onClose,
  onApprove,
  onDeny,
}: ActionDetailsProps) {
  const { events, loading: eventsLoading } = useEvents(action?.id || null);
  const isDemo = action?.context?.demo === true || action?.agent_id === 'demo';

  if (!isOpen || !action) return null;

  const handleApprove = async () => {
    await onApprove(action.id);
  };

  const handleDeny = async () => {
    await onDeny(action.id);
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 bottom-0 w-full max-w-2xl bg-white dark:bg-navy border-l border-gray-200 dark:border-gray-700 z-50 shadow-xl overflow-y-auto">
        <div className="p-6">
          {/* Header */}
          <div className="flex items-center justify-between mb-6 pb-4 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">Action Details</h2>
              {isDemo && (
                <span className="px-2 py-0.5 bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400 text-xs font-medium rounded border border-yellow-300 dark:border-yellow-700">
                  DEMO
                </span>
              )}
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 text-2xl leading-none"
            >
              ×
            </button>
          </div>

          {/* Content */}
          <div className="space-y-6">
            {/* Status */}
            <div>
              <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                Status
              </label>
              <StatusBadge status={action.status} />
            </div>

            {/* ID */}
            <div>
              <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                ID
              </label>
              <div className="font-mono text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-3 rounded border border-gray-200 dark:border-gray-700">
                {action.id}
              </div>
            </div>

            {/* Agent ID */}
            <div>
              <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                Agent ID
              </label>
              <div className="text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-3 rounded border border-gray-200 dark:border-gray-700">
                {action.agent_id}
              </div>
            </div>

            {/* Tool & Operation */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                  Tool
                </label>
                <div className="text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-3 rounded border border-gray-200 dark:border-gray-700">
                  {action.tool}
                </div>
              </div>
              <div>
                <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                  Operation
                </label>
                <div className="text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-3 rounded border border-gray-200 dark:border-gray-700">
                  {action.operation}
                </div>
              </div>
            </div>

            {/* Decision */}
            <div>
              <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                Decision
              </label>
              <div className="text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-3 rounded border border-gray-200 dark:border-gray-700">
                {action.decision || 'N/A'}
              </div>
              {action.reason && (
                <div className="mt-2 text-sm text-gray-600 dark:text-gray-400 italic">
                  {action.reason}
                </div>
              )}
            </div>

            {/* Parameters */}
            <div>
              <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                Parameters
              </label>
              <pre className="text-xs text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-4 rounded border border-gray-200 dark:border-gray-700 overflow-x-auto">
                {JSON.stringify(action.params, null, 2)}
              </pre>
            </div>

            {/* Context */}
            {action.context && Object.keys(action.context).length > 0 && (
              <div>
                <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                  Context
                </label>
                <pre className="text-xs text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-4 rounded border border-gray-200 dark:border-gray-700 overflow-x-auto">
                  {JSON.stringify(action.context, null, 2)}
                </pre>
              </div>
            )}

            {/* Timeline */}
            <div>
              <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                Timeline
              </label>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Created:</span>
                  <span className="text-gray-900 dark:text-gray-100">
                    {new Date(action.created_at).toLocaleString()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Updated:</span>
                  <span className="text-gray-900 dark:text-gray-100">
                    {new Date(action.updated_at).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>

            {/* Risk Level */}
            {action.risk_level && (
              <div>
                <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                  Risk Level
                </label>
                <div className="text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-3 rounded border border-gray-200 dark:border-gray-700">
                  {action.risk_level}
                </div>
              </div>
            )}

            {/* Policy Version */}
            {action.policy_version && (
              <div>
                <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                  Policy Version
                </label>
                <div className="text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-3 rounded border border-gray-200 dark:border-gray-700">
                  {action.policy_version}
                </div>
              </div>
            )}

            {/* Approval Token */}
            {(action.status === 'pending_approval' || action.status === 'approved') && action.approval_token && (
              <div>
                <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                  Approval Token
                </label>
                <div className="font-mono text-xs text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-3 rounded border border-gray-200 dark:border-gray-700 break-all">
                  {action.approval_token}
                </div>
              </div>
            )}

            {/* Curl Commands */}
            <div>
              <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                Curl Commands
              </label>
              <div className="space-y-2">
                {action.status === 'pending_approval' && action.approval_token ? (
                  <>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={async () => {
                          const config = (window as any).FARACORE_CONFIG || {};
                          const apiBase = config.apiBase || window.location.origin;
                          const token = localStorage.getItem('auth_token') || '';
                          const authHeader = token ? ` -H "Authorization: Bearer ${token}"` : '';
                          const curl = `curl -X POST ${apiBase}/v1/actions/${action.id}/approval${authHeader} \\
  -H "Content-Type: application/json" \\
  -d '{"token": "${action.approval_token}", "approve": true}'`;
                          await navigator.clipboard.writeText(curl);
                        }}
                        className="px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-medium transition-colors"
                      >
                        Copy Approve Curl
                      </button>
                      <button
                        onClick={async () => {
                          const config = (window as any).FARACORE_CONFIG || {};
                          const apiBase = config.apiBase || window.location.origin;
                          const token = localStorage.getItem('auth_token') || '';
                          const authHeader = token ? ` -H "Authorization: Bearer ${token}"` : '';
                          const curl = `curl -X POST ${apiBase}/v1/actions/${action.id}/approval${authHeader} \\
  -H "Content-Type: application/json" \\
  -d '{"token": "${action.approval_token}", "approve": false}'`;
                          await navigator.clipboard.writeText(curl);
                        }}
                        className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition-colors"
                      >
                        Copy Deny Curl
                      </button>
                    </div>
                  </>
                ) : action.status === 'approved' || action.status === 'allowed' ? (
                  <button
                    onClick={async () => {
                      const config = (window as any).FARACORE_CONFIG || {};
                      const apiBase = config.apiBase || window.location.origin;
                      const token = localStorage.getItem('auth_token') || '';
                      const authHeader = token ? ` -H "Authorization: Bearer ${token}"` : '';
                      const curl = `curl -X POST ${apiBase}/v1/actions/${action.id}/start${authHeader}`;
                      await navigator.clipboard.writeText(curl);
                    }}
                    className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition-colors"
                  >
                    Copy Start Curl
                  </button>
                ) : (
                  <div className="text-sm text-gray-500 dark:text-gray-400 italic">
                    No followup supported for this status.
                  </div>
                )}
              </div>
            </div>

            {/* Event Timeline */}
            <div>
              <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 block">
                Event Timeline
              </label>
              {eventsLoading ? (
                <div className="text-sm text-gray-500 dark:text-gray-400">Loading events...</div>
              ) : events.length === 0 ? (
                <div className="text-sm text-gray-500 dark:text-gray-400 italic">No events yet</div>
              ) : (
                <div className="space-y-2">
                  {events.map((event, idx) => (
                    <div
                      key={event.id}
                      className="flex items-start gap-3 p-3 bg-gray-50 dark:bg-charcoal rounded border border-gray-200 dark:border-gray-700"
                    >
                      <div className="flex-shrink-0 w-2 h-2 rounded-full bg-blue-500 mt-1.5" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                            {event.event_type}
                          </span>
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            {new Date(event.created_at).toLocaleString()}
                          </span>
                        </div>
                        {event.meta && Object.keys(event.meta).length > 0 && (
                          <div className="text-xs text-gray-600 dark:text-gray-400 font-mono bg-white dark:bg-navy p-2 rounded border border-gray-200 dark:border-gray-700">
                            {JSON.stringify(event.meta, null, 2)}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Action Buttons */}
            {action.status === 'pending_approval' && (
              <div className="flex gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  onClick={handleApprove}
                  className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition-colors"
                >
                  Approve
                </button>
                <button
                  onClick={handleDeny}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors"
                >
                  Deny
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
