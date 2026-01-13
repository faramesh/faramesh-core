import { useState, useMemo } from 'react';
import { Action, ActionStatus } from '../types';
import StatusBadge from './StatusBadge';

interface ActionTableProps {
  actions: Action[];
  selectedActionId: string | null;
  onSelectAction: (action: Action) => void;
  searchQuery: string;
  statusFilter: ActionStatus | '';
  agentFilter: string;
  toolFilter: string;
  currentPage: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}

const getStatusRowClass = (status: ActionStatus): string => {
  const baseClass = 'transition-colors cursor-pointer hover:bg-gray-50 dark:hover:bg-charcoal';
  
  switch (status) {
    case 'pending_approval':
      return `${baseClass} bg-yellow-50/50 dark:bg-yellow-900/10 border-l-2 border-yellow-400`;
    case 'approved':
      return `${baseClass} bg-blue-50/50 dark:bg-blue-900/10 border-l-2 border-blue-400`;
    case 'allowed':
      return `${baseClass} bg-green-50/50 dark:bg-green-900/10 border-l-2 border-green-400`;
    case 'denied':
      return `${baseClass} bg-red-50/50 dark:bg-red-900/10 border-l-2 border-red-400`;
    case 'executing':
      return `${baseClass} bg-purple-50/50 dark:bg-purple-900/10 border-l-2 border-purple-400 animate-pulse`;
    case 'succeeded':
      return `${baseClass} bg-green-50 dark:bg-green-900/10 border-l-2 border-green-500`;
    case 'failed':
      return `${baseClass} bg-red-50 dark:bg-red-900/10 border-l-2 border-red-500`;
    default:
      return baseClass;
  }
};

const truncateId = (id: string): string => {
  return id.length > 8 ? `${id.substring(0, 8)}...` : id;
};

export default function ActionTable({
  actions,
  selectedActionId,
  onSelectAction,
  searchQuery,
  statusFilter,
  agentFilter,
  toolFilter,
  currentPage,
  pageSize,
  onPageChange,
}: ActionTableProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredActions = useMemo(() => {
    return actions.filter((action) => {
      if (statusFilter && action.status !== statusFilter) return false;
      if (agentFilter && !action.agent_id.toLowerCase().includes(agentFilter.toLowerCase())) return false;
      if (toolFilter && !action.tool.toLowerCase().includes(toolFilter.toLowerCase())) return false;
      if (searchQuery) {
        const searchLower = searchQuery.toLowerCase();
        const searchStr = JSON.stringify(action).toLowerCase();
        if (!searchStr.includes(searchLower)) return false;
      }
      return true;
    });
  }, [actions, statusFilter, agentFilter, toolFilter, searchQuery]);

  const paginatedActions = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredActions.slice(start, start + pageSize);
  }, [filteredActions, currentPage, pageSize]);

  const totalPages = Math.ceil(filteredActions.length / pageSize);

  const handleCopyId = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (filteredActions.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500 dark:text-gray-400">
        No actions found
      </div>
    );
  }

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse bg-white dark:bg-navy rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
          <thead className="bg-gray-50 dark:bg-charcoal border-b border-gray-200 dark:border-gray-700">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                ID
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                Time
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                Agent
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                Tool
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                Operation
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                Risk
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                Decision
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {paginatedActions.map((action) => {
              const isSelected = selectedActionId === action.id;
              const time = new Date(action.created_at).toLocaleTimeString();
              const decisionSource = action.decision === 'require_approval' ? 'approval' : 'policy';
              const isDemo = action.context?.demo === true || action.agent_id === 'demo';

              return (
                <tr
                  key={action.id}
                  onClick={() => onSelectAction(action)}
                  className={`${getStatusRowClass(action.status)} ${isSelected ? 'ring-2 ring-yellow-400 dark:ring-yellow-500' : ''}`}
                >
                  <td className="px-4 py-3 text-sm">
                    <div className="flex items-center gap-2 group">
                      <span className="font-mono text-gray-900 dark:text-gray-100">
                        {truncateId(action.id)}
                      </span>
                      <button
                        onClick={(e) => handleCopyId(action.id, e)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                        title={`Copy full ID: ${action.id}`}
                      >
                        {copiedId === action.id ? '✓' : '📋'}
                      </button>
                      {isDemo && (
                        <span className="px-1.5 py-0.5 bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400 text-xs font-medium rounded border border-yellow-300 dark:border-yellow-700">
                          DEMO
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{time}</td>
                  <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100">{action.agent_id}</td>
                  <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100">{action.tool}</td>
                  <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100">{action.operation}</td>
                  <td className="px-4 py-3 text-sm">
                    <StatusBadge status={action.status} />
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {action.risk_level && (
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        action.risk_level === 'high' ? 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-400' :
                        action.risk_level === 'medium' ? 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400' :
                        'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-400'
                      }`}>
                        {action.risk_level.toUpperCase()}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{decisionSource}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="mt-4 flex items-center justify-between">
          <div className="text-sm text-gray-600 dark:text-gray-400">
            Showing {(currentPage - 1) * pageSize + 1} to {Math.min(currentPage * pageSize, filteredActions.length)} of{' '}
            {filteredActions.length} actions
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="px-3 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-charcoal text-gray-700 dark:text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-graphite"
            >
              Previous
            </button>
            <span className="px-3 py-1 text-sm text-gray-600 dark:text-gray-400">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="px-3 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-charcoal text-gray-700 dark:text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-graphite"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
