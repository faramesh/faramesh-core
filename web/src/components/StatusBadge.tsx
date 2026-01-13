import { ActionStatus } from '../types';

interface StatusBadgeProps {
  status: ActionStatus;
  className?: string;
}

const statusConfig: Record<ActionStatus, { label: string; className: string }> = {
  pending_approval: {
    label: 'Pending Approval',
    className: 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400 border-yellow-300 dark:border-yellow-700',
  },
  pending_decision: {
    label: 'Pending Decision',
    className: 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-300 border-gray-300 dark:border-gray-600',
  },
  approved: {
    label: 'Approved',
    className: 'bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-400 border-blue-300 dark:border-blue-700',
  },
  allowed: {
    label: 'Allowed',
    className: 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-400 border-green-300 dark:border-green-700',
  },
  denied: {
    label: 'Denied',
    className: 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-400 border-red-300 dark:border-red-700',
  },
  executing: {
    label: 'Executing',
    className: 'bg-purple-100 dark:bg-purple-900/20 text-purple-800 dark:text-purple-400 border-purple-300 dark:border-purple-700 animate-pulse',
  },
  succeeded: {
    label: 'Succeeded',
    className: 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-400 border-green-300 dark:border-green-700',
  },
  failed: {
    label: 'Failed',
    className: 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-400 border-red-300 dark:border-red-700',
  },
  timeout: {
    label: 'Timeout',
    className: 'bg-orange-100 dark:bg-orange-900/20 text-orange-800 dark:text-orange-400 border-orange-300 dark:border-orange-700',
  },
};

export default function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const config = statusConfig[status] || statusConfig.pending_decision;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium border ${config.className} ${className}`}
    >
      {status === 'executing' && (
        <span className="w-1.5 h-1.5 bg-current rounded-full animate-pulse" />
      )}
      {config.label}
    </span>
  );
}
