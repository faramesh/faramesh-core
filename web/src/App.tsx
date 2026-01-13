import { useState, useEffect, useCallback } from 'react';
import { Action, ActionStatus } from './types';
import { useActions } from './hooks/useActions';
import { useSSE } from './hooks/useSSE';
import NavBar from './components/NavBar';
import PolicyBanner from './components/PolicyBanner';
import ActionTable from './components/ActionTable';
import ActionDetails from './components/ActionDetails';
import ActionComposer from './components/ActionComposer';
import Toast from './components/Toast';

function App() {
  const [isDark, setIsDark] = useState(false);
  const [selectedAction, setSelectedAction] = useState<Action | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<ActionStatus | ''>('');
  const [agentFilter, setAgentFilter] = useState('');
  const [toolFilter, setToolFilter] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);
  const [showComposer, setShowComposer] = useState(false);

  const { actions, loading, updateAction, approveAction, denyAction, startAction } = useActions();
  const { isConnected: sseConnected } = useSSE(updateAction);
  
  // Check if demo mode is active
  const isDemoMode = actions.some(a => a.agent_id === 'demo' || a.context?.demo === true);

  // Theme management
  useEffect(() => {
    const saved = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = saved || (prefersDark ? 'dark' : 'light');
    const isDarkMode = theme === 'dark';
    setIsDark(isDarkMode);
    document.documentElement.classList.toggle('dark', isDarkMode);
  }, []);

  const handleThemeToggle = () => {
    const newIsDark = !isDark;
    setIsDark(newIsDark);
    document.documentElement.classList.toggle('dark', newIsDark);
    localStorage.setItem('theme', newIsDark ? 'dark' : 'light');
  };

  // Search keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && e.target === document.body) {
        e.preventDefault();
        document.getElementById('search-input')?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleApprove = useCallback(async (id: string) => {
    const result = await approveAction(id);
    if (result.success) {
      setToast({ message: 'Action approved!', type: 'success' });
      setSelectedAction(null);
    } else {
      setToast({ message: result.error || 'Failed to approve', type: 'error' });
    }
  }, [approveAction]);

  const handleDeny = useCallback(async (id: string) => {
    const result = await denyAction(id);
    if (result.success) {
      setToast({ message: 'Action denied!', type: 'success' });
      setSelectedAction(null);
    } else {
      setToast({ message: result.error || 'Failed to deny', type: 'error' });
    }
  }, [denyAction]);

  const handleStart = useCallback(async (id: string) => {
    const result = await startAction(id);
    if (result.success) {
      setToast({ message: 'Action started!', type: 'success' });
    } else {
      setToast({ message: result.error || 'Failed to start', type: 'error' });
    }
  }, [startAction]);

  const handleComposerSubmit = useCallback((action: Action) => {
    updateAction(action);
    setToast({ message: 'Action submitted!', type: 'success' });
  }, [updateAction]);

  return (
    <div className="min-h-screen bg-white dark:bg-deep-indigo">
      <NavBar onThemeToggle={handleThemeToggle} isDark={isDark} />
      
      <div className="pt-16">
        <PolicyBanner />

        {/* Filters */}
        <div className="bg-white dark:bg-navy border-b border-gray-200 dark:border-gray-700 px-6 py-4">
          <div className="flex flex-wrap gap-4">
            <div className="flex-1 min-w-[200px]">
              <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">
                Search
              </label>
              <input
                id="search-input"
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Search actions... (Press / to focus)"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
              />
            </div>
            <div className="min-w-[150px]">
              <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">
                Status
              </label>
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value as ActionStatus | '');
                  setCurrentPage(1);
                }}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
              >
                <option value="">All</option>
                <option value="pending_approval">Pending Approval</option>
                <option value="pending_decision">Pending Decision</option>
                <option value="allowed">Allowed</option>
                <option value="approved">Approved</option>
                <option value="denied">Denied</option>
                <option value="executing">Executing</option>
                <option value="succeeded">Succeeded</option>
                <option value="failed">Failed</option>
              </select>
            </div>
            <div className="min-w-[150px]">
              <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">
                Agent
              </label>
              <input
                type="text"
                value={agentFilter}
                onChange={(e) => {
                  setAgentFilter(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Filter by agent..."
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
              />
            </div>
            <div className="min-w-[150px]">
              <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">
                Tool
              </label>
              <input
                type="text"
                value={toolFilter}
                onChange={(e) => {
                  setToolFilter(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Filter by tool..."
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
              />
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="px-6 py-6">
          {/* SSE Indicator + New Action Button */}
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
              {sseConnected ? (
                <>
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                  <span>LIVE</span>
                </>
              ) : (
                <>
                  <span className="w-2 h-2 bg-gray-400 rounded-full" />
                  <span>Connecting...</span>
                </>
              )}
            </div>
            <button
              onClick={() => setShowComposer(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors text-sm"
            >
              + New Action
            </button>
          </div>

          {/* Demo Mode Hint */}
          {isDemoMode && actions.length > 0 && (
            <div className="mb-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
              <div className="flex items-center gap-2 text-sm text-yellow-800 dark:text-yellow-400">
                <span>ℹ️</span>
                <span>Demo mode is active. Actions marked with <span className="font-semibold">DEMO</span> badge are sample data.</span>
              </div>
            </div>
          )}
          
          {/* Table */}
          {loading ? (
            <div className="text-center py-12 text-gray-500 dark:text-gray-400">
              Loading actions...
            </div>
          ) : actions.length === 0 ? (
            <div className="text-center py-16">
              <div className="text-6xl mb-4">📋</div>
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">No actions yet</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Submit an action via the SDK or API to get started.
              </p>
              <div className="mt-6 p-4 bg-gray-50 dark:bg-charcoal rounded-lg border border-gray-200 dark:border-gray-700 max-w-2xl mx-auto text-left">
                <p className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Quick Start:</p>
                <pre className="text-xs text-gray-700 dark:text-gray-300 overflow-x-auto">
{`from faracore.sdk.client import ExecutionGovernorClient

client = ExecutionGovernorClient("http://127.0.0.1:8000")
action = client.submit_action(
    tool="http",
    operation="get",
    params={"url": "https://example.com"},
    context={"agent_id": "my-agent"}
)`}
                </pre>
              </div>
            </div>
          ) : (
            <ActionTable
              actions={actions}
              selectedActionId={selectedAction?.id || null}
              onSelectAction={setSelectedAction}
              searchQuery={searchQuery}
              statusFilter={statusFilter}
              agentFilter={agentFilter}
              toolFilter={toolFilter}
              currentPage={currentPage}
              pageSize={25}
              onPageChange={setCurrentPage}
            />
          )}
        </div>
      </div>

      {/* Action Details Drawer */}
      <ActionDetails
        action={selectedAction}
        isOpen={!!selectedAction}
        onClose={() => setSelectedAction(null)}
        onApprove={handleApprove}
        onDeny={handleDeny}
      />

      {/* Action Composer Modal */}
      <ActionComposer
        isOpen={showComposer}
        onClose={() => setShowComposer(false)}
        onSubmit={handleComposerSubmit}
        onApprove={handleApprove}
        onStart={handleStart}
      />

      {/* Toast */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          isVisible={!!toast}
          onClose={() => setToast(null)}
        />
      )}
    </div>
  );
}

export default App;
