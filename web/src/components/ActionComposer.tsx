import { useState } from 'react';
import { Action } from '../types';

const config = (window as any).FARACORE_CONFIG || {
  apiBase: window.location.origin,
};

const apiBase = config.apiBase || window.location.origin;

interface ActionComposerProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (action: Action) => void;
  onApprove?: (id: string) => Promise<void>;
  onStart?: (id: string) => Promise<void>;
}

const COMMON_TOOLS = ['shell', 'http', 'stripe', 'github', 'jira', 'linear'];
const COMMON_OPS: Record<string, string[]> = {
  shell: ['run', 'exec'],
  http: ['get', 'post', 'put', 'delete', 'patch'],
  stripe: ['create', 'retrieve', 'update', 'delete'],
  github: ['create', 'read', 'update', 'delete'],
  jira: ['create', 'read', 'update', 'delete'],
  linear: ['create', 'read', 'update', 'delete'],
};

export default function ActionComposer({
  isOpen,
  onClose,
  onSubmit,
  onApprove,
  onStart,
}: ActionComposerProps) {
  const [agentId, setAgentId] = useState('test-agent');
  const [tool, setTool] = useState('shell');
  const [operation, setOperation] = useState('run');
  const [paramsJson, setParamsJson] = useState('{\n  "cmd": "echo hello"\n}');
  const [contextJson, setContextJson] = useState('{}');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submittedAction, setSubmittedAction] = useState<Action | null>(null);
  const [showSnippets, setShowSnippets] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);
    setSubmittedAction(null);
    setShowSnippets(false);

    try {
      let params, context;
      try {
        params = JSON.parse(paramsJson);
      } catch (e) {
        setError(`Invalid params JSON: ${e instanceof Error ? e.message : 'Unknown error'}`);
        setLoading(false);
        return;
      }

      try {
        context = JSON.parse(contextJson || '{}');
      } catch (e) {
        setError(`Invalid context JSON: ${e instanceof Error ? e.message : 'Unknown error'}`);
        setLoading(false);
        return;
      }

      const response = await fetch(`${apiBase}/v1/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id: agentId,
          tool,
          operation,
          params,
          context,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Failed to submit action' }));
        throw new Error(errorData.detail || 'Failed to submit action');
      }

      const action = await response.json();
      setSubmittedAction(action);
      onSubmit(action);
      setShowSnippets(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit action');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async () => {
    if (!submittedAction || !onApprove) return;
    await onApprove(submittedAction.id);
    setSubmittedAction(null);
    onClose();
  };

  const handleStart = async () => {
    if (!submittedAction || !onStart) return;
    await onStart(submittedAction.id);
    setSubmittedAction(null);
    onClose();
  };

  const handleReset = () => {
    setSubmittedAction(null);
    setError(null);
    setShowSnippets(false);
    setParamsJson('{\n  "cmd": "echo hello"\n}');
    setContextJson('{}');
  };

  const buildCurlSnippet = () => {
    if (!submittedAction) return '';
    try {
      const params = JSON.parse(paramsJson);
      const context = JSON.parse(contextJson || '{}');
      const payload = JSON.stringify({
        agent_id: agentId,
        tool,
        operation,
        params,
        context,
      }, null, 2);
      return `curl -X POST ${apiBase}/v1/actions \\\n  -H "Content-Type: application/json" \\\n  -d '${payload.replace(/'/g, "\\'")}'`;
    } catch {
      return '';
    }
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="bg-white dark:bg-navy rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col border border-gray-200 dark:border-gray-700">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">New Action</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 text-2xl leading-none"
            >
              ×
            </button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-6">
            {submittedAction ? (
              <div className="space-y-4">
                {/* Success Message */}
                <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                  <div className="flex items-center gap-2 text-green-800 dark:text-green-400">
                    <span className="text-xl">✓</span>
                    <span className="font-semibold">Action submitted successfully!</span>
                  </div>
                  <div className="mt-2 text-sm text-green-700 dark:text-green-300">
                    Status: <span className="font-mono">{submittedAction.status}</span>
                  </div>
                </div>

                {/* Action Info */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">
                      Action ID
                    </label>
                    <div className="font-mono text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-2 rounded border border-gray-200 dark:border-gray-700">
                      {submittedAction.id.substring(0, 8)}...
                    </div>
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1 block">
                      Decision
                    </label>
                    <div className="text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-charcoal p-2 rounded border border-gray-200 dark:border-gray-700">
                      {submittedAction.decision || 'N/A'}
                    </div>
                  </div>
                </div>

                {/* Snippets */}
                {showSnippets && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Code Snippets
                      </label>
                      <button
                        onClick={() => setShowSnippets(false)}
                        className="text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
                      >
                        Hide
                      </button>
                    </div>

                    {/* Curl */}
                    <div className="bg-gray-900 text-gray-100 p-4 rounded border border-gray-700">
                      <div className="text-xs font-semibold text-blue-400 mb-2">curl</div>
                      <pre className="text-xs overflow-x-auto">{buildCurlSnippet()}</pre>
                    </div>

                    {/* Python */}
                    {submittedAction.python_example && (
                      <div className="bg-gray-900 text-gray-100 p-4 rounded border border-gray-700">
                        <div className="text-xs font-semibold text-blue-400 mb-2">Python SDK</div>
                        <pre className="text-xs overflow-x-auto whitespace-pre-wrap">{submittedAction.python_example}</pre>
                      </div>
                    )}

                    {/* JavaScript */}
                    {submittedAction.js_example && (
                      <div className="bg-gray-900 text-gray-100 p-4 rounded border border-gray-700">
                        <div className="text-xs font-semibold text-blue-400 mb-2">JavaScript SDK</div>
                        <pre className="text-xs overflow-x-auto whitespace-pre-wrap">{submittedAction.js_example}</pre>
                      </div>
                    )}
                  </div>
                )}

                {/* Action Buttons */}
                {submittedAction.status === 'pending_approval' && onApprove && (
                  <div className="flex gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <button
                      onClick={handleApprove}
                      className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition-colors"
                    >
                      Approve
                    </button>
                    <button
                      onClick={handleReset}
                      className="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-gray-100 rounded-lg font-medium transition-colors"
                    >
                      New Action
                    </button>
                  </div>
                )}

                {(submittedAction.status === 'approved' || submittedAction.status === 'allowed') && onStart && (
                  <div className="flex gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <button
                      onClick={handleStart}
                      className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
                    >
                      Start Execution
                    </button>
                    <button
                      onClick={handleReset}
                      className="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-gray-100 rounded-lg font-medium transition-colors"
                    >
                      New Action
                    </button>
                  </div>
                )}

                {submittedAction.status === 'denied' && (
                  <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                    <button
                      onClick={handleReset}
                      className="w-full px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-gray-100 rounded-lg font-medium transition-colors"
                    >
                      Create New Action
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                {/* Error */}
                {error && (
                  <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <div className="text-red-800 dark:text-red-400 text-sm">{error}</div>
                  </div>
                )}

                {/* Form */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                      Agent ID
                    </label>
                    <input
                      type="text"
                      value={agentId}
                      onChange={(e) => setAgentId(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
                      placeholder="agent-id"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                      Tool
                    </label>
                    <select
                      value={tool}
                      onChange={(e) => {
                        setTool(e.target.value);
                        const ops = COMMON_OPS[e.target.value] || [];
                        if (ops.length > 0) {
                          setOperation(ops[0]);
                        }
                      }}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
                    >
                      {COMMON_TOOLS.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                    Operation
                  </label>
                  <select
                    value={operation}
                    onChange={(e) => setOperation(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
                  >
                    {(COMMON_OPS[tool] || ['run']).map((op) => (
                      <option key={op} value={op}>
                        {op}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                    Params (JSON)
                  </label>
                  <textarea
                    value={paramsJson}
                    onChange={(e) => setParamsJson(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
                    rows={6}
                    placeholder='{\n  "key": "value"\n}'
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                    Context (JSON, optional)
                  </label>
                  <textarea
                    value={contextJson}
                    onChange={(e) => setContextJson(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-charcoal text-gray-900 dark:text-gray-100 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-yellow-400 dark:focus:ring-yellow-500"
                    rows={4}
                    placeholder='{}'
                  />
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          {!submittedAction && (
            <div className="flex items-center justify-end gap-3 p-6 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={onClose}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={loading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
              >
                {loading ? 'Submitting...' : 'Submit Action'}
              </button>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
