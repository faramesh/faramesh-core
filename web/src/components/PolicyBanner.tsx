import { useState, useEffect } from 'react';

interface PolicyInfo {
  policy_file: string;
  policy_path: string;
  exists: boolean;
  policy_version: string | null;
}

export default function PolicyBanner() {
  const [policyInfo, setPolicyInfo] = useState<PolicyInfo | null>(null);
  const [hasError, setHasError] = useState(false);

  useEffect(() => {
    const config = (window as any).FARACORE_CONFIG || {};
    const apiBase = config.apiBase || window.location.origin;
    
    fetch(`${apiBase}/v1/policy/info`)
      .then((res) => {
        if (!res.ok) throw new Error('Failed to fetch policy info');
        return res.json();
      })
      .then((data: PolicyInfo) => {
        setPolicyInfo(data);
        setHasError(!data.exists);
      })
      .catch(() => {
        setHasError(true);
      });
  }, []);

  if (!policyInfo) {
    return null; // Still loading
  }

  if (hasError || !policyInfo.exists) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border-b border-red-200 dark:border-red-800 px-6 py-2">
        <div className="flex items-center gap-2 text-sm text-red-800 dark:text-red-400">
          <span className="font-semibold">⚠️ Warning:</span>
          <span>Policy file not found:</span>
          <span className="font-mono">{policyInfo.policy_file}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-blue-50 dark:bg-blue-900/20 border-b border-blue-200 dark:border-blue-800 px-6 py-2">
      <div className="flex items-center gap-2 text-sm text-blue-800 dark:text-blue-400">
        <span className="font-semibold">Active Policy:</span>
        <span className="font-mono">{policyInfo.policy_file}</span>
        {policyInfo.policy_version && (
          <>
            <span className="text-blue-600 dark:text-blue-500">•</span>
            <span className="text-xs">v{policyInfo.policy_version}</span>
          </>
        )}
      </div>
    </div>
  );
}
