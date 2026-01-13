/**
 * FaraCore Node.js SDK
 * 
 * Provides wrappers for submitting actions to the FaraCore governance server
 */

/**
 * Custom error classes
 */
class GovernorError extends Error {
  constructor(message) {
    super(message);
    this.name = 'GovernorError';
  }
}

class GovernorTimeoutError extends GovernorError {
  constructor(message) {
    super(message);
    this.name = 'GovernorTimeoutError';
  }
}

class GovernorAuthError extends GovernorError {
  constructor(message) {
    super(message);
    this.name = 'GovernorAuthError';
  }
}

class GovernorConnectionError extends GovernorError {
  constructor(message) {
    super(message);
    this.name = 'GovernorConnectionError';
  }
}

/**
 * Pending action (requires approval)
 */
class PendingAction extends Error {
  constructor(data) {
    super(`Action requires approval: ${data.id}`);
    this.name = 'PendingAction';
    this.id = data.id;
    this.status = data.status;
    this.decision = data.decision;
    this.reason = data.reason;
    this.approval_token = data.approval_token;
    this.risk_level = data.risk_level;
  }
}

/**
 * Configuration for the SDK
 */
class Config {
  constructor(options = {}) {
    this.apiBase = options.apiBase || process.env.FARA_API_BASE || 'http://127.0.0.1:8000';
    this.apiKey = options.apiKey || process.env.FARA_AUTH_TOKEN || null;
    this.timeout = options.timeout || parseInt(process.env.FARA_TIMEOUT || '5000', 10);
    this.maxRetries = options.maxRetries || parseInt(process.env.FARA_MAX_RETRIES || '3', 10);
    this.retryBackoffFactor = options.retryBackoffFactor || 0.5;
    this.retryStatusCodes = options.retryStatusCodes || [429, 500, 502, 503, 504];
  }

  getHeaders() {
    const headers = {
      'Content-Type': 'application/json',
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }
}

/**
 * Retry helper with exponential backoff
 */
async function retryWithBackoff(fn, maxRetries, backoffFactor, retryStatusCodes) {
  let lastError;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      // Don't retry auth errors
      if (error instanceof GovernorAuthError) {
        throw error;
      }
      
      // Check if we should retry
      const shouldRetry = 
        attempt < maxRetries &&
        (error.status >= 500 || retryStatusCodes.includes(error.status));
      
      if (!shouldRetry) {
        throw error;
      }
      
      // Wait before retrying
      const waitTime = backoffFactor * Math.pow(2, attempt);
      await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
    }
  }
  
  throw lastError;
}

/**
 * Submit an action to the governance server
 * 
 * @param {Object} action - Action request
 * @param {string} action.agentId - Agent identifier
 * @param {string} action.tool - Tool name
 * @param {string} action.operation - Operation name
 * @param {Object} [action.params] - Parameters
 * @param {Object} [action.context] - Additional context
 * @param {Config} [config] - SDK configuration
 * @returns {Promise<Object>} Action response
 */
async function submitAction(action, config = new Config()) {
  const url = `${config.apiBase}/v1/actions`;
  
  const response = await retryWithBackoff(
    async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeout);
      
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: config.getHeaders(),
          body: JSON.stringify({
            agent_id: action.agentId,
            tool: action.tool,
            operation: action.operation,
            params: action.params || {},
            context: action.context || {},
          }),
          signal: controller.signal,
        });
        
        clearTimeout(timeoutId);
        
        if (res.status === 401) {
          throw new GovernorAuthError(`Authentication failed: ${await res.text()}`);
        }
        
        if (!res.ok) {
          const error = new GovernorError(`Request failed: ${res.status} ${res.statusText}`);
          error.status = res.status;
          throw error;
        }
        
        return res;
      } catch (error) {
        clearTimeout(timeoutId);
        
        if (error.name === 'AbortError') {
          throw new GovernorTimeoutError(`Request timed out: ${url}`);
        }
        
        if (error instanceof GovernorAuthError || error instanceof GovernorError) {
          throw error;
        }
        
        throw new GovernorConnectionError(`Failed to connect: ${error.message}`);
      }
    },
    config.maxRetries,
    config.retryBackoffFactor,
    config.retryStatusCodes
  );
  
  return await response.json();
}

function assertDecision(data) {
  if (data && data.status === 'denied') {
    const reason = data.reason || 'Action denied by policy';
    const err = new GovernorError(reason);
    err.status = 'denied';
    throw err;
  }
  return data;
}

/**
 * Get an action by ID
 * 
 * @param {string} actionId - Action ID
 * @param {Config} [config] - SDK configuration
 * @returns {Promise<Object>} Action response
 */
async function getAction(actionId, config = new Config()) {
  const url = `${config.apiBase}/v1/actions/${actionId}`;
  
  const response = await retryWithBackoff(
    async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeout);
      
      try {
        const res = await fetch(url, {
          method: 'GET',
          headers: config.getHeaders(),
          signal: controller.signal,
        });
        
        clearTimeout(timeoutId);
        
        if (res.status === 401) {
          throw new GovernorAuthError(`Authentication failed: ${await res.text()}`);
        }
        
        if (res.status === 404) {
          const error = new GovernorError(`Action not found: ${actionId}`);
          error.status = 404;
          throw error;
        }
        
        if (!res.ok) {
          const error = new GovernorError(`Request failed: ${res.status} ${res.statusText}`);
          error.status = res.status;
          throw error;
        }
        
        return res;
      } catch (error) {
        clearTimeout(timeoutId);
        
        if (error.name === 'AbortError') {
          throw new GovernorTimeoutError(`Request timed out: ${url}`);
        }
        
        if (error instanceof GovernorAuthError || error instanceof GovernorError) {
          throw error;
        }
        
        throw new GovernorConnectionError(`Failed to connect: ${error.message}`);
      }
    },
    config.maxRetries,
    config.retryBackoffFactor,
    config.retryStatusCodes
  );
  
  return assertDecision(await response.json());
}

/**
 * List actions with optional filters
 * 
 * @param {Object} [options] - Filter options
 * @param {number} [options.limit] - Maximum number of actions
 * @param {number} [options.offset] - Offset for pagination
 * @param {string} [options.agentId] - Filter by agent ID
 * @param {string} [options.tool] - Filter by tool
 * @param {string} [options.status] - Filter by status
 * @param {Config} [config] - SDK configuration
 * @returns {Promise<Array>} List of actions
 */
async function listActions(options = {}, config = new Config()) {
  const params = new URLSearchParams();
  if (options.limit) params.append('limit', options.limit.toString());
  if (options.offset) params.append('offset', options.offset.toString());
  if (options.agentId) params.append('agent_id', options.agentId);
  if (options.tool) params.append('tool', options.tool);
  if (options.status) params.append('status', options.status);
  
  const url = `${config.apiBase}/v1/actions?${params.toString()}`;
  
  const response = await retryWithBackoff(
    async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeout);
      
      try {
        const res = await fetch(url, {
          method: 'GET',
          headers: config.getHeaders(),
          signal: controller.signal,
        });
        
        clearTimeout(timeoutId);
        
        if (res.status === 401) {
          throw new GovernorAuthError(`Authentication failed: ${await res.text()}`);
        }
        
        if (!res.ok) {
          const error = new GovernorError(`Request failed: ${res.status} ${res.statusText}`);
          error.status = res.status;
          throw error;
        }
        
        return res;
      } catch (error) {
        clearTimeout(timeoutId);
        
        if (error.name === 'AbortError') {
          throw new GovernorTimeoutError(`Request timed out: ${url}`);
        }
        
        if (error instanceof GovernorAuthError || error instanceof GovernorError) {
          throw error;
        }
        
        throw new GovernorConnectionError(`Failed to connect: ${error.message}`);
      }
    },
    config.maxRetries,
    config.retryBackoffFactor,
    config.retryStatusCodes
  );
  
  return assertDecision(await response.json());
}

// Polyfill fetch for Node < 18
if (typeof fetch === 'undefined') {
  try {
    global.fetch = require('node-fetch');
  } catch (e) {
    // node-fetch not available, user must provide fetch
  }
}

module.exports = {
  // Core classes
  Config,
  // Core functions
  submitAction,
  getAction,
  listActions,
  // Error classes
  GovernorError,
  GovernorTimeoutError,
  GovernorAuthError,
  GovernorConnectionError,
  PendingAction,
};
