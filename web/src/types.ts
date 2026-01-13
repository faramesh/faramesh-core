export interface Action {
  id: string;
  agent_id: string;
  tool: string;
  operation: string;
  params: Record<string, any>;
  context: Record<string, any>;
  status: ActionStatus;
  decision: Decision | null;
  reason: string | null;
  risk_level: string | null;
  approval_token: string | null;
  policy_version: string | null;
  created_at: string;
  updated_at: string;
  js_example?: string;
  python_example?: string;
}

export type ActionStatus =
  | 'pending_decision'
  | 'allowed'
  | 'denied'
  | 'pending_approval'
  | 'approved'
  | 'executing'
  | 'succeeded'
  | 'failed'
  | 'timeout';

export type Decision = 'allow' | 'deny' | 'require_approval';

export interface SSEEvent {
  type: string;
  data: Action;
}
