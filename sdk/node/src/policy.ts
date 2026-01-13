/**
 * Typed policy objects for client-side policy building and validation.
 * 
 * These models allow you to build and test policies in code without needing
 * to write YAML files. The server-side DSL, evaluators, and policy packs
 * remain in Horizon/Nexus.
 */

export type RiskLevel = "low" | "medium" | "high";

export interface MatchCondition {
  tool?: string; // Tool name or "*" for any
  op?: string; // Operation name or "*" for any
  operation?: string; // Alias for op
  pattern?: string; // Regex pattern to match in params
  contains?: string; // Substring match in params JSON
  amount_gt?: number; // Numeric comparison: amount > value
  amount_lt?: number; // Numeric comparison: amount < value
  amount_gte?: number; // Numeric comparison: amount >= value
  amount_lte?: number; // Numeric comparison: amount <= value
  path_contains?: string; // Path contains substring
  path_starts_with?: string; // Path starts with
  path_ends_with?: string; // Path ends with
  method?: string; // HTTP method
  branch?: string; // Git branch name
  agent_id?: string; // Agent identifier
  field?: string; // Custom field name
  value?: any; // Custom field value
}

export interface PolicyRule {
  match: MatchCondition;
  description: string;
  allow?: boolean;
  deny?: boolean;
  require_approval?: boolean;
  risk?: RiskLevel;
}

export interface RiskRule {
  name: string;
  when: MatchCondition;
  risk_level: RiskLevel;
}

export interface Policy {
  rules: PolicyRule[];
  risk?: {
    rules: RiskRule[];
  };
}

/**
 * Validate a policy and return list of errors (empty if valid)
 */
export function validatePolicy(policy: Policy): string[] {
  const errors: string[] = [];

  if (!policy.rules || policy.rules.length === 0) {
    errors.push("Policy must have at least one rule");
  }

  policy.rules.forEach((rule, index) => {
    if (!rule.description) {
      errors.push(`Rule ${index + 1}: description is required`);
    }

    const matchKeys = Object.keys(rule.match || {});
    if (matchKeys.length === 0) {
      errors.push(`Rule ${index + 1}: match conditions cannot be empty`);
    }

    const effects = [
      rule.allow === true,
      rule.deny === true,
      rule.require_approval === true,
    ].filter(Boolean).length;

    if (effects !== 1) {
      errors.push(
        `Rule ${index + 1}: must have exactly one effect (allow, deny, or require_approval)`
      );
    }
  });

  return errors;
}

/**
 * Convert policy to YAML string
 */
export function policyToYaml(policy: Policy): string {
  try {
    const yaml = require("yaml");
    return yaml.stringify(policyToDict(policy), { defaultStringType: "PLAIN" });
  } catch {
    throw new Error(
      "YAML support requires 'yaml' package. Install with: npm install yaml"
    );
  }
}

/**
 * Convert policy to dictionary
 */
export function policyToDict(policy: Policy): any {
  const result: any = {
    rules: policy.rules.map((rule) => {
      const ruleDict: any = {
        match: { ...rule.match },
        description: rule.description,
      };
      if (rule.allow !== undefined) ruleDict.allow = rule.allow;
      if (rule.deny !== undefined) ruleDict.deny = rule.deny;
      if (rule.require_approval !== undefined)
        ruleDict.require_approval = rule.require_approval;
      if (rule.risk) ruleDict.risk = rule.risk;
      return ruleDict;
    }),
  };

  if (policy.risk && policy.risk.rules) {
    result.risk = {
      rules: policy.risk.rules.map((rule) => ({
        name: rule.name,
        when: rule.when,
        risk_level: rule.risk_level,
      })),
    };
  }

  return result;
}

/**
 * Create a policy from rules
 */
export function createPolicy(
  rules: PolicyRule[],
  riskRules?: RiskRule[]
): Policy {
  return {
    rules,
    risk: riskRules ? { rules: riskRules } : undefined,
  };
}
