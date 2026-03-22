/**
 * Example: Build policy in code
 */

const {
  createPolicy,
  validatePolicy,
  policyToYaml,
} = require('../dist/index.js');

// Build a policy programmatically
const policy = createPolicy([
  {
    match: { tool: 'http', op: 'get' },
    description: 'Allow HTTP GET requests',
    allow: true,
    risk: 'low',
  },
  {
    match: { tool: 'shell', op: '*' },
    description: 'Shell commands require approval',
    require_approval: true,
    risk: 'medium',
  },
  {
    match: { tool: '*', op: '*' },
    description: 'Default deny',
    deny: true,
    risk: 'high',
  },
]);

// Validate it
const errors = validatePolicy(policy);
if (errors.length > 0) {
  console.error('Policy validation errors:');
  errors.forEach((err) => console.error(`  - ${err}`));
  process.exit(1);
}

// Convert to YAML
try {
  const yaml = policyToYaml(policy);
  console.log('Generated policy YAML:');
  console.log(yaml);
} catch (error) {
  console.error('Error generating YAML:', error.message);
  console.log('Policy dict:', JSON.stringify(policy, null, 2));
}
