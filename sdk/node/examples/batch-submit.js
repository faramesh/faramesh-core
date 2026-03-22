/**
 * Example: Batch submit multiple actions
 */

const { configure, submitActions } = require('../dist/index.js');

configure({ baseUrl: 'http://localhost:8000' });

(async () => {
  const actions = await submitActions([
    {
      agent_id: 'agent1',
      tool: 'http',
      operation: 'get',
      params: { url: 'https://example.com' },
    },
    {
      agent_id: 'agent2',
      tool: 'http',
      operation: 'get',
      params: { url: 'https://example.org' },
    },
    {
      agent_id: 'agent3',
      tool: 'shell',
      operation: 'run',
      params: { cmd: 'ls -la' },
    },
  ]);

  console.log(`Submitted ${actions.length} actions:`);
  actions.forEach((action, i) => {
    if (action.error) {
      console.log(`  ${i + 1}. Error: ${action.error}`);
    } else {
      console.log(`  ${i + 1}. Action ${action.id}: ${action.status}`);
    }
  });
})();
