/**
 * Example: List actions
 */

const { configure, listActions } = require('../dist/index.js');

async function main() {
  configure({
    baseUrl: process.env.FARACORE_BASE_URL || 'http://127.0.0.1:8000',
    token: process.env.FARACORE_TOKEN,
  });

  try {
    // List recent actions
    console.log('Fetching recent actions...');
    const actions = await listActions({ limit: 10 });

    console.log(`\nFound ${actions.length} actions:\n`);
    
    actions.forEach((action, index) => {
      console.log(`${index + 1}. ${action.id.substring(0, 8)}...`);
      console.log(`   Agent: ${action.agent_id}`);
      console.log(`   Tool: ${action.tool} / ${action.operation}`);
      console.log(`   Status: ${action.status}`);
      console.log(`   Created: ${action.created_at}`);
      console.log('');
    });
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
