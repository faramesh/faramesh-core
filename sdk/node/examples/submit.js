/**
 * Example: Submit an action using the FaraCore Node.js SDK
 */

const { configure, submitAction } = require('../dist/index.js');

async function main() {
  // Configure SDK
  configure({
    baseUrl: process.env.FARACORE_BASE_URL || 'http://127.0.0.1:8000',
    token: process.env.FARACORE_TOKEN,
  });

  try {
    // Submit an action
    const action = await submitAction(
      'example-agent',
      'http',
      'get',
      { url: 'https://example.com' },
      { source: 'example-script' }
    );

    console.log('Action submitted successfully!');
    console.log(`  ID: ${action.id}`);
    console.log(`  Status: ${action.status}`);
    console.log(`  Decision: ${action.decision || 'N/A'}`);
    
    if (action.status === 'pending_approval') {
      console.log(`\n  ⚠️  Action requires approval`);
      console.log(`  Token: ${action.approval_token}`);
    }
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
