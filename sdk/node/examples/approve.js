/**
 * Example: Submit and approve an action
 */

const { configure, submitAction, approveAction, startAction } = require('../dist/index.js');

async function main() {
  configure({
    baseUrl: process.env.FARACORE_BASE_URL || 'http://127.0.0.1:8000',
    token: process.env.FARACORE_TOKEN,
  });

  try {
    // Submit an action that requires approval
    console.log('Submitting action...');
    const action = await submitAction(
      'example-agent',
      'shell',
      'run',
      { cmd: 'echo "Hello, FaraCore!"' }
    );

    console.log(`Action ${action.id.substring(0, 8)}... status: ${action.status}`);

    if (action.status === 'pending_approval') {
      console.log('Approving action...');
      const approved = await approveAction(
        action.id,
        action.approval_token,
        'Approved by example script'
      );
      console.log(`Action approved: ${approved.status}`);

      console.log('Starting execution...');
      const started = await startAction(approved.id);
      console.log(`Action started: ${started.status}`);
    } else {
      console.log(`Action status: ${action.status} (no approval needed)`);
    }
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
