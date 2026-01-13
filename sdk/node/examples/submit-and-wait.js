/**
 * Example: Submit and wait for completion
 */

const { configure, submitAndWait } = require('../dist/index.js');

configure({ baseUrl: 'http://localhost:8000' });

(async () => {
  try {
    // Submit action and wait for completion (with auto-approval)
    const action = await submitAndWait(
      'my-agent',
      'http',
      'get',
      { url: 'https://example.com' },
      {}, // context
      {
        pollInterval: 1000,
        timeout: 60000,
        autoApprove: true,
      }
    );

    console.log(`Action completed: ${action.id}`);
    console.log(`Final status: ${action.status}`);
    console.log(`Reason: ${action.reason || 'N/A'}`);
  } catch (error) {
    console.error('Error:', error.message);
  }
})();
