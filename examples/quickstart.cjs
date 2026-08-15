// Smallest working Simple integration.
const { Client } = require('systemlocker-simple');

async function main() {
  const client = new Client({
    systemId: 'abcdefghijklmnopqrst', // from the dashboard
    version: '1.0.0',
    // hwid stays "1" unless you want device locking.
  });

  try {
    const ok = await client.authenticateWithKey('SL-XXXX-XXXX-XXXX');
    if (!ok) return; // rejected — block the action
  } catch (error) {
    console.log('check failed:', error.message); // transport / server error
    return;
  }

  console.log('license ok — run the gated action');

  const expiration = await client.keyExpirationForKey('SL-XXXX-XXXX-XXXX');
  console.log('expires:', expiration.permanent ? 'never' : expiration.expiresAt);

  const flags = await client.getVariable('feature_flags');
  if (flags.found) {
    console.log('feature_flags =', flags.value);
  }
}

main();
