'use strict';

// The server embeds this URL in sso/ssoexp/ssowrong denial reasons; the
// client mirrors it so the flow can start before a denial is ever seen.
const GOOGLE_SSO_PORTAL = 'https://systemlocker.net/user/sso?system=';

/** Returns the Google SSO portal URL for a system. After the user signs in
 * there, the portal shows a system-specific password that is valid for 180
 * days and is then used as the account password.
 *
 * The Simple protocol targets trusted machines (typically servers), so the
 * library deliberately stops at the URL: route it to your user through your
 * own channel (API response, email, chat) rather than expecting a browser
 * on the host. */
function googleSsoUrl(systemId) {
  return GOOGLE_SSO_PORTAL + encodeURIComponent(systemId);
}

module.exports = { GOOGLE_SSO_PORTAL, googleSsoUrl };
