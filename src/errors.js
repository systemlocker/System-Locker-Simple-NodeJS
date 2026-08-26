'use strict';

/** Error kinds. Denials carry the server's raw reason string. */
const ErrorKind = Object.freeze({
  Configuration: 'Configuration',
  Transport: 'Transport',
  Server: 'Server',
  Denied: 'Denied',
  SSO: 'SSO',
  LocalFailure: 'LocalFailure',
  UnknownReason: 'UnknownReason',
});

class SimpleError extends Error {
  constructor(kind, message, reason = '') {
    super(message);
    this.name = 'SimpleError';
    this.kind = kind;
    this.reason = reason;
  }
}

const KNOWN_DENIED_REASONS = new Set([
  'no username', 'no password', 'no key', 'no sys', 'no hwid', 'false',
  'not verified', 'bad u/p', 'bad key', 'bad keys', 'frozen', 'paused',
  'destitute', 'user limit', 'hwid banned', 'spoofsuspected', 'hwid',
  'expired key', 'outdated', 'digest', 'exp err big', 'no var',
]);

const SSO_STAGES = ['ssowrong', 'ssoexp', 'sso'];

function classify(reason) {
  if (reason === 'dbe') {
    return new SimpleError(ErrorKind.Server, 'The server reported an internal error.', reason);
  }
  for (const stage of SSO_STAGES) {
    if (reason === stage || (reason.length > stage.length && reason.startsWith(stage + ' '))) {
      const link = reason.slice(stage.length + 1);
      const guidance = stage === 'sso'
        ? 'This account requires a Google SSO token; visit the link to create one.'
        : stage === 'ssoexp'
          ? 'The Google SSO token expired; visit the link to renew it.'
          : 'The supplied password is not the Google SSO token; visit the link.';
      return new SimpleError(ErrorKind.SSO, `${guidance} Portal: ${link}`, reason);
    }
  }
  if (KNOWN_DENIED_REASONS.has(reason)) {
    return new SimpleError(ErrorKind.Denied, `The request was rejected: ${reason}.`, reason);
  }
  return new SimpleError(ErrorKind.UnknownReason, `The server returned an unrecognized failure: ${reason}`, reason);
}

/** Returns the portal URL from an sso/ssoexp/ssowrong error, or ''. */
function ssoLink(error) {
  if (error instanceof SimpleError && error.kind === ErrorKind.SSO) {
    const space = error.reason.indexOf(' ');
    return space >= 0 ? error.reason.slice(space + 1) : '';
  }
  return '';
}

module.exports = { SimpleError, ErrorKind, classify, ssoLink };
