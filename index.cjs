'use strict';

const { Client, defaultConfig, RESET_GRANTED, RESET_DENIED, RESET_TOO_SOON } = require('./src/client');
const { SimpleError, ErrorKind, classify, ssoLink } = require('./src/errors');
const { Management, Expiry } = require('./src/management');
const { FetchHttpClient } = require('./src/transport');
const { GOOGLE_SSO_PORTAL, googleSsoUrl } = require('./src/sso');

module.exports = {
  Client,
  defaultConfig,
  SimpleError,
  ErrorKind,
  classify,
  ssoLink,
  Management,
  Expiry,
  FetchHttpClient,
  GOOGLE_SSO_PORTAL,
  googleSsoUrl,
  RESET_GRANTED,
  RESET_DENIED,
  RESET_TOO_SOON,
};
