'use strict';

const { SimpleError, ErrorKind, classify } = require('./errors');

const AUTH_PATH = '/auth';
const VARIABLE_PATH = '/auth/variable';
const API_V1_PATH = '/api/v1';

const RESET_GRANTED = 'granted';
const RESET_DENIED = 'denied';
const RESET_TOO_SOON = 'tooSoon';

/** Returns a config with every default filled in. */
function defaultConfig() {
  return {
    systemId: '',
    version: '',
    hwid: null,
    requestTimeoutMs: 15_000,
    baseUrl: 'https://systemlocker.net',
    userAgent: 'systemlocker-simple-node/0.1',
    programDigest: null,
    apiKey: null,
  };
}

/**
 * Stateless Simple client: one request, one answer. Safe for concurrent
 * use. Failing operations throw a SimpleError with a `kind`.
 */
class Client {
  /**
   * @param {object} [config] start from defaultConfig() and override
   * @param {object} [options] { http: custom transport }
   */
  constructor(config = {}, options = {}) {
    const merged = { ...defaultConfig(), ...config };
    if (!merged.systemId) {
      throw new SimpleError(ErrorKind.Configuration, 'System ID must not be empty.');
    }
    if (!merged.version) {
      throw new SimpleError(ErrorKind.Configuration, 'Version must not be empty.');
    }
    if (!String(merged.baseUrl).startsWith('https://')) {
      throw new SimpleError(ErrorKind.Configuration, 'Base URL must use HTTPS.');
    }
    this.config = merged;
    this.http = options.http ?? null;
  }

  get transport() {
    if (this.http === null) {
      const { FetchHttpClient } = require('./transport');
      this.http = new FetchHttpClient({
        requestTimeoutMs: this.config.requestTimeoutMs,
        userAgent: this.config.userAgent,
      });
    }
    return this.http;
  }

  endpoint(path) {
    return this.config.baseUrl.endsWith('/')
      ? this.config.baseUrl.slice(0, -1) + path
      : this.config.baseUrl + path;
  }

  async baseFields() {
    if (this.config.hwid === null || this.config.hwid === '') {
      this.config.hwid = await require('../hwid/collect.cjs').deviceHwid();
    }
    const fields = {
      system: this.config.systemId,
      version: this.config.version,
      hwid: this.config.hwid,
      clean: '1',
    };
    if (this.config.programDigest) {
      fields.digest = this.config.programDigest;
    }
    return fields;
  }

  async request(path, fields) {
    const httpResponse = await this.transport.postForm(this.endpoint(path), fields, {});
    if (httpResponse.error || httpResponse.status < 200 || httpResponse.status >= 300) {
      const message = httpResponse.error
        ? `request failed: ${httpResponse.error}`
        : `server returned HTTP ${httpResponse.status}: ${String(httpResponse.body).trim()}`;
      throw new SimpleError(ErrorKind.Transport, message);
    }
    return {
      body: String(httpResponse.body).trim(),
      headers: httpResponse.headers,
    };
  }

  /** Checks a license key (mikros mode). True only on a literal "true". */
  async authenticateWithKey(licenseKey) {
    return this.authenticate({ ...(await this.baseFields()), key: licenseKey });
  }

  /** Checks username + password credentials (goliath mode). */
  async authenticateWithPassword(username, password) {
    return this.authenticate({ ...(await this.baseFields()), username, password });
  }

  async authenticate(fields) {
    const { body } = await this.request(AUTH_PATH, fields);
    if (body === 'true') {
      return true;
    }
    throw classify(body);
  }

  /** Returns the expiry of a license key. */
  async keyExpirationForKey(licenseKey) {
    return this.expiration({ ...(await this.baseFields()), key: licenseKey });
  }

  /** Returns the expiry of the authenticated user's key for this system. */
  async keyExpirationForPassword(username, password) {
    return this.expiration({ ...(await this.baseFields()), username, password });
  }

  async expiration(fields) {
    const { body, headers } = await this.request(AUTH_PATH, { ...fields, intent: 'expiration' });
    if ((headers['auth'] ?? '') !== 'true') {
      throw classify(body);
    }
    if (body === 'Never' || body === 'N/A') {
      return { permanent: true, expiresAt: body };
    }
    return { permanent: false, expiresAt: body };
  }

  /**
   * Fetches a server-side variable. Pass a license key as the second
   * argument when the variable is protected.
   */
  async getVariable(name, licenseKey = '') {
    const fields = {
      system: this.config.systemId,
      variable: name,
      clean: '1',
    };
    if (licenseKey) {
      fields.key = licenseKey;
    }

    const { body, headers } = await this.request(VARIABLE_PATH, fields);
    switch (headers['intent'] ?? '') {
      case 'true':
        return { found: true, value: body };
      case 'false':
        return { found: false, value: null };
      default:
        throw classify(body);
    }
  }

  /** Clears the HWID bound to a license key (self-service; 30-day cooldown). */
  async resetHwidForKey(licenseKey) {
    return this.resetHwid({ ...(await this.baseFields()), key: licenseKey });
  }

  /** Clears the HWID of the authenticated user's key. */
  async resetHwidForPassword(username, password) {
    return this.resetHwid({ ...(await this.baseFields()), username, password });
  }

  async resetHwid(fields) {
    const { body, headers } = await this.request(AUTH_PATH, { ...fields, intent: 'hwidreset' });
    const authHeader = headers['auth'] ?? '';
    if (authHeader !== '' && authHeader !== 'true') {
      throw classify(body);
    }
    switch (headers['intent'] ?? '') {
      case 'true':
      case '1':
        return RESET_GRANTED;
      case 'toosoon':
        return RESET_TOO_SOON;
      case 'false':
      case '':
        if (body === 'toosoon') {
          return RESET_TOO_SOON;
        }
        if (body === 'true' || body === '1') {
          return RESET_GRANTED;
        }
        return RESET_DENIED;
      default:
        throw new SimpleError(ErrorKind.UnknownReason, `Unexpected hwidreset response: ${headers['intent']}`, headers['intent']);
    }
  }

  /** The management sub-API (POST /api/v1). Requires config.apiKey. */
  management() {
    if (this._management === undefined) {
      const { Management } = require('./management');
      this._management = new Management(this);
    }
    return this._management;
  }
}

const RESET_OUTCOMES = Object.freeze({ RESET_GRANTED, RESET_DENIED, RESET_TOO_SOON });

module.exports = { Client, defaultConfig, RESET_OUTCOMES, RESET_GRANTED, RESET_DENIED, RESET_TOO_SOON };
