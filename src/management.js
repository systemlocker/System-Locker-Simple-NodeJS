'use strict';

const { SimpleError, ErrorKind } = require('./errors');

/** Key-generation expiry presets. Duration presets start at redemption. */
const Expiry = Object.freeze({
  Permanent: '0',
  OneDay: '1',
  OneWeek: '2',
  OneMonth: '3',
  ThreeMonths: '4',
  OneYear: '5',
});

// Duration in seconds for each Expiry preset, indexed by its value.
// Index 0 (permanent) is never sent as a duration.
const PRESET_SECONDS = [0, 86400, 604800, 2592000, 7776000, 31536000];
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

// Reads a required field from a response's data object. A missing field and
// an invalid value are both protocol errors rather than silent defaults.
function field(data, name, valid) {
  if (!data || typeof data !== 'object' || !Object.hasOwn(data, name) || !valid(data[name])) {
    throw new SimpleError(ErrorKind.Transport, `invalid management field: ${name}`);
  }
  return data[name];
}

const isStringArray = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string');
const isNullableString = (value) => value === null || typeof value === 'string';

/**
 * Wraps the Management API v2 (/api/v2). Independent of the authentication
 * protocol; meant for server-side tooling. config.apiKey must hold a scoped
 * v2 bearer credential for this system — treat it as a secret.
 */
class Management {
  /** @param {import('./client').Client} client */
  constructor(client) {
    this.client = client;
  }

  get systemPath() {
    return `/systems/${encodeURIComponent(this.client.config.systemId)}`;
  }

  keyPath(license) {
    return `${this.systemPath}/keys/${encodeURIComponent(license)}`;
  }

  /**
   * Calls any v2 resource path (relative to /api/v2, e.g. '/permissions' or
   * '/systems/{id}/nightflyer') and returns the response's JSON `data`.
   * POST/PUT/PATCH without data send an empty JSON object. A non-2xx
   * response throws a SimpleError whose `reason` is the server's error code
   * (e.g. 'INSUFFICIENT_SCOPE'). Mutations are never retried.
   */
  async request(method, path, data) {
    const credential = this.client.config.apiKey;
    if (!credential || /[\r\n]/.test(credential)) {
      throw new SimpleError(ErrorKind.Configuration, 'a management bearer credential is required');
    }
    if (!METHODS.includes(method) || typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.includes('#')) {
      throw new SimpleError(ErrorKind.Configuration, 'invalid management method or resource path');
    }
    const transport = this.client.transport;
    if (typeof transport.requestJson !== 'function') {
      throw new SimpleError(ErrorKind.Configuration, 'HTTP client must implement requestJson for management');
    }
    const headers = { Authorization: `Bearer ${credential}`, Accept: 'application/json' };
    // The server requires a JSON Content-Type on every mutation, even one
    // without fields.
    const body = data === undefined && ['POST', 'PUT', 'PATCH'].includes(method) ? {} : data;
    const response = await transport.requestJson(method, this.client.endpoint('/api/v2' + path), body, headers);
    if (response.error) throw new SimpleError(ErrorKind.Transport, String(response.error));
    let payload;
    try {
      payload = JSON.parse(Buffer.from(response.body).toString('utf8'));
    } catch {
      throw new SimpleError(ErrorKind.Transport, `management returned invalid JSON (HTTP ${response.status})`);
    }
    if (response.status < 200 || response.status >= 300) {
      const detail = payload && typeof payload.error === 'object' && payload.error !== null ? payload.error : {};
      const message = typeof detail.message === 'string' && detail.message ? detail.message : `management HTTP ${response.status}`;
      throw new SimpleError(ErrorKind.Transport, message, typeof detail.code === 'string' ? detail.code : '');
    }
    if (!payload || typeof payload !== 'object' || !Object.hasOwn(payload, 'data')) {
      throw new SimpleError(ErrorKind.UnknownReason, 'management response is missing data');
    }
    return payload.data;
  }

  /** Scopes granted to the configured credential. Requires no scope. */
  async permissions() {
    return field(await this.request('GET', '/permissions'), 'scopes', isStringArray);
  }

  /**
   * The system's user count (accounts plus key-only redemptions). The server
   * refreshes it periodically, so it can lag behind recent redemptions.
   * Requires systems.read.
   */
  async redeemedUserCount() {
    return field(await this.request('GET', this.systemPath + '/statistics'), 'total_users',
      (value) => Number.isSafeInteger(value) && value >= 0);
  }

  /**
   * How a key is claimed: 'user' (attached to an account), 'mikros'
   * (redeemed without an account) or 'unclaimed'. Requires keys.read.
   */
  async keyStatus(license) {
    return field(await this.request('GET', this.keyPath(license)), 'claim_type', (value) => typeof value === 'string');
  }

  /**
   * A key's expiry. `expiresAt` is an RFC 3339 UTC timestamp, or '' when the
   * key has no fixed expiry. `permanent` is only reported for redeemed keys:
   * an unredeemed duration key has no timestamp yet either. Requires keys.read.
   */
  async keyExpiration(license) {
    const data = await this.request('GET', this.keyPath(license));
    const expiry = field(data, 'expires_at', isNullableString);
    const redeemed = field(data, 'redeemed_at', isNullableString);
    return { permanent: expiry === null && redeemed !== null, expiresAt: expiry ?? '' };
  }

  /**
   * Administrative HWID reset of one key (no cooldown). Returns the key's
   * details as JSON text. Self-service resets use client.resetHwidForKey.
   * Requires keys.update.
   */
  async resetHwid(license) {
    return JSON.stringify(await this.request('POST', this.keyPath(license) + '/hwid-reset'));
  }

  /** Resets every key's HWID; returns '{"updated":count}'. Use with care. Requires keys.update. */
  async resetAllHwids() {
    return JSON.stringify(await this.request('POST', this.systemPath + '/keys/hwid-reset'));
  }

  /**
   * Generates count (1–100) keys with an Expiry preset, optionally annotated
   * with a note (≤250 characters). Returns the keys one per line. Duration
   * presets start at redemption. Requires keys.create.
   */
  async generateKeys(expiry, count, note = '') {
    if (!Number.isInteger(count) || count < 1 || count > 100) {
      throw new SimpleError(ErrorKind.Configuration, 'count must be in [1, 100]');
    }
    if ([...note].length > 250) {
      throw new SimpleError(ErrorKind.Configuration, 'note must be at most 250 characters');
    }
    if (!/^[0-5]$/.test(String(expiry))) {
      throw new SimpleError(ErrorKind.Configuration, 'invalid expiry preset');
    }
    const seconds = PRESET_SECONDS[Number(expiry)];
    const policy = seconds ? { type: 'after_redemption', seconds } : { type: 'perpetual' };
    const data = await this.request('POST', this.systemPath + '/keys', { count, notes: note, expiry: policy });
    return field(data, 'keys', isStringArray).join('\n');
  }

  /** Permanently deletes a key; returns '{"deleted":true}'. Requires keys.delete. */
  async banKey(license) {
    return JSON.stringify(await this.request('DELETE', this.keyPath(license)));
  }

  /**
   * Extends a key's expiry by a positive number of seconds; returns the key's
   * details as JSON text. Replaces the retired absolute-expiry adjustment,
   * which has no v2 equivalent. Requires keys.update.
   */
  async addTime(license, seconds) {
    if (!Number.isSafeInteger(seconds) || seconds <= 0) {
      throw new SimpleError(ErrorKind.Configuration, 'seconds must be a positive integer');
    }
    return JSON.stringify(await this.request('POST', this.keyPath(license) + '/time', { seconds }));
  }
}

module.exports = { Management, Expiry };
