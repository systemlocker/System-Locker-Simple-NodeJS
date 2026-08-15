'use strict';

const { SimpleError, ErrorKind } = require('./errors');

const API_V1_PATH = '/api/v1';

/** Expiry presets the server understands. */
const Expiry = Object.freeze({
  Permanent: '0',
  OneDay: '1',
  OneWeek: '2',
  OneMonth: '3',
  ThreeMonths: '4',
  OneYear: '5',
});

/**
 * Wraps POST /api/v1: key status/expiration, HWID resets, key generation,
 * bans, expiry adjustment. Independent of the auth protocol; meant for
 * server-side tooling. Requires config.apiKey — treat it as a secret.
 */
class Management {
  /** @param {import('./client').Client} client */
  constructor(client) {
    this.client = client;
  }

  async post(fields) {
    if (!this.client.config.apiKey) {
      throw new SimpleError(ErrorKind.Configuration, 'management API key not configured');
    }
    return this.client.request(API_V1_PATH, { ...fields, key: this.client.config.apiKey });
  }

  /** Number of redeemed keys for the system. */
  async redeemedUserCount() {
    const { body } = await this.post({ select: 'users' });
    const count = Number.parseInt(body, 10);
    if (!Number.isSafeInteger(count) || String(count) !== body) {
      throw new SimpleError(ErrorKind.UnknownReason, `non-numeric users response: ${body}`, body);
    }
    return count;
  }

  /** Redemption status of a license key (server-defined string). */
  async keyStatus(license) {
    const { body } = await this.post({ select: 'key', lkey: license });
    return body;
  }

  /** Expiration date of a license key. */
  async keyExpiration(license) {
    const { body } = await this.post({ select: 'expiration', lkey: license });
    const lower = body.toLowerCase();
    return { permanent: lower === 'permanent' || lower === 'never' || body === '0', expiresAt: body };
  }

  /** Resets the HWID of one key. asAdmin=false enforces the 30-day cooldown. */
  async resetHwid(license, asAdmin = true) {
    const fields = { command: 'hwidreset', license };
    if (!asAdmin) {
      fields.as_admin = 'false';
    }
    const { body } = await this.post(fields);
    return body;
  }

  /** Resets the HWID of every key in the system. Use with care. */
  async resetAllHwids() {
    const { body } = await this.post({ command: 'systemhwidreset' });
    return body;
  }

  /**
   * Generates count (1–100) keys with an expiry preset, optionally
   * annotated with a note (≤250 characters). Returns the raw body
   * (typically the keys, one per line).
   */
  async generateKeys(expiry, count, note = '') {
    if (!Number.isSafeInteger(count) || count < 1 || count > 100) {
      throw new SimpleError(ErrorKind.Configuration, 'count must be in [1, 100]');
    }
    if (note.length > 250) {
      throw new SimpleError(ErrorKind.Configuration, 'note must be at most 250 characters');
    }
    const fields = { command: 'genkeys', expire: expiry, count: String(count) };
    if (note) {
      fields.note = note;
    }
    const { body } = await this.post(fields);
    return body;
  }

  /** Permanently deletes a key. */
  async banKey(license) {
    const { body } = await this.post({ command: 'bankey', license });
    return body;
  }

  /**
   * Adjusts a key's expiry. newExpiry is a date the server understands
   * (e.g. "2026-12-31") or "0" for permanent. tz is an IANA timezone such
   * as "America/Chicago".
   */
  async adjustExpiry(license, newExpiry, tz) {
    const { body } = await this.post({ command: 'adjustexpiry', license, newexpiry: newExpiry, tz });
    return body;
  }
}

module.exports = { Management, Expiry };
