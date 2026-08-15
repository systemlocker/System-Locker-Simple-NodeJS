'use strict';

const crypto = require('node:crypto');

/** Canonical composition order from the shared specification. */
const FACTOR_ORDER = Object.freeze([
  'machine_guid', 'product_uuid', 'board_serial', 'cpu_id', 'disk_serial', 'mac',
]);

const PLACEHOLDERS = new Set([
  '', 'none', 'unknown', 'default string', 'to be filled by o.e.m.',
  'not specified', 'system serial number',
]);

/**
 * Trims, lowercases, and strips NUL bytes. MAC values additionally drop
 * ":" and "-" separators; other factors (UUIDs, machine IDs) keep theirs.
 */
function normalize(name, raw) {
  let value = String(raw).replace(/\0/g, '').trim().toLowerCase();
  if (name === 'mac') {
    value = value.replace(/[: -]/g, '');
  }
  return value;
}

/**
 * Builds the canonical factor string. Factors absent (or holding placeholder
 * values) contribute nothing.
 * @param {Record<string, string>} factors
 */
function canonicalString(factors) {
  const parts = [];
  for (const name of FACTOR_ORDER) {
    if (!Object.prototype.hasOwnProperty.call(factors, name)) {
      continue;
    }
    const value = normalize(name, factors[name]);
    if (value === '' || PLACEHOLDERS.has(value)) {
      continue;
    }
    parts.push(`factor=${name}|value=${value}`);
  }
  return parts.join('&');
}

/** Hashes a canonical string into the final HWID. */
function fromCanonical(canonical) {
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

/** Derives an HWID from collected factors. */
function compose(factors) {
  return fromCanonical(canonicalString(factors));
}

module.exports = { FACTOR_ORDER, PLACEHOLDERS, normalize, canonicalString, fromCanonical, compose };
