'use strict';

/**
 * Pure cryptographic core of the §4A secret-sharing HWID module: GF(2^61-1)
 * arithmetic on BigInt, four-limb secret sharing, x-derivation, helper-blob
 * serialization, recovery and refresh. Platform-free; the lifecycle in
 * ss.cjs wires it to collectors, storage and the CSPRNG.
 */

const crypto = require('crypto');

const P = (1n << 61n) - 1n;
const HELPER_MAGIC = Buffer.from('SLSSHWID', 'ascii');
const SLSTORE_PREFIX = Buffer.from('SLSTOR1', 'ascii');

class SsError extends Error {}
class CorruptHelperError extends SsError {}

class DriftError extends SsError {
  constructor(present, needed, missing, mandatory) {
    const detail = mandatory
      ? `mandatory factor(s) ${missing.join(', ')} changed or absent; re-activation required`
      : `hardware drifted past the recovery threshold (${present} factors present, ${needed} needed); re-activation required`;
    super(`slhwid: ${detail}`);
    this.present = present;
    this.needed = needed;
    this.missing = missing;
    this.mandatory = mandatory;
  }
}

// ── field arithmetic ────────────────────────────────────────────────

function addmod(a, b) {
  const s = a + b;
  return s >= P ? s - P : s;
}

function submod(a, b) {
  return a >= b ? a - b : a + P - b;
}

function mulmod(a, b) {
  return (a * b) % P;
}

function invmod(a) {
  let lm = 1n;
  let hm = 0n;
  let low = a % P;
  let high = P;
  while (low > 1n) {
    const r = high / low;
    [lm, hm] = [hm - lm * r, lm];
    [low, high] = [high - low * r, low];
  }
  if (lm < 0n) {
    lm += P;
  }
  return lm;
}

// ── randomness ──────────────────────────────────────────────────────

/** Replays a byte source (callable n -> Buffer) as 8-byte LE draws. */
class Draw {
  constructor(source) {
    this.source = source;
  }

  elem() {
    const chunk = this.source(8);
    if (chunk.length !== 8) {
      throw new SsError('slhwid: randomness exhausted');
    }
    return chunk.readBigUInt64LE(0) % P;
  }
}

function randomSource(n) {
  return crypto.randomBytes(n);
}

function fixedSource(data) {
  let pos = 0;
  return (n) => data.subarray(pos, (pos += n));
}

// ── derivation ──────────────────────────────────────────────────────

function deriveX(slot, value, salt) {
  const h = crypto.createHash('sha256');
  h.update(Buffer.from('SL-SS-X1', 'ascii'));
  h.update(Buffer.from([0, salt, 0]));
  h.update(Buffer.from(slot, 'ascii'));
  h.update(Buffer.from([0]));
  h.update(Buffer.from(value, 'utf8'));
  const digest = h.digest();
  const v = digest.readBigUInt64LE(0) & P;
  return 1n + (v % (P - 1n));
}

function keyBytes(k) {
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    out.writeBigUInt64LE(k[i], i * 8);
  }
  return out;
}

function checkWord(k) {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from('SL-SS-CW1', 'ascii'), keyBytes(k)]))
    .digest();
}

function hwidOf(k) {
  const digest = crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x02]), Buffer.from('SL-SS-ID1', 'ascii'), keyBytes(k)]))
    .digest();
  return digest.toString('base64url');
}

function ctEqual(a, b) {
  return crypto.timingSafeEqual(a, b);
}

// ── threshold ───────────────────────────────────────────────────────

function threshold(n, m) {
  // A conservative physical-machine floor is nine current-schema slots;
  // requiring one fewer tolerates one unavailable collector. V1 helpers keep
  // their stored threshold, so raising this enrollment floor cannot strand an
  // existing device.
  if (n < 8) {
    throw new SsError(`slhwid: need at least 8 enrolled factor slots, have ${n}`);
  }
  if (m >= n) {
    throw new SsError(`slhwid: mandatory slots (${m}) must be fewer than total (${n})`);
  }
  // Keep both branches explicit for the schema contract. New helpers begin
  // at eight factors, therefore use the 70% branch today.
  const [num, den] = n < 8 ? [4, 5] : [7, 10];
  const t = Math.ceil((num * n) / den);
  return Math.max(m + 1, Math.min(t, n));
}

// ── normalization ───────────────────────────────────────────────────

const PLACEHOLDERS = new Set([
  '',
  'none',
  'unknown',
  'default string',
  'to be filled by o.e.m.',
  'not specified',
  'system serial number',
]);

function normalize(name, raw) {
  let value = String(raw).replace(/\0/g, '').trim().toLowerCase();
  if (name === 'mac' || name === 'nic_identity') {
    value = value.replace(/[:\-]/g, '');
  }
  return value;
}

function isMissing(value) {
  return PLACEHOLDERS.has(value.trim());
}

function normalizeFactors(raw) {
  const out = {};
  for (const [name, value] of Object.entries(raw)) {
    const nv = normalize(name, value);
    if (nv && !isMissing(nv)) {
      out[name] = nv;
    }
  }
  return out;
}

const LEGACY_NORM_VERSION = 1;
const CURRENT_NORM_VERSION = 2;

// These names are historical compatibility data. Do not change this list:
// schema-v1 helpers need the exact slots they were enrolled against.
const LEGACY_FACTOR_NAMES = Object.freeze([
  'slstore', 'machine_guid', 'product_uuid', 'board_serial', 'cpu_id', 'disk_serial', 'mac',
  'ram_total', 'volume_id', 'computer_name', 'firmware', 'gpu_id', 'monitor_edid', 'os_build',
]);

const CURRENT_DIRECT_FACTOR_NAMES = Object.freeze([
  'slstore', 'machine_guid', 'cpu_id', 'disk_serial', 'ram_total', 'volume_id', 'firmware',
  'tpm_ek', 'memory_modules', 'nic_identity', 'battery_serial',
]);

const CURRENT_FACTOR_GROUPS = Object.freeze([
  ['platform_identity', ['system_uuid', 'board_serial', 'system_serial', 'chassis_serial']],
  ['display_group', ['gpu_id', 'monitor_edid']],
  ['software_environment', ['computer_name', 'os_build']],
]);

function groupValue(name, members, raw) {
  const hash = crypto.createHash('sha256');
  hash.update('SL-HWID-GROUP2\0', 'ascii');
  hash.update(name, 'ascii');
  hash.update(Buffer.from([0]));
  let present = false;
  for (const member of members) {
    const value = raw[member] ?? '';
    present ||= value !== '';
    hash.update(member, 'ascii');
    hash.update(Buffer.from([0]));
    if (value !== '') {
      hash.update(value, 'utf8');
    }
    hash.update(Buffer.from([0]));
  }
  return present ? hash.digest('hex') : '';
}

/** Projects collected raw signals into the helper's factor schema. */
function projectFactors(raw, normVersion) {
  const output = {};
  if (normVersion === LEGACY_NORM_VERSION) {
    for (const name of LEGACY_FACTOR_NAMES) {
      if (raw[name]) {
        output[name] = raw[name];
      }
    }
    return output;
  }
  if (normVersion !== CURRENT_NORM_VERSION) {
    throw new SsError(`slhwid: unsupported factor schema ${normVersion}`);
  }
  for (const name of CURRENT_DIRECT_FACTOR_NAMES) {
    if (raw[name]) {
      output[name] = raw[name];
    }
  }
  for (const [name, members] of CURRENT_FACTOR_GROUPS) {
    const value = groupValue(name, members, raw);
    if (value) {
      output[name] = value;
    }
  }
  return output;
}

function currentMandatoryName(name) {
  if (['product_uuid', 'board_serial', 'system_uuid', 'system_serial', 'chassis_serial'].includes(name)) {
    return 'platform_identity';
  }
  if (name === 'gpu_id' || name === 'monitor_edid') {
    return 'display_group';
  }
  if (name === 'computer_name' || name === 'os_build') {
    return 'software_environment';
  }
  return name === 'mac' ? 'nic_identity' : name;
}

function mapMandatoryToCurrent(names) {
  return new Set([...names].map(currentMandatoryName));
}

// ── sharing ─────────────────────────────────────────────────────────

function slotList(factors, mandatory) {
  return Object.keys(factors)
    .sort()
    .map((name) => ({ name, value: factors[name], mandatory: mandatory.has(name) }));
}

function buildShares(k, slots, t, draw) {
  let salt = 0;
  let xs;
  for (;;) {
    xs = slots.map((s) => deriveX(s.name, s.value, salt));
    const seen = new Set(xs.map(String));
    if (seen.size === xs.length) {
      break;
    }
    salt++;
    if (salt === 255) {
      throw new SsError('slhwid: x-coordinate collision loop');
    }
  }
  const coeffs = [[], [], [], []];
  for (let limb = 0; limb < 4; limb++) {
    coeffs[limb][0] = 0n;
    for (let j = 1; j < t; j++) {
      coeffs[limb][j] = draw.elem();
    }
  }
  const shares = {};
  for (let i = 0; i < slots.length; i++) {
    const share = [];
    for (let limb = 0; limb < 4; limb++) {
      let acc = 0n;
      for (let j = t - 1; j >= 1; j--) { // Horner
        acc = addmod(mulmod(acc, xs[i]), coeffs[limb][j]);
      }
      share.push(addmod(mulmod(acc, xs[i]), k[limb]));
    }
    shares[slots[i].name] = share;
  }
  return { shares, salt };
}

// ── helper blob ─────────────────────────────────────────────────────

function serializeHelper(shares, mandatory, t, salt, cw, normVersion = CURRENT_NORM_VERSION) {
  const names = Object.keys(shares).sort();
  const payload = Buffer.alloc(8 + names.length * 35 + names.reduce((a, n) => a + n.length, 0));
  payload.writeUInt8(1, 0); // version
  payload.writeUInt8(normVersion, 1); // factor schema version
  payload.writeUInt8(salt, 2);
  payload.writeUInt8(names.length, 3);
  payload.writeUInt8(names.filter((n) => mandatory.has(n)).length, 4);
  payload.writeUInt8(t, 5);
  payload.writeUInt16LE(0, 6);
  let offset = 8;
  for (const name of names) {
    payload.writeUInt8(name.length, offset++);
    payload.write(name, offset, 'ascii');
    offset += name.length;
    payload.writeUInt8(mandatory.has(name) ? 1 : 0, offset++);
    for (let limb = 0; limb < 4; limb++) {
      payload.writeBigUInt64LE(shares[name][limb], offset);
      offset += 8;
    }
  }
  const head = Buffer.concat([HELPER_MAGIC, Buffer.alloc(4), payload.subarray(0, offset)]);
  head.writeUInt32LE(offset, 8);
  const integrity = crypto.createHash('sha256').update(Buffer.concat([head, cw])).digest();
  return Buffer.concat([head, cw, integrity]);
}

function parseHelper(blob) {
  const corrupt = (why) => new CorruptHelperError(`slhwid: stored helper data is corrupt: ${why}`);
  if (blob.length < 8 + 4 + 8 + 32 + 32) {
    throw corrupt('truncated');
  }
  if (!blob.subarray(0, 8).equals(HELPER_MAGIC)) {
    throw corrupt('magic mismatch');
  }
  const integrity = crypto.createHash('sha256').update(blob.subarray(0, blob.length - 32)).digest();
  if (!ctEqual(integrity, blob.subarray(blob.length - 32))) {
    throw corrupt('integrity mismatch');
  }
  const payloadLen = blob.readUInt32LE(8);
  if (12 + payloadLen + 64 !== blob.length) {
    throw corrupt('length mismatch');
  }
  const body = blob.subarray(12, 12 + payloadLen);
  const cw = blob.subarray(12 + payloadLen, 12 + payloadLen + 32);
  if (body[0] !== 1) {
    throw corrupt(`unsupported version ${body[0]}`);
  }
  if (body[1] !== LEGACY_NORM_VERSION && body[1] !== CURRENT_NORM_VERSION) {
    throw corrupt(`unsupported factor schema ${body[1]}`);
  }
  const helper = { normVersion: body[1], salt: body[2], threshold: body[5], checkWord: cw, slots: [] };
  const n = body[3];
  let offset = 8;
  const seen = new Set();
  for (let i = 0; i < n; i++) {
    if (offset + 1 > body.length) {
      throw corrupt('slot truncated');
    }
    const nameLen = body[offset];
    if (nameLen === 0 || offset + 1 + nameLen + 1 + 32 > body.length) {
      throw corrupt('slot truncated');
    }
    const name = body.toString('ascii', offset + 1, offset + 1 + nameLen);
    if (seen.has(name)) {
      throw corrupt(`duplicate slot ${name}`);
    }
    seen.add(name);
    const mandatory = (body[offset + 1 + nameLen] & 1) === 1;
    const share = [];
    for (let limb = 0; limb < 4; limb++) {
      const value = body.readBigUInt64LE(offset + 2 + nameLen + limb * 8);
      if (value >= P) {
        throw corrupt('share limb out of range');
      }
      share.push(value);
    }
    helper.slots.push({ name, mandatory, share });
    offset += 2 + nameLen + 32;
  }
  if (offset !== body.length) {
    throw corrupt('trailing bytes');
  }
  return helper;
}

// ── recovery ────────────────────────────────────────────────────────

function lagrangeAtZero(xs, ys) {
  let total = 0n;
  for (let j = 0; j < xs.length; j++) {
    let num = 1n;
    let den = 1n;
    for (let k = 0; k < xs.length; k++) {
      if (k === j) {
        continue;
      }
      num = mulmod(num, xs[k]);
      den = mulmod(den, submod(xs[k], xs[j]));
    }
    total = addmod(total, mulmod(ys[j], mulmod(num, invmod(den))));
  }
  return total;
}

function evaluateAt(xs, ys, xq) {
  let total = 0n;
  for (let j = 0; j < xs.length; j++) {
    let num = 1n;
    let den = 1n;
    for (let k = 0; k < xs.length; k++) {
      if (k === j) {
        continue;
      }
      num = mulmod(num, submod(xq, xs[k]));
      den = mulmod(den, submod(xs[j], xs[k]));
    }
    total = addmod(total, mulmod(ys[j], mulmod(num, invmod(den))));
  }
  return total;
}

function keyFromPoints(points) {
  const xs = points.map((p) => p.x);
  return [0, 1, 2, 3].map((limb) => lagrangeAtZero(xs, points.map((p) => p.share[limb])));
}

// The sweep is exhaustive: neither intermediate failures nor a match
// truncate it, so the amount of work done does not signal which factors
// survived (side-channel resistance).
function* combinations(length, need) {
  const idx = [];
  function* dfs(start) {
    if (idx.length === need) {
      yield [...idx];
      return;
    }
    for (let i = start; i <= length - (need - idx.length); i++) {
      idx.push(i);
      yield* dfs(i + 1);
      idx.pop();
    }
  }
  yield* dfs(0);
}

function findRecoveringSubset(mandatory, optional, t, cw) {
  const need = Math.max(0, t - mandatory.length);
  if (need > optional.length) {
    return null;
  }
  let found = null;
  for (const combo of combinations(optional.length, need)) {
    const points = mandatory.concat(combo.map((i) => optional[i]));
    if (found === null && ctEqual(Buffer.from(checkWord(keyFromPoints(points))), cw)) {
      found = { points, chosen: new Set(combo.map((i) => optional[i].name)) };
    }
  }
  return found;
}

function isMandatorySlot(helper, name) {
  return helper.slots.some((s) => s.name === name && s.mandatory);
}

function recoverCore(blob, factors) {
  let helper;
  try {
    helper = parseHelper(blob);
  } catch (error) {
    if (error instanceof CorruptHelperError) {
      return { ok: false, reason: 'corrupt' };
    }
    throw error;
  }
  const t = helper.threshold;

  const mandatory = [];
  const optional = [];
  const missingMandatory = [];
  let present = 0;
  for (const slot of helper.slots) { // slots are stored sorted by name
    const value = factors[slot.name];
    if (!value) {
      if (slot.mandatory) {
        missingMandatory.push(slot.name);
      }
      continue;
    }
    present++;
    const point = { name: slot.name, x: deriveX(slot.name, value, helper.salt), share: slot.share };
    if (slot.mandatory) {
      mandatory.push(point);
    } else {
      optional.push(point);
    }
  }
  // The sweep runs to completion regardless of absences or failures
  // (constant-work shape); the hard-locked mandatory verdict is applied
  // afterwards and any accidental match is discarded.
  const found = findRecoveringSubset(mandatory, optional, t, helper.checkWord);
  if (missingMandatory.length > 0) {
    return { ok: false, reason: 'mandatory', present, needed: t, missing: missingMandatory };
  }
  if (!found) {
    // Diagnostic: if dropping one mandatory slot lets the rest of the
    // machine recover, that mandatory factor was changed (intentional
    // tampering) rather than the machine having drifted. Every mandatory
    // slot is tested (no early exit); the first culprit in stored order wins.
    let culprit = '';
    for (const ms of helper.slots) {
      if (!ms.mandatory) {
        continue;
      }
      const merged = mandatory.concat(optional).filter((p) => p.name !== ms.name);
      const mand2 = merged.filter((p) => isMandatorySlot(helper, p.name));
      const opt2 = merged.filter((p) => !isMandatorySlot(helper, p.name));
      if (culprit === '' && findRecoveringSubset(mand2, opt2, t, helper.checkWord)) {
        culprit = ms.name;
      }
    }
    if (culprit !== '') {
      return { ok: false, reason: 'mandatory', present, needed: t, missing: [culprit] };
    }
    return { ok: false, reason: 'drift', present, needed: t };
  }

  const k = keyFromPoints(found.points);
  const xs = found.points.map((p) => p.x);
  const live = [];
  const dead = [];
  for (const slot of helper.slots) {
    const inMandatory = mandatory.some((p) => p.name === slot.name);
    if (inMandatory || found.chosen.has(slot.name)) {
      live.push(slot.name);
      continue;
    }
    const value = factors[slot.name];
    if (!value) {
      dead.push(slot.name);
      continue;
    }
    const xq = deriveX(slot.name, value, helper.salt);
    const onCurve = [0, 1, 2, 3].every(
      (limb) => evaluateAt(xs, found.points.map((p) => p.share[limb]), xq) === slot.share[limb],
    );
    (onCurve ? live : dead).push(slot.name);
  }
  live.sort();
  dead.sort();
  return { ok: true, key: k, hwid: hwidOf(k), live, dead, pending: dead.length > 0 };
}

function refreshCore(k, factors, mandatory, draw) {
  // During v1-to-v2 migration a legacy hard lock can map to a grouped slot.
  // If the current collector cannot produce that slot, skip the rewrite: a
  // refresh that omitted it would silently weaken the original hard lock.
  if ([...mandatory].some((name) => !factors[name])) {
    return { blob: null, written: false };
  }
  const slots = slotList(factors, mandatory);
  const m = slots.filter((s) => s.mandatory).length;
  let t;
  try {
    t = threshold(slots.length, m);
  } catch {
    return { blob: null, written: false };
  }
  const { shares, salt } = buildShares(k, slots, t, draw);
  const blob = serializeHelper(shares, mandatory, t, salt, checkWord(k), CURRENT_NORM_VERSION);
  return { blob, written: true };
}

module.exports = {
  P,
  SLSTORE_PREFIX,
  SsError,
  CorruptHelperError,
  DriftError,
  Draw,
  randomSource,
  fixedSource,
  addmod,
  submod,
  mulmod,
  invmod,
  deriveX,
  checkWord,
  hwidOf,
  threshold,
  normalize,
  normalizeFactors,
  LEGACY_NORM_VERSION,
  CURRENT_NORM_VERSION,
  LEGACY_FACTOR_NAMES,
  CURRENT_DIRECT_FACTOR_NAMES,
  CURRENT_FACTOR_GROUPS,
  groupValue,
  projectFactors,
  currentMandatoryName,
  mapMandatoryToCurrent,
  slotList,
  buildShares,
  serializeHelper,
  parseHelper,
  recoverCore,
  refreshCore,
};
