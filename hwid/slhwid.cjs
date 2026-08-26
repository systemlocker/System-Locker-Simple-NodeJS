'use strict';

/**
 * Fault-tolerant secret-sharing HWID module: a random
 * 244-bit key is shared across hardware factors with a threshold scheme, and
 * the transmitted HWID is a domain-separated hash of that key. Ordinary
 * hardware drift leaves the HWID unchanged; mandatory slots (by default the
 * module's own persisted random value) can never be routed around.
 *
 * The module is on by default since 1.0.0 (see the client's hwidMode
 * configuration) and can also be driven directly:
 *
 *   const session = await slhwid.prepare({});
 *   // ... authenticate with session.hwid ...
 *   await session.commit(); // after the server accepted the authentication
 */

const {
  CorruptHelperError,
  DriftError,
  Draw,
  SsError,
  buildShares,
  checkWord,
  hwidOf,
  CURRENT_NORM_VERSION,
  mapMandatoryToCurrent,
  normalizeFactors,
  parseHelper,
  projectFactors,
  recoverCore,
  refreshCore,
  serializeHelper,
  slotList,
  threshold,
} = require('./slhwid-core.cjs');

const SLOT_NAME_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
const DEVICE_HELPER_ID = 'device';

class Session {
  constructor(hwid, fresh, drifted, pending) {
    this.hwid = hwid;
    this.freshlyEnrolled = fresh;
    this.driftedSlots = drifted;
    this.pendingRefresh = pending;
    this._committed = false;
    this._key = null;
    this._draw = null;
    this._factors = null;
    this._mandatory = null;
    this._store = null;
    this._expectedHelper = null;
  }

  /**
   * Re-shares the recovered key over the hardware observed at prepare time
   * and persists the new helper data. Must only be called after the server
   * accepted the authentication that used the hwid. Failures are non-fatal:
   * the next launch re-derives everything.
   */
  async commit() {
    if (this._committed || this._key === null) {
      this._key = null;
      return;
    }
    this._committed = true;
    try {
      await withStoreLock(this._store, async () => {
        const current = await this._store.readHelper(DEVICE_HELPER_ID);
        if (!current.found || !current.blob.equals(this._expectedHelper)) {
          // Another module user refreshed or re-enrolled this device after
          // prepare. A stale session must never overwrite that newer state.
          return;
        }
        const { blob, written } = refreshCore(this._key, this._factors, this._mandatory, this._draw);
        if (written) {
          await this._store.writeHelper(DEVICE_HELPER_ID, blob);
          this.pendingRefresh = false;
          this.driftedSlots = [];
        }
      });
    } catch {
      /* the next launch re-derives */
    } finally {
      this._key = null; // best-effort zeroization of the reference
    }
  }
}

/** Collects factors and recovers (or enrolls) the secret-sharing HWID. */
async function prepare(options) {
  return prepareWith(options, null, null, null);
}

async function prepareWith(options, collect, source, store) {
  options ??= {};
  const requestedMandatory = new Set(['slstore']);
  for (const name of options.extraMandatory ?? []) {
    if (!SLOT_NAME_PATTERN.test(name)) {
      throw new SsError(`slhwid: invalid extra mandatory slot name ${JSON.stringify(name)}`);
    }
    requestedMandatory.add(name);
  }

  const collected = await (collect ?? require('./slhwid-collect.cjs').collect)();
  const rawFactors = normalizeFactors(collected);
  const randomness = source ?? require('./slhwid-core.cjs').randomSource;
  const theStore = store ?? require('./slhwid-store.cjs').defaultStore(options.storePath);

  const hid = DEVICE_HELPER_ID;
  return withStoreLock(theStore, async () => {
  const { blob: storedBlob, found } = await theStore.readHelper(hid);

  // The slstore factor is ours, not collectable hardware: recovery injects
  // the persisted value (read-only). An absent value with an existing helper
  // is intentional tampering and recoverCore reports it as a hard-locked
  // mandatory failure below.
  if (found && !options.forceReenroll && !rawFactors.slstore) {
    const value = await theStore.readSlstore();
    if (value) {
      if (value.length !== 32) {
        throw new CorruptHelperError('slhwid: store secret has the wrong size');
      }
      rawFactors.slstore = value.toString('hex');
    }
  }

  if (!found || options.forceReenroll) {
    if (!rawFactors.slstore) {
      rawFactors.slstore = await ensureSlstore(theStore, randomness);
    }
    const factors = projectFactors(rawFactors, CURRENT_NORM_VERSION);
    const mandatory = mapMandatoryToCurrent(requestedMandatory);
    for (const name of [...mandatory].sort()) {
      if (!factors[name]) {
        throw new SsError(`slhwid: mandatory factor ${JSON.stringify(name)} is not available on this machine`);
      }
    }
    const n = Object.keys(factors).length;
    const m = mandatory.size;
    const t = threshold(n, m);
    const draw = new Draw(randomness);
    const k = [draw.elem(), draw.elem(), draw.elem(), draw.elem()];
    const { shares, salt } = buildShares(k, slotList(factors, mandatory), t, draw);
    const blob = serializeHelper(shares, mandatory, t, salt, checkWord(k), CURRENT_NORM_VERSION);
    await theStore.writeHelper(hid, blob);
    const session = new Session(hwidOf(k), true, [], false);
    session._key = k;
    session._draw = new Draw(randomness);
    session._factors = factors;
    session._mandatory = mandatory;
    session._store = theStore;
    session._expectedHelper = Buffer.from(blob);
    return session;
  }

  let helper;
  try {
    helper = parseHelper(storedBlob);
  } catch (error) {
    if (error instanceof CorruptHelperError) {
      throw new CorruptHelperError('slhwid: stored helper data is corrupt; re-enroll to recover');
    }
    throw error;
  }
  // Recovery must use the factor schema encoded in the helper. In particular,
  // v1 slots remain plain raw signals until a successful authentication allows
  // commit() to migrate the helper to v2.
  const recoveryFactors = projectFactors(rawFactors, helper.normVersion);
  const result = recoverCore(storedBlob, recoveryFactors);
  if (!result.ok) {
    if (result.reason === 'corrupt') {
      throw new CorruptHelperError('slhwid: stored helper data is corrupt; re-enroll to recover');
    }
    throw new DriftError(result.present, result.needed, result.missing, result.reason === 'mandatory');
  }
  const currentFactors = projectFactors(rawFactors, CURRENT_NORM_VERSION);
  const storedMandatory = mapMandatoryToCurrent(helper.slots
    .filter((slot) => slot.mandatory)
    .map((slot) => slot.name));
  const session = new Session(
    result.hwid,
    false,
    result.dead,
    result.pending || helper.normVersion !== CURRENT_NORM_VERSION,
  );
  session._key = result.key;
  session._draw = new Draw(randomness);
  session._factors = currentFactors;
  // A second application must not weaken a hard lock selected by the
  // application that enrolled the shared device helper.
  session._mandatory = storedMandatory;
  session._store = theStore;
  session._expectedHelper = Buffer.from(storedBlob);
  return session;
  });
}

async function withStoreLock(store, operation) {
  return typeof store.withLock === 'function' ? store.withLock(operation) : operation();
}

async function ensureSlstore(store, source) {
  const existing = await store.readSlstore();
  if (existing) {
    if (existing.length !== 32) {
      throw new CorruptHelperError('slhwid: store secret has the wrong size');
    }
    return existing.toString('hex');
  }
  const value = source(32);
  if (value.length !== 32) {
    throw new SsError('slhwid: randomness failed');
  }
  await store.writeSlstore(value);
  return value.toString('hex');
}

module.exports = { prepare, prepareWith, Session, DriftError, CorruptHelperError, SsError };
