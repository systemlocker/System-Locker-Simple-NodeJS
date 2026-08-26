'use strict';

/**
 * Persistence for the secret-sharing module: the Windows registry
 * (HKLM with an HKCU fallback) or owner-only files elsewhere. All formats
 * are the normative cross-language ones.
 */

const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { CorruptHelperError, SLSTORE_PREFIX } = require('./slhwid-core.cjs');

const REG_ROOT_HKLM = 'HKLM\\SOFTWARE\\SystemLocker';
const REG_ROOT_HKCU = 'HKCU\\SOFTWARE\\SystemLocker';
const LOCK_FILE = '.slhwid.lock';
const LOCK_HEADER = 'SLHwidLockV1';
const LOCK_WAIT_MS = 30000;
const UNKNOWN_LOCK_GRACE_MS = 120000;

function localLockDirectory() {
  const local = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  return path.join(local, 'SystemLocker');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readLock(lockPath) {
  try {
    const contents = fs.readFileSync(lockPath, 'utf8');
    const [header, pidText, token] = contents.split('\n');
    const pid = Number.parseInt(pidText, 10);
    return header === LOCK_HEADER && Number.isSafeInteger(pid) && pid > 0 && token
      ? { contents, pid }
      : { contents, pid: null };
  } catch (error) {
    return error.code === 'ENOENT' ? null : { contents: null, pid: null };
  }
}

function processIsAlive(pid) {
  if (!pid) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists but is owned by somebody else.
    return error.code === 'EPERM';
  }
}

function removeIfUnchanged(lockPath, expected) {
  try {
    if (fs.readFileSync(lockPath, 'utf8') === expected) {
      fs.unlinkSync(lockPath);
    }
  } catch {
    /* A concurrent release/replacement needs no action. */
  }
}

async function acquireLock(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const lockPath = path.join(directory, LOCK_FILE);
  const token = crypto.randomBytes(16).toString('hex');
  const contents = LOCK_HEADER + '\n' + process.pid + '\n' + token + '\n';
  const deadline = Date.now() + LOCK_WAIT_MS;

  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600);
      try {
        fs.writeFileSync(fd, contents, 'utf8');
      } finally {
        fs.closeSync(fd);
      }
      return () => removeIfUnchanged(lockPath, contents);
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw new Error('slhwid: cannot acquire storage lock: ' + error.message);
      }
    }

    const existing = readLock(lockPath);
    if (existing && existing.contents !== null) {
      let stale = existing.pid !== null && !processIsAlive(existing.pid);
      if (existing.pid === null) {
        try {
          stale = Date.now() - fs.statSync(lockPath).mtimeMs >= UNKNOWN_LOCK_GRACE_MS;
        } catch {
          stale = false;
        }
      }
      if (stale) {
        removeIfUnchanged(lockPath, existing.contents);
        continue;
      }
    }
    if (Date.now() >= deadline) {
      throw new Error('slhwid: storage is busy; retry the operation');
    }
    await sleep(50);
  }
}

function run(command, args, timeoutMs) {
  return new Promise((resolve) => {
    const child = execFile(
      command,
      args,
      { timeout: timeoutMs ?? 4000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout) => resolve({ error, stdout: stdout ?? '' }),
    );
    child.on('error', () => resolve({ error: true, stdout: '' }));
  });
}

function parseRegBinary(output, name) {
  const lines = output.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const fields = lines[i].trim().split(/\s+/);
    for (let j = 1; j + 1 < fields.length; j++) {
      if (fields[j].toUpperCase() !== 'REG_BINARY' || fields[j - 1].toLowerCase() !== name.toLowerCase()) {
        continue;
      }
      const tokens = fields.slice(j + 1);
      for (let k = i + 1; k < lines.length; k++) {
        const continuation = lines[k].trim().split(/\s+/);
        if (continuation.length === 0 || continuation.length === 1 && continuation[0] === '') {
          break;
        }
        if (!continuation.every((t) => /^[0-9A-Fa-f]+$/.test(t))) {
          break;
        }
        tokens.push(...continuation);
      }
      const hex = tokens.join('');
      if (hex.length === 0 || hex.length % 2 !== 0) {
        return null;
      }
      return Buffer.from(hex, 'hex');
    }
  }
  return null;
}

class RegistryStore {
  constructor() {
    this.lockDir = localLockDirectory();
  }

  async withLock(operation) {
    const release = await acquireLock(this.lockDir);
    try {
      return await operation();
    } finally {
      release();
    }
  }

  async readValue(name) {
    for (const root of [REG_ROOT_HKLM, REG_ROOT_HKCU]) {
      const { error, stdout } = await run('reg', ['query', root, '/v', name, '/reg:64']);
      if (!error) {
        const data = parseRegBinary(stdout, name);
        if (data) {
          return data;
        }
      }
    }
    return null;
  }

  async writeValue(name, data) {
    for (const root of [REG_ROOT_HKLM, REG_ROOT_HKCU]) {
      const { error } = await run('reg', [
        'add', root, '/v', name, '/t', 'REG_BINARY', '/d', data.toString('hex'), '/f', '/reg:64',
      ]);
      if (!error) {
        return true;
      }
    }
    return false;
  }

  unwrapSlstore(data) {
    if (!data || data.length !== SLSTORE_PREFIX.length + 32) {
      throw new CorruptHelperError('slhwid: store secret has the wrong size');
    }
    if (!data.subarray(0, SLSTORE_PREFIX.length).equals(SLSTORE_PREFIX)) {
      throw new CorruptHelperError('slhwid: store secret prefix mismatch');
    }
    return data.subarray(SLSTORE_PREFIX.length);
  }

  async readSlstore() {
    const data = await this.readValue('SLStore');
    return data ? this.unwrapSlstore(data) : null;
  }

  async writeSlstore(value) {
    if (!await this.writeValue('SLStore', Buffer.concat([SLSTORE_PREFIX, value]))) {
      throw new Error('slhwid: registry write failed');
    }
  }

  async readHelper(helperId) {
    const blob = await this.readValue(`HWID-${helperId}`);
    return { blob, found: blob !== null };
  }

  async writeHelper(helperId, blob) {
    if (!await this.writeValue(`HWID-${helperId}`, blob)) {
      throw new Error('slhwid: registry write failed');
    }
  }
}

class DirStore {
  constructor(directory) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    try {
      fs.chmodSync(directory, 0o700);
    } catch {
      /* best effort on exotic filesystems */
    }
    this.dir = directory;
  }

  async withLock(operation) {
    const release = await acquireLock(this.dir);
    try {
      return await operation();
    } finally {
      release();
    }
  }

  unwrapSlstore(data) {
    if (!data || data.length !== SLSTORE_PREFIX.length + 32) {
      throw new CorruptHelperError('slhwid: store secret has the wrong size');
    }
    if (!data.subarray(0, SLSTORE_PREFIX.length).equals(SLSTORE_PREFIX)) {
      throw new CorruptHelperError('slhwid: store secret prefix mismatch');
    }
    return data.subarray(SLSTORE_PREFIX.length);
  }

  async readSlstore() {
    try {
      return this.unwrapSlstore(fs.readFileSync(path.join(this.dir, 'slstore.bin')));
    } catch (error) {
      if (error.code === 'ENOENT') {
        return null;
      }
      if (error instanceof CorruptHelperError) {
        throw error;
      }
      throw error;
    }
  }

  async writeSlstore(value) {
    this.writeSync('slstore.bin', Buffer.concat([SLSTORE_PREFIX, value]));
  }

  async readHelper(helperId) {
    try {
      const blob = fs.readFileSync(path.join(this.dir, `hwid-${helperId}.bin`));
      return { blob, found: true };
    } catch (error) {
      if (error.code === 'ENOENT') {
        return { blob: null, found: false };
      }
      throw error;
    }
  }

  async writeHelper(helperId, blob) {
    this.writeSync(`hwid-${helperId}.bin`, blob);
  }

  writeSync(name, data) {
    const target = path.join(this.dir, name);
    const temporary = path.join(this.dir, '.' + name + '.' + process.pid + '.' + crypto.randomBytes(8).toString('hex') + '.tmp');
    try {
      fs.writeFileSync(temporary, data, { mode: 0o600 });
      fs.renameSync(temporary, target);
    } finally {
      try {
        fs.unlinkSync(temporary);
      } catch (error) {
        if (error.code !== 'ENOENT') {
          throw error;
        }
      }
    }
    try {
      fs.chmodSync(target, 0o600); // tighten pre-existing files too
    } catch {
      /* best effort */
    }
  }
}

function defaultStore(override) {
  if (override) {
    return new DirStore(override);
  }
  if (process.platform === 'win32') {
    return new RegistryStore();
  }
  const home = os.homedir();
  const base = process.platform === 'darwin'
    ? path.join(home, 'Library', 'Application Support', 'SystemLocker')
    : process.env.XDG_DATA_HOME
      ? path.join(process.env.XDG_DATA_HOME, 'systemlocker')
      : path.join(home, '.local', 'share', 'systemlocker');
  return new DirStore(base);
}

module.exports = { defaultStore, DirStore, RegistryStore };
