'use strict';

const os = require('node:os');
const { execFile } = require('node:child_process');

const { compose } = require('./core.cjs');

const VIRTUAL_PREFIXES = [
  'vethernet', 'vmware', 'virtual', 'loopback', 'tap', 'tun', 'zerotier',
  'wsl', 'docker', 'veth', 'br-', 'bluetooth', 'tailscale', 'vpn', 'wg', 'zt',
];

function isVirtualInterfaceName(name) {
  const lower = name.toLowerCase();
  return VIRTUAL_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

function macAddress() {
  for (const iface of Object.values(os.networkInterfaces())) {
    for (const entry of iface ?? []) {
      if (entry.internal || entry.mac === '00:00:00:00:00:00' || entry.mac.length !== 17) {
        continue;
      }
      if (isVirtualInterfaceName(entry.name ?? '')) {
        continue;
      }
      return entry.mac;
    }
  }
  return '';
}

/** Reads one string value from the Windows registry through reg.exe. */
function registryValue(path, name) {
  return new Promise((resolve) => {
    execFile('reg', ['query', path, '/v', name], { windowsHide: true }, (error, stdout) => {
      if (error) {
        resolve('');
        return;
      }
      for (const line of stdout.split('\n')) {
        const fields = line.trim().split(/\s+/);
        const index = fields.findIndex((field, i) => i > 0 && field.toUpperCase() === 'REG_SZ');
        if (index > 0 && index < fields.length - 1) {
          resolve(fields.slice(index + 1).join(' '));
          return;
        }
      }
      resolve('');
    });
  });
}

async function readFileTrimmed(path) {
  const fs = require('node:fs/promises');
  try {
    return (await fs.readFile(path, 'utf8')).trim();
  } catch {
    return '';
  }
}

async function cpuSerial() {
  const text = await readFileTrimmed('/proc/cpuinfo');
  if (text === '') {
    return '';
  }
  for (const line of text.split('\n')) {
    const [key, ...rest] = line.split(':');
    if (key.trim() === 'Serial') {
      return rest.join(':').trim();
    }
  }
  return '';
}

async function diskSerial() {
  const fs = require('node:fs/promises');
  let entries;
  try {
    entries = await fs.readdir('/sys/block');
  } catch {
    return '';
  }
  for (const name of entries) {
    if (/^(loop|ram|dm-)/.test(name)) {
      continue;
    }
    for (const candidate of [`/sys/block/${name}/device/ident`, `/sys/block/${name}/device/serial`, `/sys/block/${name}/serial`]) {
      const serial = await readFileTrimmed(candidate);
      if (serial !== '') {
        return serial;
      }
    }
  }
  return '';
}

/**
 * Collects the available hardware factors. machine_guid is required and
 * fails closed; the rest degrade gracefully.
 */
async function collect() {
  if (process.platform === 'win32') {
    const machineGuid = await registryValue('HKLM\\SOFTWARE\\Microsoft\\Cryptography', 'MachineGuid');
    if (machineGuid === '') {
      throw new Error('hwid: machine GUID unavailable');
    }
    const factors = { machine_guid: machineGuid };
    const hardwareId = await registryValue('HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation', 'ComputerHardwareId');
    if (hardwareId !== '') {
      factors.product_uuid = hardwareId.replace(/[{}]/g, '');
    }
    const boardSerial = await registryValue('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BaseBoardSerialNumber');
    if (boardSerial !== '') {
      factors.board_serial = boardSerial;
    }
    const cpuId = await registryValue('HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', 'Identifier');
    if (cpuId !== '') {
      factors.cpu_id = cpuId;
    }
    const mac = macAddress();
    if (mac !== '') {
      factors.mac = mac;
    }
    return factors;
  }

  if (process.platform === 'linux') {
    let machineId = await readFileTrimmed('/etc/machine-id');
    if (machineId === '') {
      machineId = await readFileTrimmed('/var/lib/dbus/machine-id');
    }
    if (machineId === '') {
      throw new Error('hwid: /etc/machine-id unavailable');
    }
    const factors = { machine_guid: machineId };
    const productUuid = await readFileTrimmed('/sys/class/dmi/id/product_uuid');
    if (productUuid !== '') {
      factors.product_uuid = productUuid;
    }
    const boardSerial = await readFileTrimmed('/sys/class/dmi/id/board_serial');
    if (boardSerial !== '') {
      factors.board_serial = boardSerial;
    }
    const serial = await cpuSerial();
    if (serial !== '') {
      factors.cpu_id = serial;
    }
    const disk = await diskSerial();
    if (disk !== '') {
      factors.disk_serial = disk;
    }
    const mac = macAddress();
    if (mac !== '') {
      factors.mac = mac;
    }
    return factors;
  }

  throw new Error('hwid: hardware factor collection is not supported on this platform');
}

/** Derives the HWID for this machine in one call. */
async function deviceHwid() {
  return compose(await collect());
}

module.exports = { collect, deviceHwid };
