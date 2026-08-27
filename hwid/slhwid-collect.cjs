'use strict';

/**
 * §4A.1 factor collection per platform. The legacy slots reuse the shared
 * hwid collector on Windows and Linux; the extended slots come from the
 * registry, environment, os, and best-effort subprocess queries. Every
 * source degrades gracefully — a missing source just leaves the slot
 * absent, which the threshold scheme absorbs.
 */

const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');

const DISPLAY_CLASS_GUID = '{4d36e968-e325-11ce-bfc1-08002be10318}';

function run(command, args, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const child = execFile(
      command,
      args,
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 1024 },
      (error, stdout) => {
        // execFile only terminates its direct child. Providers may have their
        // own children, so close the complete Windows process tree on timeout.
        if (error?.killed && process.platform === 'win32') {
          execFile('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, timeout: 2000 });
        }
        resolve({ error, stdout: stdout ?? '' });
      },
    );
  });
}

function firstMatch(pattern, text) {
  const match = new RegExp(pattern).exec(text);
  return match ? match[1] : '';
}

function allMatches(pattern, text, flags = 'g') {
  return [...text.matchAll(new RegExp(pattern, flags))].map((m) => m[1]);
}

function multiInstance(values) {
  return values.filter((v) => v).sort().join('|');
}

function put(factors, name, value) {
  if (value) {
    factors[name] = value;
  }
}

function namedLines(text) {
  const factors = {};
  for (const line of text.split('\n')) {
    const separator = line.indexOf('=');
    if (separator > 0 && separator + 1 < line.length) {
      factors[line.slice(0, separator)] = line.slice(separator + 1).trim();
    }
  }
  return factors;
}

async function regTypedValue(regPath, name) {
  const { error, stdout } = await run('reg', ['query', regPath, '/v', name, '/reg:64']);
  if (error) {
    return '';
  }
  for (const line of stdout.split('\n')) {
    const fields = line.trim().split(/\s+/);
    for (let i = 1; i + 1 < fields.length; i++) {
      if (fields[i - 1].toLowerCase() !== name.toLowerCase()) {
        continue;
      }
      if (['REG_SZ', 'REG_EXPAND_SZ', 'REG_DWORD', 'REG_QWORD', 'REG_MULTI_SZ'].includes(fields[i])) {
        return fields.slice(i + 1).join(' ');
      }
    }
  }
  return '';
}

async function regValuesRecursive(regPath, name) {
  const { error, stdout } = await run('reg', ['query', regPath, '/s', '/v', name, '/reg:64'], 10000);
  if (error) {
    return [];
  }
  const values = [];
  for (const line of stdout.split('\n')) {
    const fields = line.trim().split(/\s+/);
    for (let i = 1; i + 1 < fields.length; i++) {
      if (fields[i - 1].toLowerCase() !== name.toLowerCase()) {
        continue;
      }
      if (['REG_SZ', 'REG_EXPAND_SZ', 'REG_BINARY', 'REG_MULTI_SZ'].includes(fields[i])) {
        values.push(fields.slice(i + 1).join(''));
      }
    }
  }
  return values;
}

function macAddress() {
  const interfaces = os.networkInterfaces();
  const virtualPrefixes = ['vethernet', 'vmware', 'virtual', 'loopback', 'tap', 'tun', 'zerotier', 'wsl', 'docker', 'bluetooth', 'tailscale', 'vpn'];
  for (const [name, addresses] of Object.entries(interfaces)) {
    if (virtualPrefixes.some((prefix) => name.toLowerCase().startsWith(prefix))) {
      continue;
    }
    for (const address of addresses ?? []) {
      if (address.mac && address.mac !== '00:00:00:00:00:00' && !address.internal) {
        return address.mac;
      }
    }
  }
  return '';
}

async function volumeSerial() {
  const drive = process.env.SystemDrive || 'C:';
  const { stdout } = await run('cmd', ['/c', 'vol', drive]);
  const matches = stdout.match(/([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})/g);
  return matches ? matches[matches.length - 1] : '';
}

async function collectWindows() {
  const factors = {};
  try {
    const legacy = await require('./collect.cjs').collect();
    Object.assign(factors, legacy);
  } catch {
    /* the legacy collector fails closed on machine_guid; degrade */
  }

  if (process.env.COMPUTERNAME) {
    factors.computer_name = process.env.COMPUTERNAME;
  }

  const firmwareParts = [];
  const systemBios = await regTypedValue('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'SystemBiosVersion');
  if (systemBios) {
    firmwareParts.push(systemBios);
  }
  const biosVersion = await regTypedValue('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BIOSVersion');
  if (biosVersion) {
    firmwareParts.push(biosVersion);
  }
  const firmware = multiInstance(firmwareParts);
  if (firmware) {
    factors.firmware = firmware;
  }

  const build = await regTypedValue('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'CurrentBuildNumber');
  const ubrHex = await regTypedValue('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'UBR');
  if (build && ubrHex) {
    const ubr = parseInt(ubrHex.replace(/^0x/i, ''), 16);
    if (Number.isInteger(ubr)) {
      factors.os_build = `${build}-${ubr}`;
    }
  }

  const descs = await regValuesRecursive(`HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\${DISPLAY_CLASS_GUID}`, 'DriverDesc');
  const gpu = multiInstance(descs);
  if (gpu) {
    factors.gpu_id = gpu;
  }

  const edidBlobs = await regValuesRecursive('HKLM\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY', 'EDID');
  const edid = multiInstance(edidBlobs.map((b) => b.toLowerCase()));
  if (edid) {
    factors.monitor_edid = edid;
  }

  const volume = await volumeSerial();
  if (volume) {
    factors.volume_id = volume;
  }

  const mac = macAddress();
  if (mac) {
    factors.mac = mac;
  }

  // CIM-backed v2 signals deliberately supplement rather than replace the
  // legacy collection above: v1 helpers still recover from those raw slots.
  const script = [
    "$ErrorActionPreference='SilentlyContinue'",
    "function Emit($n,$v){$c=@($v|Where-Object {$_ -ne $null -and ([string]$_).Trim().Length -gt 0}|ForEach-Object {([string]$_).Trim()}|Sort-Object);if($c.Count -gt 0){Write-Output ($n+'='+($c -join '|'))}}",
    "$p=Get-CimInstance Win32_ComputerSystemProduct;Emit 'system_uuid' $p.UUID;Emit 'system_serial' $p.IdentifyingNumber",
    "Emit 'chassis_serial' (Get-CimInstance Win32_SystemEnclosure).SerialNumber",
    "Emit 'disk_serial' (Get-CimInstance Win32_DiskDrive).SerialNumber",
    "Emit 'memory_modules' (Get-CimInstance Win32_PhysicalMemory).SerialNumber",
    "Emit 'nic_identity' (Get-CimInstance Win32_NetworkAdapter|Where-Object {$_.PhysicalAdapter}).PermanentAddress",
    "Emit 'battery_serial' (Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData).SerialNumber",
    "$ek=Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256;if($ek.IsPresent){Emit 'tpm_ek' $ek.PublicKeyHash}",
  ].join(';');
  const v2 = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], 12000);
  for (const [name, value] of Object.entries(namedLines(v2.stdout))) {
    // CIM is optional enrichment; it must not replace a native/base slot.
    factors[name] ??= value;
  }

  return factors;
}

async function collectDarwin() {
  const factors = {};

  const expert = await run('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice']);
  const uuid = firstMatch('"IOPlatformUUID"\\s*=\\s*"([^"]+)"', expert.stdout);
  if (uuid) {
    factors.machine_guid = uuid;
  }
  const serial = firstMatch('"IOPlatformSerialNumber"\\s*=\\s*"([^"]+)"', expert.stdout);
  if (serial) {
    factors.board_serial = serial;
    factors.system_serial = serial;
  }

  let brand = (await run('sysctl', ['-n', 'machdep.cpu.brand_string'])).stdout.trim();
  if (!brand) {
    brand = (await run('sysctl', ['-n', 'hw.model'])).stdout.trim();
  }
  const cores = (await run('sysctl', ['-n', 'hw.physicalcpu'])).stdout.trim();
  if (brand && cores) {
    factors.cpu_id = `${brand}-${cores}`;
  }

  const ifconfig = await run('ifconfig', ['en0']);
  const mac = firstMatch('ether\\s+([0-9a-fA-F:]{17})', ifconfig.stdout);
  if (mac) {
    factors.mac = mac;
  }

  const hardwarePorts = await run('networksetup', ['-listallhardwareports']);
  put(factors, 'nic_identity', multiInstance(allMatches('Ethernet Address:\\s*([0-9a-fA-F:]{17})', hardwarePorts.stdout)));

  const memsize = (await run('sysctl', ['-n', 'hw.memsize'])).stdout.trim();
  if (memsize) {
    factors.ram_total = memsize;
  }

  const diskutil = await run('diskutil', ['info', '-plist', '/']);
  const volumeUUID = firstMatch('<key>VolumeUUID</key>\\s*<string>([^<]+)</string>', diskutil.stdout);
  if (volumeUUID) {
    factors.volume_id = volumeUUID;
  }

  const computerName = (await run('scutil', ['--get', 'ComputerName'])).stdout.trim()
    || (await run('scutil', ['--get', 'LocalHostName'])).stdout.trim();
  if (computerName) {
    factors.computer_name = computerName;
  }

  const hardware = await run('system_profiler', ['SPHardwareDataType', '-json'], 5000);
  const bootrom = firstMatch('"spmachine_bootrom_version"\\s*:\\s*"([^"]+)"', hardware.stdout);
  if (bootrom) {
    factors.firmware = bootrom;
  }

  const memory = await run('system_profiler', ['SPMemoryDataType', '-json'], 5000);
  put(factors, 'memory_modules', multiInstance(allMatches('"[^\"]*serial[^\"]*"\\s*:\\s*"([^\"]+)"', memory.stdout)));

  const battery = await run('ioreg', ['-r', '-c', 'AppleSmartBattery']);
  put(
    factors,
    'battery_serial',
    firstMatch('"BatterySerialNumber"\\s*=\\s*"([^\"]+)"', battery.stdout)
      || firstMatch('"Serial"\\s*=\\s*"?([^"\\n]+)"?', battery.stdout),
  );

  const displays = await run('system_profiler', ['SPDisplaysDataType', '-json'], 5000);
  const models = allMatches('"spdisplays_model"\\s*:\\s*"([^"]+)"', displays.stdout);
  if (models.length > 0) {
    factors.gpu_id = [...models].sort().join('|');
  }

  const storage = await run('system_profiler', ['SPStorageDataType', '-json'], 5000);
  const diskSerials = allMatches('"[a-z_]*serial[a-z_]*"\\s*:\\s*"([^"]+)"', storage.stdout);
  if (diskSerials.length > 0) {
    factors.disk_serial = [...diskSerials].sort().join('|');
  }

  const displayIO = await run('ioreg', ['-r', '-c', 'IODisplayConnect']);
  const blobs = allMatches('"IODisplayEDID"\\s*=\\s*<?([0-9a-fA-F]+)>?', displayIO.stdout);
  if (blobs.length > 0) {
    factors.monitor_edid = blobs.map((b) => b.toLowerCase()).sort().join('|');
  }

  const version = (await run('sw_vers', ['-productVersion'])).stdout.trim();
  const build = (await run('sw_vers', ['-buildVersion'])).stdout.trim();
  if (version && build) {
    factors.os_build = `${version}-${build}`;
  }

  if (Object.keys(factors).length === 0) {
    throw new Error('slhwid: no hardware factors available on this machine');
  }
  return factors;
}

async function collectLinux() {
  const factors = {};
  try {
    const legacy = await require('./collect.cjs').collect();
    Object.assign(factors, legacy);
  } catch {
    /* degrade */
  }

  const hostname = os.hostname();
  if (hostname) {
    factors.computer_name = hostname;
  }

  try {
    const meminfo = fs.readFileSync('/proc/meminfo', 'ascii');
    const match = /MemTotal:\s+(\d+)\s+kB/.exec(meminfo);
    if (match) {
      factors.ram_total = String(Number(match[1]) * 1024);
    }
  } catch { /* absent */ }

  const findmnt = await run('findmnt', ['-no', 'UUID', '/']);
  const volumeUUID = findmnt.stdout.trim();
  if (volumeUUID) {
    factors.volume_id = volumeUUID;
  }

  for (const [slot, file] of [['firmware', '/sys/class/dmi/id/bios_version']]) {
    try {
      const value = fs.readFileSync(file, 'ascii').trim();
      if (value) {
        factors[slot] = value;
      }
    } catch { /* absent */ }
  }

  const extraDmi = [
    ['system_uuid', '/sys/class/dmi/id/product_uuid'],
    ['system_serial', '/sys/class/dmi/id/product_serial'],
    ['chassis_serial', '/sys/class/dmi/id/chassis_serial'],
  ];
  for (const [slot, file] of extraDmi) {
    try {
      put(factors, slot, fs.readFileSync(file, 'ascii').trim());
    } catch { /* absent */ }
  }

  const memory = await run('dmidecode', ['--type', 'memory'], 5000);
  put(factors, 'memory_modules', multiInstance(allMatches('^\\s*Serial Number:\\s*(\\S.*)$', memory.stdout, 'gm')));

  const nicIds = [];
  try {
    for (const name of fs.readdirSync('/sys/class/net').sort()) {
      const device = `/sys/class/net/${name}/device`;
      const permanent = `${device}/perm_address`;
      if (!fs.existsSync(device) || !fs.existsSync(permanent)) {
        continue;
      }
      const value = fs.readFileSync(permanent, 'ascii').trim();
      if (value && value !== '00:00:00:00:00:00') {
        nicIds.push(value);
      }
    }
  } catch { /* absent */ }
  put(factors, 'nic_identity', multiInstance(nicIds));

  const batteries = [];
  try {
    for (const name of fs.readdirSync('/sys/class/power_supply').filter((entry) => entry.startsWith('BAT')).sort()) {
      const serial = `/sys/class/power_supply/${name}/serial_number`;
      if (fs.existsSync(serial)) {
        const value = fs.readFileSync(serial, 'ascii').trim();
        if (value) batteries.push(value);
      }
    }
  } catch { /* absent */ }
  put(factors, 'battery_serial', multiInstance(batteries));

  for (const file of ['/sys/class/tpm/tpm0/device/ek_pub', '/sys/class/tpm/tpm0/ek_pub']) {
    try {
      const value = fs.readFileSync(file);
      if (value.length > 0) {
        factors.tpm_ek = require('crypto').createHash('sha256').update(value).digest('hex');
        break;
      }
    } catch { /* absent */ }
  }

  try {
    const osRelease = fs.readFileSync('/etc/os-release', 'utf8');
    const match = /^PRETTY_NAME="?([^"\n]+)"?/m.exec(osRelease);
    if (match) {
      factors.os_build = match[1];
    }
  } catch { /* absent */ }

  let edids = [];
  try {
    edids = fs.readdirSync('/sys/class/drm')
      .filter((name) => /^card\d+-\d+$/.test(name))
      .map((name) => `/sys/class/drm/${name}/edid`)
      .filter((file) => fs.existsSync(file));
  } catch { /* absent */ }
  const blobs = [];
  for (const file of edids) {
    try {
      const data = fs.readFileSync(file);
      if (data.length > 0) {
        blobs.push(data.toString('hex'));
      }
    } catch { /* absent */ }
  }
  if (blobs.length > 0) {
    factors.monitor_edid = blobs.sort().join('|');
  }

  const gpus = [];
  let pciDevices = [];
  try {
    pciDevices = fs.readdirSync('/sys/bus/pci/devices');
  } catch { /* absent */ }
  for (const device of pciDevices.sort()) {
    try {
      const klass = fs.readFileSync(`/sys/bus/pci/devices/${device}/class`, 'ascii').trim();
      if (!klass.startsWith('0x03')) {
        continue;
      }
      const vendor = fs.readFileSync(`/sys/bus/pci/devices/${device}/vendor`, 'ascii').trim();
      const id = fs.readFileSync(`/sys/bus/pci/devices/${device}/device`, 'ascii').trim();
      gpus.push(`${vendor}:${id}`);
    } catch { /* absent */ }
  }
  if (gpus.length > 0) {
    factors.gpu_id = gpus.sort().join('|');
  }

  return factors;
}

async function collect() {
  if (process.platform === 'win32') {
    return collectWindows();
  }
  if (process.platform === 'darwin') {
    return collectDarwin();
  }
  if (process.platform === 'linux') {
    return collectLinux();
  }
  throw new Error('slhwid: secret-sharing HWID is not supported on this platform');
}

module.exports = { collect };
