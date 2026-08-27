'use strict';

const fs = require('node:fs/promises');

const { SimpleError, ErrorKind } = require('./errors');

const DOWNLOAD_PREFIX = '/a/';
const METADATA_PREFIX = '/api/v1/files/';
const METADATA_SUFFIX = '/metadata';
const REVISIONS_KEY = '__revisions';

function validReferenceId(referenceId) {
  return typeof referenceId === 'string' &&
    referenceId.length >= 4 && referenceId.length <= 128 &&
    /^[A-Za-z0-9_-]+$/.test(referenceId);
}

function percentEncode(value) {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function errorMessage(httpResponse) {
  try {
    const json = JSON.parse(httpResponse.body.toString('utf8'));
    if (typeof json.message === 'string') {
      return json.message;
    }
    if (typeof json.error === 'string') {
      return json.error;
    }
  } catch {
    // not JSON
  }
  return '';
}

function transportError(action, httpResponse) {
  if (httpResponse.error) {
    return new SimpleError(ErrorKind.Transport, `Invisible Folder ${action} failed: ${httpResponse.error}`);
  }
  return new SimpleError(ErrorKind.Transport, `Invisible Folder ${action} returned HTTP ${httpResponse.status}.`);
}

function responseOk(httpResponse) {
  return Boolean(httpResponse) && !httpResponse.error && httpResponse.status >= 200 && httpResponse.status < 300;
}

/**
 * Maps a download credential onto request headers. The credential selects the
 * file's protection mode; omit it (or pass an empty object) for a public or
 * hidden file. Fill in exactly one mode:
 *   { filePassword }          password-protected files
 *   { licenseKey }            System Locker Simple files
 *   { username, password }    System Locker Simple files (account mode)
 */
function credentialHeaders(credential = {}) {
  const modes =
    (credential.filePassword ? 1 : 0) +
    (credential.licenseKey ? 1 : 0) +
    (credential.username || credential.password ? 1 : 0);
  if (modes > 1) {
    throw new SimpleError(ErrorKind.Configuration,
      'Invisible Folder credential must use one mode: file password, license key, or username and password.');
  }
  if (Boolean(credential.username) !== Boolean(credential.password)) {
    throw new SimpleError(ErrorKind.Configuration, 'Invisible Folder username and password must be supplied together.');
  }

  const headers = {};
  if (credential.filePassword) {
    headers['X-Invisiblefolder-Password'] = String(credential.filePassword);
  }
  if (credential.licenseKey) {
    headers['X-Systemlocker-Key'] = String(credential.licenseKey);
  }
  if (credential.username) {
    headers['X-Systemlocker-Username'] = String(credential.username);
    headers['X-Systemlocker-Password'] = String(credential.password);
  }
  return headers;
}

/**
 * Downloads files from Invisible Folder using the Simple credential set.
 * The token-based Advanced permission is a Bedrock feature and is
 * intentionally absent here.
 */
class InvisibleFolder {
  /** @param {import('./client').Client} client */
  constructor(client) {
    this.client = client;
  }

  invisibleEndpoint(prefix, referenceId) {
    const base = this.client.config.invisibleFolderBaseUrl.endsWith('/')
      ? this.client.config.invisibleFolderBaseUrl.slice(0, -1)
      : this.client.config.invisibleFolderBaseUrl;
    return base + prefix + referenceId;
  }

  checkPrerequisites(referenceId) {
    if (!this.client.config.invisibleFolderBaseUrl.startsWith('https://')) {
      throw new SimpleError(ErrorKind.Configuration, 'Invisible Folder base URL must use HTTPS.');
    }
    if (!validReferenceId(referenceId)) {
      throw new SimpleError(ErrorKind.Configuration, 'Invisible Folder reference ID must be 4 through 128 URL-safe characters.');
    }
  }

  /** Downloads a file into memory (a Buffer). */
  async download(referenceId, credential = {}) {
    this.checkPrerequisites(referenceId);
    // The download route is a plain GET; credentials travel in headers
    // because GET request bodies are not supported.
    const headers = { 'X-Invisiblefolder-Download': '1', ...credentialHeaders(credential) };
    const httpResponse = await this.client.transport.get(this.invisibleEndpoint(DOWNLOAD_PREFIX, referenceId), headers);
    if (!responseOk(httpResponse)) {
      const message = errorMessage(httpResponse);
      throw message !== ''
        ? new SimpleError(ErrorKind.Transport, `Invisible Folder download failed: ${message}`)
        : transportError('download', httpResponse);
    }
    return Buffer.from(httpResponse.body);
  }

  /** Downloads a file and writes it to destination (unencrypted). */
  async downloadToFile(referenceId, destination, credential = {}) {
    if (!destination) {
      throw new SimpleError(ErrorKind.Configuration, 'Invisible Folder download destination cannot be empty.');
    }
    const bytes = await this.download(referenceId, credential);
    try {
      await fs.writeFile(destination, bytes, { mode: 0o600 });
    } catch {
      throw new SimpleError(ErrorKind.LocalFailure, 'Could not write Invisible Folder download destination.');
    }
    return destination;
  }

  /**
   * Fetches a file's description and metadata entries. keys selects specific
   * entries; omit for all. Requires config.invisibleFolderApiKey to read
   * metadata for API Available, Password Protected, and System Locker Simple
   * files.
   */
  async metadata(referenceId, keys = []) {
    this.checkPrerequisites(referenceId);

    const headers = {};
    if (this.client.config.invisibleFolderApiKey) {
      headers['X-Api-Key'] = this.client.config.invisibleFolderApiKey;
    }

    let url = this.invisibleEndpoint(METADATA_PREFIX, referenceId) + METADATA_SUFFIX;
    if (keys.length > 0) {
      url += '?keys[]=' + keys.map(percentEncode).join('&keys[]=');
    }

    const httpResponse = await this.client.transport.get(url, headers);
    if (!responseOk(httpResponse)) {
      const message = errorMessage(httpResponse);
      throw message !== ''
        ? new SimpleError(ErrorKind.Transport, `Invisible Folder metadata request failed: ${message}`)
        : transportError('metadata request', httpResponse);
    }
    return parseMetadata(httpResponse.body.toString('utf8'));
  }

  /**
   * Downloads only when the __revisions metadata differs from
   * knownRevision. With a destination the file is written to disk; without
   * one it is returned in memory.
   */
  async downloadIfNew(referenceId, knownRevision = '', destination = '', credential = {}) {
    const currentMetadata = await this.metadata(referenceId, [REVISIONS_KEY]);
    const revisionEntry = currentMetadata.values[REVISIONS_KEY];
    if (revisionEntry === undefined) {
      throw new SimpleError(ErrorKind.Server, 'Invisible Folder metadata did not contain __revisions.');
    }

    const result = { downloaded: false, revision: revisionEntry.value, metadata: currentMetadata };
    if (knownRevision !== '' && knownRevision === result.revision) {
      return result;
    }

    result.downloaded = true;
    if (destination) {
      await this.downloadToFile(referenceId, destination, credential);
      result.destination = destination;
      return result;
    }
    result.bytes = await this.download(referenceId, credential);
    return result;
  }
}

function parseMetadata(bodyText) {
  let json;
  try {
    json = JSON.parse(bodyText);
  } catch {
    throw new SimpleError(ErrorKind.Server, 'Invisible Folder metadata JSON is invalid.');
  }
  const data = json?.data;
  if (data === null || typeof data !== 'object' ||
      data.file === null || typeof data.file !== 'object' ||
      data.metadata === null || typeof data.metadata !== 'object') {
    throw new SimpleError(ErrorKind.Server, 'Invisible Folder metadata response has the wrong shape.');
  }

  const file = data.file;
  for (const name of ['id', 'reference_id', 'name', 'mime_type', 'size', 'downloads', 'uploaded_at', 'permission_type_id']) {
    if (!(name in file)) {
      throw new SimpleError(ErrorKind.Server, `Invisible Folder file field '${name}' is missing.`);
    }
  }
  for (const name of ['id', 'reference_id', 'name', 'mime_type', 'uploaded_at']) {
    if (typeof file[name] !== 'string') {
      throw new SimpleError(ErrorKind.Server, `Invisible Folder file field '${name}' has the wrong type.`);
    }
  }
  if (!Number.isSafeInteger(file.size) || file.size < 0 || !Number.isSafeInteger(file.downloads) ||
      !Number.isSafeInteger(file.permission_type_id)) {
    throw new SimpleError(ErrorKind.Server, 'Invisible Folder file numeric fields have the wrong type.');
  }

  const values = {};
  for (const [key, entry] of Object.entries(data.metadata)) {
    if (entry === null || typeof entry !== 'object' || typeof entry.value !== 'string') {
      throw new SimpleError(ErrorKind.Server, 'Invisible Folder metadata entry has the wrong type.');
    }
    const createdAt = entry.created_at ?? null;
    if (createdAt !== null && typeof createdAt !== 'string') {
      throw new SimpleError(ErrorKind.Server, 'Invisible Folder metadata creation time has the wrong type.');
    }
    values[key] = { value: entry.value, createdAt };
  }

  return {
    file: {
      id: file.id,
      referenceId: file.reference_id,
      name: file.name,
      mimeType: file.mime_type,
      size: file.size,
      downloads: file.downloads,
      uploadedAt: file.uploaded_at,
      permissionTypeId: file.permission_type_id,
    },
    values,
  };
}

module.exports = { InvisibleFolder, validReferenceId, credentialHeaders };
