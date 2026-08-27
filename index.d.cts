declare namespace Simple {
  type ErrorKindValue =
    | 'Configuration'
    | 'Transport'
    | 'Server'
    | 'Denied'
    | 'SSO'
    | 'LocalFailure'
    | 'UnknownReason';

  class SimpleError extends Error {
    readonly kind: ErrorKindValue;
    readonly reason: string;
  }

  interface HttpResponse {
    status: number;
    body: Buffer | string;
    headers: Record<string, string>;
    error?: string;
  }

  interface HTTPClient {
    postForm(url: string, form: Record<string, string | string[]>, headers?: Record<string, string>): Promise<HttpResponse>;
    get(url: string, headers?: Record<string, string>): Promise<HttpResponse>;
  }

  interface SimpleConfig {
    systemId: string;
    version: string;
    hwid?: string;
    hwidMode?: 'legacy' | 'sl-hwid';
    slHwidStore?: string | null;
    slHwidExtraMandatory?: string[] | null;
    requestTimeoutMs?: number;
    baseUrl?: string;
    invisibleFolderBaseUrl?: string;
    userAgent?: string;
    programDigest?: string | null;
    invisibleFolderApiKey?: string | null;
    apiKey?: string | null;
  }

  interface Expiration {
    permanent: boolean;
    expiresAt: string;
  }

  interface VariableValue {
    found: boolean;
    value: string | null;
  }

  type ResetOutcome = 'granted' | 'denied' | 'tooSoon';

  class Client {
    constructor(config?: Partial<SimpleConfig>, options?: { http?: HTTPClient });
    authenticateWithKey(licenseKey: string): Promise<boolean>;
    authenticateWithPassword(username: string, password: string): Promise<boolean>;
    keyExpirationForKey(licenseKey: string): Promise<Expiration>;
    keyExpirationForPassword(username: string, password: string): Promise<Expiration>;
    getVariable(name: string, licenseKey?: string): Promise<VariableValue>;
    resetHwidForKey(licenseKey: string): Promise<ResetOutcome>;
    resetHwidForPassword(username: string, password: string): Promise<ResetOutcome>;
    management(): Management;
    invisibleFolder(): InvisibleFolder;
  }

  /** Selects how an Invisible Folder download authorizes against the file's
   * protection; the empty object downloads a public or hidden file. Fill in
   * exactly one mode. */
  interface InvisibleFolderCredential {
    filePassword?: string;
    licenseKey?: string;
    username?: string;
    password?: string;
  }

  interface InvisibleFolderMetadataValue {
    value: string;
    createdAt: string | null;
  }

  interface InvisibleFolderMetadata {
    file: {
      id: string;
      referenceId: string;
      name: string;
      mimeType: string;
      size: number;
      downloads: number;
      uploadedAt: string;
      permissionTypeId: number;
    };
    values: Record<string, InvisibleFolderMetadataValue>;
  }

  interface DownloadIfNewResult {
    downloaded: boolean;
    revision: string;
    metadata: InvisibleFolderMetadata;
    bytes?: Buffer;
    destination?: string;
  }

  class InvisibleFolder {
    download(referenceId: string, credential?: InvisibleFolderCredential): Promise<Buffer>;
    downloadToFile(referenceId: string, destination: string, credential?: InvisibleFolderCredential): Promise<string>;
    metadata(referenceId: string, keys?: string[]): Promise<InvisibleFolderMetadata>;
    downloadIfNew(referenceId: string, knownRevision?: string, destination?: string, credential?: InvisibleFolderCredential): Promise<DownloadIfNewResult>;
  }

  type KeyExpiry = '0' | '1' | '2' | '3' | '4' | '5';

  class Management {
    redeemedUserCount(): Promise<number>;
    keyStatus(license: string): Promise<string>;
    keyExpiration(license: string): Promise<Expiration>;
    resetHwid(license: string, asAdmin?: boolean): Promise<string>;
    resetAllHwids(): Promise<string>;
    generateKeys(expiry: KeyExpiry, count: number, note?: string): Promise<string>;
    banKey(license: string): Promise<string>;
    adjustExpiry(license: string, newExpiry: string, tz: string): Promise<string>;
  }

  function defaultConfig(): Required<SimpleConfig>;
  function ssoLink(error: unknown): string;

  const Expiry: {
    readonly Permanent: '0';
    readonly OneDay: '1';
    readonly OneWeek: '2';
    readonly OneMonth: '3';
    readonly ThreeMonths: '4';
    readonly OneYear: '5';
  };

  const RESET_GRANTED: 'granted';
  const RESET_DENIED: 'denied';
  const RESET_TOO_SOON: 'tooSoon';
}

export = Simple;
