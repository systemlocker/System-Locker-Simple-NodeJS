'use strict';

/**
 * HTTP transport mirroring the Bedrock client's shape so tests can reuse
 * fakes: postForm(url, form, headers) and get(url, headers) →
 * { status, body, headers, error? }.
 */
class FetchHttpClient {
  /**
   * @param {{ requestTimeoutMs?: number, userAgent?: string }} options
   */
  constructor(options = {}) {
    this.requestTimeoutMs = options.requestTimeoutMs ?? 15_000;
    this.userAgent = options.userAgent ?? 'systemlocker-simple-node/2.0.0';
  }

  async _execute(method, url, { form = null, json = undefined, headers = {} } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    try {
      const fetchOptions = { method, headers: { ...headers }, signal: controller.signal, redirect: 'manual' };
      if (this.userAgent) {
        fetchOptions.headers['User-Agent'] = this.userAgent;
      }
      if (form) {
        fetchOptions.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        fetchOptions.body = new URLSearchParams(form).toString();
      }
      if (json !== undefined) {
        fetchOptions.headers['Content-Type'] = 'application/json';
        fetchOptions.body = JSON.stringify(json);
      }
      const response = await fetch(url, fetchOptions);
      const body = await readBoundedBody(response, controller);
      const responseHeaders = {};
      for (const [name, value] of response.headers) {
        responseHeaders[name.toLowerCase()] = value;
      }
      return { status: response.status, body, headers: responseHeaders };
    } catch (error) {
      return { status: 0, body: Buffer.alloc(0), headers: {}, error: String(error?.cause ?? error?.message ?? error) };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * @param {string} url
   * @param {Record<string, string|string[]>} form
   * @param {Record<string, string>} [headers]
   */
  postForm(url, form, headers = {}) {
    return this._execute('POST', url, { form, headers });
  }

  /**
   * Sends a Management API request. `json`, when not undefined, is
   * serialized as the body with Content-Type: application/json.
   * Authentication keeps using postForm.
   * @param {string} method
   * @param {string} url
   * @param {unknown} json
   * @param {Record<string, string>} [headers]
   */
  requestJson(method, url, json, headers = {}) {
    return this._execute(method, url, { json, headers });
  }

  /**
   * @param {string} url
   * @param {Record<string, string>} [headers]
   */
  get(url, headers = {}) {
    return this._execute('GET', url, { headers });
  }
}

const MAX_RESPONSE_BYTES = 1024 * 1024;

async function readBoundedBody(response, controller) {
  const length = Number(response.headers.get('content-length'));
  if (Number.isFinite(length) && length > MAX_RESPONSE_BYTES) throw new Error('response body exceeds 1 MiB limit');
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) { controller.abort(); throw new Error('response body exceeds 1 MiB limit'); }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks, size);
}

module.exports = { FetchHttpClient };
