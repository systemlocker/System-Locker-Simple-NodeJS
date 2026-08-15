'use strict';

const { SimpleError, ErrorKind } = require('./errors');

/**
 * HTTP transport mirroring the Bedrock client's shape so tests can reuse
 * fakes: postForm(url, form, headers) → { status, body, headers, error? }.
 */
class FetchHttpClient {
  constructor(options = {}) {
    this.requestTimeoutMs = options.requestTimeoutMs ?? 15_000;
    this.userAgent = options.userAgent ?? 'systemlocker-simple-node/0.1';
  }

  async postForm(url, form, headers = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    try {
      const fetchOptions = {
        method: 'POST',
        headers: { ...headers },
        signal: controller.signal,
        redirect: 'manual',
      };
      if (this.userAgent) {
        fetchOptions.headers['User-Agent'] = this.userAgent;
      }
      if (form) {
        fetchOptions.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        fetchOptions.body = new URLSearchParams(form).toString();
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
