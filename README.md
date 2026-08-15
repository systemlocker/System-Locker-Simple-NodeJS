# System Locker Simple — Node.js

Official Node.js client for the **System Locker Simple** protocol
(`POST /auth`): one request, one answer. No sessions, no heartbeats, no
signatures — the right fit when the machine running the check is one you
control. For software distributed to untrusted machines,
use a **Bedrock** client instead: it verifies an Ed25519 signature on every
response.

## Install

```sh
npm install systemlocker-simple
```

Zero runtime dependencies, Node.js 20+. Works from both ESM and CommonJS.

## Quickstart

```js
import { Client } from "systemlocker-simple";

const client = new Client({
	systemId: "abcdefghijklmnopqrst", // from the dashboard
	version: "1.0.0",
	// hwid stays "1" unless you want device locking.
});

const ok = await client.authenticateWithKey("SL-XXXX-XXXX-XXXX");
if (!ok) process.exit(1); // rejected — block the action
// …run the gated action…
```

## Operations

| Operation                          | Method                                                                    |
| ---------------------------------- | ------------------------------------------------------------------------- |
| Check a license key                | `authenticateWithKey(key)`                                                |
| Check username + password          | `authenticateWithPassword(user, pass)`                                    |
| Key expiry (`Never` or a UTC date) | `keyExpirationForKey` / `keyExpirationForPassword`                        |
| Server-side variable               | `getVariable(name, key?)`                                                 |
| Self-service HWID reset            | `resetHwidForKey` / `resetHwidForPassword` → `granted`/`denied`/`tooSoon` |

Errors throw a `SimpleError` whose `kind` separates infrastructure problems
(`Transport`, `Server`) from license denials (`Denied` with the server's raw
reason: `frozen`, `hwid banned`, `expired key`, …), Google-SSO cases
(`SSO`, with `ssoLink(error)` for the portal URL), and unrecognized reasons
(`UnknownReason`, raw string carried).

## Management API (server-side tooling)

```js
const client = new Client({ systemId, version: "1.0.0", apiKey: "…" });

const count = await client.management().redeemedUserCount();
const keys = await client.management().generateKeys(Expiry.OneMonth, 10, "june-batch");
```

Wraps `POST /api/v1`: key status/expiration, HWID resets (single/admin or
whole-system), key generation, bans, expiry adjustment. Keep the API key on
servers you control.

## Device identifiers (HWID)

The library derives a hardware ID by default. To provide your own stable ID:

```js
import { deviceHwid } from "systemlocker-simple/hwid";

config.hwid = await deviceHwid();
```

Derives a stable identifier from the machine GUID, hardware UUID, CPU id,
and MAC (Windows and Linux). A developer-supplied stable value works just as
well. Set `config.hwid = "1"` only to explicitly disable device locking.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
