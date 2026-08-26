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
(`SSO`, with `ssoLink(error)` for the portal URL), `LocalFailure` when an
opt-in SL-HWID device identity cannot be produced (see below), and
unrecognized reasons (`UnknownReason`, raw string carried).

## Management API (server-side tooling)

```js
const client = new Client({ systemId, version: "1.0.0", apiKey: "…" });

const count = await client.management().redeemedUserCount();
const keys = await client.management().generateKeys(Expiry.OneMonth, 10, "june-batch");
```

Wraps `POST /api/v1`: key status/expiration, HWID resets (single/admin or
whole-system), key generation, bans, expiry adjustment. Keep the API key on
servers you control.

## Google SSO (account authentication)

Accounts created through Google sign-in have no local password on the
server. A `username`/`password` check for such an account fails with an
`sso`, `ssoexp`, or `ssowrong` reason that embeds the portal URL where the
user completes Google sign-in and receives a system-specific password
(valid 180 days) to use as their account password. There is no callback;
the user transcribes the generated password into your login form and you
simply retry.

Deliver the portal link to your user through your own channel (API response, email, chat).

```js
try {
	await client.authenticateWithPassword(username, password);
} catch (error) {
	if (error instanceof simple.SimpleError && error.kind === simple.ErrorKind.SSO) {
		// sso / ssoexp / ssowrong — the portal URL is embedded in the error.
		const portal = simple.ssoLink(error);
		sendToUser(user, portal); // your channel: API response, email, chat…
		return;
	}
	throw error; // any other denial
}
```

`simple.googleSsoUrl(systemId)` (or `client.googleSsoUrl()`) builds the
same portal URL before any denial, if you already know the account signs in
through Google.

## Device identifiers (HWID)

The default derivation is a plain hardware hash:

```js
import { deviceHwid } from "systemlocker-simple/hwid";

config.hwid = await deviceHwid();
```

Derives a stable identifier from the machine GUID, hardware UUID, CPU id,
and MAC (Windows and Linux). It stays available, but it is the weaker
option: the hash over-fits a handful of hardware values, so swapping a disk
or NIC — or cloning the machine into a VM — changes the HWID and forces your
user through a device reset. A developer-supplied stable value works just as
well. Set `config.hwid = "1"` only to explicitly disable device locking.

### Fault-tolerant HWID (SL-HWID), opt-in

```js
const config = defaultConfig();
config.hwidMode = "sl-hwid"; // default is "legacy"
```

SL-HWID derives the HWID from a random key locked behind threshold secret
sharing instead of hashing hardware directly. It is fault tolerant and cross
platform (Windows, macOS, Linux), combines **14 hardware factors**, and any
two of them can fail or change without changing the HWID; drifted factors
are quietly re-absorbed after each successful authentication. The module's
own persisted value is hard-locked, so copied state cannot stand in for
changed hardware.

Things to know before enabling it:

- **The HWID changes.** SL-HWID produces a new opaque identifier, so a
  deployment switching from the legacy hash (or a custom value) must reset
  its claimed HWIDs once, at rollout — per key, self-service, or
  system-wide through the management API — or users will hit `hwid`
  mismatches.
- **Storage is shared.** The enrollment lives in one per-machine location
  (the registry on Windows, an application-support directory elsewhere),
  shared by every System Locker client on the device. Configure
  `slHwidStore` only when you deliberately need separate device state.
- **Re-activation exists.** If hardware drifts past the recovery threshold,
  requests fail with a `LOCAL_FAILURE` error and the user needs a reset.

SL-HWID is the right choice for a **launcher**: a Simple-based launcher that
opens a Bedrock-protected program reports exactly the HWID the Bedrock
client reports, because both share the same per-machine enrollment. The key
the user already activated in the launcher works for the protected program
too — one device, one HWID, no `hwid` mismatch between the two.

SL-HWID changes the device identifier only. It does not change what the
Simple protocol guarantees: responses are still unsigned, so only use this
client on machines you control.

An explicit `hwid` value (including `"1"`) always wins over both modes.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
