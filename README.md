# SikkerKey Node.js SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@sikkerkey/sdk)](https://www.npmjs.com/package/@sikkerkey/sdk)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)

Use the official SikkerKey Node.js SDK to give a JavaScript or TypeScript application read access to the secrets its machine is authorized to use.

The SDK can:

- Read standard and structured secrets asynchronously.
- List the secrets available to a machine.
- Export accessible secrets as application-friendly key/value pairs.
- Monitor selected secrets for changes.
- Use persistent machine identities or memory-only ephemeral identities.
- Keep an optional encrypted fallback cache for temporary service or network outages.

After the client is initialized, every secret request is authenticated with the machine's Ed25519 identity. The package supports Node.js 18 or newer, includes TypeScript declarations, and uses only Node.js built-in modules.

## Install the SDK

```bash
npm install @sikkerkey/sdk
```

The version represented by this source is `1.4.1`.

## Read your first secret

```typescript
import { SikkerKey } from '@sikkerkey/sdk'

const sikkerKey = SikkerKey.create('vault_abc123')
const apiKey = await sikkerKey.getSecret('sk_stripe_key')
```

The SDK loads the machine identity from:

```text
~/.sikkerkey/vaults/vault_abc123/identity.json
```

It signs the request with the machine's Ed25519 private key and returns the secret value as a `string`. Your application's access remains limited by the machine's configured access.

## Create a client

Client creation from disk is synchronous:

```typescript
// Select a registered vault.
const byVault = SikkerKey.create('vault_abc123')

// Load a specific identity file.
const byPath = SikkerKey.create(
  '/etc/sikkerkey/vaults/vault_abc123/identity.json',
)

// Use SIKKERKEY_IDENTITY or auto-select the only registered vault.
const automatically = SikkerKey.create()
```

When no argument is supplied, the SDK checks `SIKKERKEY_IDENTITY` first. If that variable is not set, it uses the only registered vault under `~/.sikkerkey/vaults/`.

If more than one vault is registered, select one explicitly. Missing identities, unreadable keys, invalid identity files, and ambiguous vault selection produce a `ConfigurationError`.

The `vault_` prefix is added when a vault ID is supplied without it.

### Use a different identity directory

```bash
export SIKKERKEY_HOME=/var/lib/sikkerkey
```

The SDK will look under:

```text
/var/lib/sikkerkey/vaults/<vault-id>/identity.json
```

## Use an ephemeral identity

Use the memory-only bootstrap flow for short-lived or read-only environments:

```typescript
import { SikkerKey } from '@sikkerkey/sdk'

const sikkerKey = await SikkerKey.bootstrap(
  process.env.SIKKERKEY_VAULT_ID!,
  process.env.SIKKERKEY_ENROLLMENT_TOKEN!,
).inMemory()

const databaseUrl =
  await sikkerKey.getSecret('sk_db_prod')
```

`SikkerKey.bootstrap` creates a bootstrap builder. Calling `inMemory`:

1. Generates an Ed25519 key pair in memory.
2. Uses the enrollment token to register an ephemeral machine.
3. Keeps the private key inside the running Node.js process.
4. Returns an ordinary `SikkerKey` client.

Nothing is written to disk. Enrollment errors are returned by `inMemory`, and the private key disappears when the process exits.

The enrollment token registers the machine; it does not read secrets itself. The resulting machine remains subject to the token's permitted scope, use limit, hostname rules, and machine lifetime. Reads fail with `AuthenticationError` after the machine expires.

### Set the machine hostname and name

```typescript
const sikkerKey = await SikkerKey.bootstrap(
  vaultId,
  enrollmentToken,
  {
    hostname: 'worker-1',
    name: 'invoice-runner',
  },
).inMemory()
```

`hostname` defaults to the `HOSTNAME` environment variable and then to `serverless`. A name pattern configured on the enrollment token takes precedence over `name`.

For reliable ephemeral deployments:

- Set a machine lifetime long enough for the workload to finish.
- Allow enough token uses for expected cold starts and concurrency.
- Use a unique name pattern such as `worker-{uuid8}`.
- Ensure the vault's IP allowlist permits the workload's outbound address when an allowlist is enabled.

Each active ephemeral machine uses a machine slot until it expires.

The SDK requires a Node.js runtime with outbound HTTPS. Browser and edge runtimes are not supported because the SDK relies on Node's `crypto`, `fs`, `http`, and `https` modules.

## Read secrets

### Standard secrets

```typescript
const apiKey =
  await sikkerKey.getSecret('sk_stripe_prod')
```

### Structured secrets

```typescript
const database =
  await sikkerKey.getFields('sk_db_prod')

const host = database.host
const username = database.username
const password = database.password
```

`getFields` expects a JSON object and converts each property to a string. It throws `SecretStructureError` for another structure.

Use `getField` when the application needs one field:

```typescript
const password = await sikkerKey.getField(
  'sk_db_prod',
  'password',
)
```

A missing field produces `FieldNotFoundError` with the available field names.

## Discover accessible secrets

```typescript
const secrets = await sikkerKey.listSecrets()

for (const secret of secrets) {
  console.log(`${secret.id}: ${secret.name}`)
}
```

Limit the result to one project:

```typescript
const productionSecrets =
  await sikkerKey.listSecretsByProject('proj_production')
```

Each `SecretListItem` contains:

| Property | Type | Meaning |
|---|---|---|
| `id` | `string` | Secret ID used by read methods |
| `name` | `string` | Display name |
| `fieldNames` | `string \| null` | Optional structured-field metadata |
| `projectId` | `string \| null` | Owning project, when present |

Listing returns metadata, not secret values.

## Export secrets for application configuration

```typescript
const configuration = await sikkerKey.export()
```

Limit the export to a project:

```typescript
const productionConfiguration =
  await sikkerKey.export('proj_production')
```

The returned `Record<string, string>` uses uppercase environment-style names. Structured secrets are expanded into one entry per field:

```text
API_KEY
DB_CREDENTIALS_HOST
DB_CREDENTIALS_USERNAME
DB_CREDENTIALS_PASSWORD
```

## Continue reads during temporary outages

The fallback cache is disabled by default:

```typescript
const sikkerKey = SikkerKey
  .create('vault_abc123')
  .enableCache()
```

After it is enabled, successful `getSecret` reads are stored under:

```text
~/.sikkerkey/vaults/<vault-id>/cache/
```

`getFields` and `getField` use `getSecret`, so their successful reads are cached too. Cache writes are best-effort and cannot turn a successful live read into a failure.

The SDK can return a cached value after a network failure, request timeout, or HTTP `502`, `503`, `504`, `520` through `527`, or `530`.

Authentication failures, revoked access, missing secrets, rate limits, and other authoritative responses are never replaced by cached values.

Entries use AES-256-GCM with a key derived from the machine's Ed25519 identity and vault ID. Tampered entries and entries belonging to another identity are rejected. The `.skc` format is compatible with other SikkerKey SDKs and the SikkerKey CLI.

### Limit cache age and observe fallback use

```typescript
const sikkerKey = SikkerKey
  .create('vault_abc123')
  .enableCache({
    maxAge: 3600,
    onFallback: (secretId, cachedAt) => {
      console.log(
        `Using cached value for ${secretId} from epoch ${cachedAt}`,
      )
    },
  })
```

`maxAge` is measured in seconds. Omitting it means no automatic expiry. The callback is optional; fallback is otherwise silent.

The cache is intended for a host with a persistent, protected identity directory, not a memory-only identity that disappears with the process.

## Monitor secrets for changes

```typescript
sikkerKey.watch('sk_db_credentials', (event) => {
  switch (event.status) {
    case 'changed':
      console.log(`${event.secretId} changed`)
      console.log(event.fields)
      break

    case 'deleted':
      console.log(`${event.secretId} was deleted`)
      break

    case 'access_denied':
      console.log(`Access to ${event.secretId} was removed`)
      break

    case 'error':
      console.log(`Could not retrieve the update: ${event.error}`)
      break
  }
})
```

The SDK polls through an unreferenced Node.js interval every 15 seconds by default. The timer does not keep an otherwise idle process alive.

For changed secrets, `value` contains the complete new value and `fields` contains parsed structured fields when available. Deleted and inaccessible secrets are automatically removed from the watch list. A failed poll is skipped and tried again during a later interval; it does not emit an event by itself.

Callbacks run from the asynchronous polling flow. Keep them short or hand slow work to your application's queue.

### Change or stop polling

```typescript
sikkerKey.setPollInterval(30) // seconds; minimum 10
sikkerKey.unwatch('sk_db_credentials')
sikkerKey.close()
```

Changing the interval restarts the timer. `close` stops polling and clears all callbacks, while leaving the client available for later reads.

## Work with more than one vault

```typescript
const production =
  SikkerKey.create('vault_production')
const staging =
  SikkerKey.create('vault_staging')

const productionKey =
  await production.getSecret('sk_api_key')
const stagingKey =
  await staging.getSecret('sk_api_key')
```

List locally registered vault IDs:

```typescript
const vaultIds = SikkerKey.listVaults()
```

## Inspect the active machine

```typescript
console.log(sikkerKey.machineId)
console.log(sikkerKey.machineName)
console.log(sikkerKey.vaultId)
console.log(sikkerKey.apiUrl)
```

| Property | Meaning |
|---|---|
| `machineId` | Machine UUID assigned by SikkerKey |
| `machineName` | Machine name assigned during provisioning or enrollment |
| `vaultId` | Vault associated with the identity |
| `apiUrl` | Service endpoint stored in the identity |

## Handle errors

```typescript
import {
  AccessDeniedError,
  ApiError,
  AuthenticationError,
  ConfigurationError,
  NotFoundError,
  RateLimitedError,
} from '@sikkerkey/sdk'

try {
  const value =
    await sikkerKey.getSecret('sk_example')
} catch (error) {
  if (error instanceof NotFoundError) {
    console.error('Secret not found')
  } else if (error instanceof AccessDeniedError) {
    console.error('Access denied')
  } else if (error instanceof AuthenticationError) {
    console.error('Authentication failed')
  } else if (error instanceof RateLimitedError) {
    console.error('Request remained rate-limited')
  } else if (error instanceof ApiError) {
    console.error(
      `SikkerKey returned HTTP ${error.httpStatus}`,
    )
  } else if (error instanceof ConfigurationError) {
    console.error('Machine identity could not be loaded')
  }
}
```

### Exception reference

| Exception | When it is used |
|---|---|
| `ConfigurationError` | Identity, key, vault-selection, or bootstrap configuration is invalid |
| `AuthenticationError` | HTTP `401` |
| `AccessDeniedError` | HTTP `403` |
| `NotFoundError` | HTTP `404` |
| `ConflictError` | HTTP `409` |
| `RateLimitedError` | HTTP `429` |
| `ServerSealedError` | HTTP `503` |
| `ApiError` | Another HTTP or network error; inspect `httpStatus` |
| `SecretStructureError` | `getFields` or `getField` received a non-object value |
| `FieldNotFoundError` | The requested structured field does not exist |

Network failures and request timeouts use an `ApiError` with `httpStatus === 0`.

### Retries and timeout

Authenticated secret requests retry network failures, request timeouts, and HTTP `429` or `503` responses up to three times. Retries wait 1, 2, and 4 seconds, and every attempt receives a fresh timestamp and nonce.

Each request has a 15-second timeout. Other HTTP responses are returned immediately as their matching exception.

## Feature-to-API reference

| What you want to do | SDK API | Result |
|---|---|---|
| Create a client from disk | `SikkerKey.create(vaultOrPath?)` | `SikkerKey` |
| Prepare ephemeral enrollment | `SikkerKey.bootstrap(vaultId, token, options?)` | `SikkerKeyBootstrap` |
| Complete ephemeral enrollment | `inMemory()` | `Promise<SikkerKey>` |
| List locally registered vaults | `SikkerKey.listVaults()` | `string[]` |
| Enable outage fallback | `enableCache(options?)` | The same `SikkerKey` client |
| Read a standard secret | `getSecret(secretId)` | `Promise<string>` |
| Read every structured field | `getFields(secretId)` | `Promise<Record<string, string>>` |
| Read one structured field | `getField(secretId, field)` | `Promise<string>` |
| List accessible secrets | `listSecrets()` | `Promise<SecretListItem[]>` |
| List accessible secrets in a project | `listSecretsByProject(projectId)` | `Promise<SecretListItem[]>` |
| Export accessible values | `export(projectId?)` | `Promise<Record<string, string>>` |
| Monitor a secret | `watch(secretId, callback)` | `void` |
| Stop monitoring one secret | `unwatch(secretId)` | `void` |
| Set the polling interval | `setPollInterval(seconds)` | `void` |
| Stop all monitoring | `close()` | `void` |

## Runtime footprint

The SDK uses Node.js built-ins for HTTPS, JSON, Ed25519, AES-GCM, and HKDF. It has no runtime package dependencies.

## Documentation

- [SikkerKey documentation](https://docs.sikkerkey.com)
- [SDK overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [Node.js SDK reference](https://docs.sikkerkey.com/docs/sdk/node)
- [Machine authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

The SikkerKey Node.js SDK is available under the [MIT License](LICENSE).
