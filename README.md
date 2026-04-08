# SikkerKey Node.js SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@sikkerkey/sdk)](https://www.npmjs.com/package/@sikkerkey/sdk)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)

The official Node.js SDK for [SikkerKey](https://sikkerkey.com). Read-only access to secrets using Ed25519 machine authentication. Zero external dependencies - Node.js built-in `crypto`, `fs`, `http`, `https` only.

## Installation

```bash
npm install @sikkerkey/sdk
```

Requires Node.js 18+.

## Quick Start

```typescript
import { SikkerKey } from '@sikkerkey/sdk'

const sk = SikkerKey.create('vault_abc123')
const apiKey = await sk.getSecret('sk_stripe_key')
```

The SDK reads the machine identity from `~/.sikkerkey/vaults/<vault-id>/identity.json`, signs every request with the machine's Ed25519 private key, and returns the decrypted value.

## Client Creation

```typescript
// Explicit vault ID
const sk = SikkerKey.create('vault_abc123')

// Direct path to identity file
const sk = SikkerKey.create('/etc/sikkerkey/vaults/vault_abc123/identity.json')

// Auto-detect: uses SIKKERKEY_IDENTITY env, or finds the single vault on disk
const sk = SikkerKey.create()
```

Auto-detection throws `ConfigurationError` if multiple vaults are registered and no vault is specified.

## Reading Secrets

### Single Value

```typescript
const apiKey = await sk.getSecret('sk_stripe_prod')
```

### Structured (Multiple Fields)

```typescript
const fields = await sk.getFields('sk_db_prod')
const host = fields.host       // "db.example.com"
const password = fields.password // "hunter2"
```

Throws `SecretStructureError` if the secret value is not a JSON object.

### Single Field

```typescript
const password = await sk.getField('sk_db_prod', 'password')
```

Throws `FieldNotFoundError` if the field doesn't exist. The error message includes the available field names.

## Listing Secrets

```typescript
// All secrets this machine can access
const secrets = await sk.listSecrets()
for (const s of secrets) {
  console.log(`${s.id}: ${s.name}`)
}

// Secrets in a specific project
const projectSecrets = await sk.listSecretsByProject('proj_production')
```

Each `SecretListItem` has `id`, `name`, `fieldNames` (null for single-value), and `projectId`.

## Export

Export all accessible secrets as a flat key-value map in a single round trip:

```typescript
const env = await sk.export()
// { API_KEY: "sk-live-...", DB_CREDS_HOST: "db.example.com", DB_CREDS_PASSWORD: "s3cret" }

// Scoped to a project
const env = await sk.export('proj_production')
```

Secret names are converted to uppercase env format. Structured secrets are flattened: `SECRET_NAME_FIELD_NAME`.

## Multi-Vault

```typescript
const prod = SikkerKey.create('vault_a1b2c3')
const staging = SikkerKey.create('vault_x9y8z7')

const prodKey = await prod.getSecret('sk_api_key')
const stagingKey = await staging.getSecret('sk_api_key')
```

### List Registered Vaults

```typescript
const vaults = SikkerKey.listVaults()
// ["vault_a1b2c3", "vault_x9y8z7"]
```

## Machine Info

```typescript
sk.machineId    // "550e8400-e29b-41d4-a716-446655440000"
sk.machineName  // "api-server-1"
sk.vaultId      // "vault_abc123"
sk.apiUrl       // "https://api.sikkerkey.com"
```

## Error Handling

The SDK uses typed exceptions for every error case:

```typescript
import { SikkerKey, NotFoundError, AccessDeniedError, AuthenticationError } from '@sikkerkey/sdk'

try {
  const secret = await sk.getSecret('sk_nonexistent')
} catch (e) {
  if (e instanceof NotFoundError) {
    // Secret doesn't exist
  } else if (e instanceof AccessDeniedError) {
    // Machine not approved or no grant
  } else if (e instanceof AuthenticationError) {
    // Invalid signature or unknown machine
  }
}
```

### Exception Hierarchy

```
SikkerKeyError
├── ConfigurationError      — identity file missing, bad key, invalid config
├── SecretStructureError    — secret is not a JSON object (getFields/getField)
├── FieldNotFoundError      — field not in structured secret
└── ApiError                — HTTP error from the API
    ├── AuthenticationError — 401
    ├── AccessDeniedError   — 403
    ├── NotFoundError       — 404
    ├── ConflictError       — 409
    ├── RateLimitedError    — 429
    └── ServerSealedError   — 503
```

`ApiError` has a `httpStatus` property with the HTTP status code.

## Identity Resolution

The SDK resolves the identity file in this order:

1. **Explicit path** — starts with `/` or contains `identity.json`
2. **Vault ID** — looks up `~/.sikkerkey/vaults/{vaultId}/identity.json`
3. **`SIKKERKEY_IDENTITY` env** — path to identity file
4. **Auto-detect** — single vault on disk

The `vault_` prefix is added automatically if not present.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SIKKERKEY_IDENTITY` | Path to `identity.json` — overrides vault lookup |
| `SIKKERKEY_HOME` | Base config directory (default: `~/.sikkerkey`) |

## Retry Behavior

429 (rate limited) and 503 (server sealed) responses are retried up to 3 times with exponential backoff (1s, 2s, 4s). Each retry uses a fresh timestamp and nonce. Network errors are also retried.

## Authentication

Every request includes Ed25519-signed headers:

- `X-Machine-Id` — machine UUID
- `X-Timestamp` — Unix timestamp
- `X-Nonce` — random base64 nonce (replay protection)
- `X-Signature` — signature of `method:path:timestamp:nonce:bodyHash`

HTTPS is enforced for all non-localhost connections. 15-second request timeout.

## Method Reference

| Method | Returns | Description |
|--------|---------|-------------|
| `SikkerKey.create(vaultOrPath?)` | `SikkerKey` | Create client (sync) |
| `SikkerKey.listVaults()` | `string[]` | List registered vault IDs (static) |
| `getSecret(secretId)` | `Promise<string>` | Read a secret value |
| `getFields(secretId)` | `Promise<Record<string, string>>` | Read structured secret |
| `getField(secretId, field)` | `Promise<string>` | Read single field |
| `listSecrets()` | `Promise<SecretListItem[]>` | List all accessible secrets |
| `listSecretsByProject(projectId)` | `Promise<SecretListItem[]>` | List secrets in a project |
| `export(projectId?)` | `Promise<Record<string, string>>` | Export as env map |

## Dependencies

None. Uses Node.js built-ins only: `crypto`, `fs`, `path`, `http`, `https`.

## Documentation

- [SDK Overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [Node.js SDK Reference](https://docs.sikkerkey.com/docs/sdk/node)
- [Machine Authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

MIT - see [LICENSE](LICENSE) for details.
