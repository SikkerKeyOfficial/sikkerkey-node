import * as crypto from 'crypto'
import * as http from 'http'
import * as https from 'https'
import {
  ApiError,
  AuthenticationError,
  AccessDeniedError,
  ConfigurationError,
  ConflictError,
  NotFoundError,
  RateLimitedError,
  ServerSealedError,
} from './exceptions'
import type { SikkerKey, SecretListItem } from './client'

// ── Constants ──

const DEFAULT_API_URL = 'https://api.sikkerkey.com'
const DEFAULT_RENEW_SKEW_MS = 60_000
const ENROLL_TIMEOUT_MS = 15_000

// ── Types ──

export interface BootstrapOptions {
  /** Hostname label recorded on the enrolled machine. If the enrollment token sets a hostname pattern, this must match it. */
  hostname?: string
  /** Optional machine name to request. */
  name?: string
  /** Re-enroll this many ms before the ephemeral machine's TTL expires. Default 60_000. */
  renewSkewMs?: number
}

interface EnrollIdentity {
  machineId: string
  machineName: string
  vaultId: string
  apiUrl: string
  privateKeyPath: string
}

/** Builds an in-memory SikkerKey from an enrolled identity + private key. Supplied by SikkerKey.bootstrap so the private constructor never leaks. */
export type SikkerKeyFactory = (identity: EnrollIdentity, privateKey: crypto.KeyObject) => SikkerKey

interface EnrollResponse {
  machineId: string
  machineName: string
  vaultId: string
  expiresAt: number
}

// ── Builder ──

/** Returned by `SikkerKey.bootstrap()`. Call `.inMemory()` to get a client. */
export class SikkerKeyBootstrap {
  constructor(
    private readonly vaultId: string,
    private readonly token: string,
    private readonly options: BootstrapOptions,
    private readonly factory: SikkerKeyFactory,
  ) {}

  /**
   * Create a memory-only client. Nothing is written to disk: an Ed25519
   * keypair is generated in memory and an ephemeral machine is enrolled
   * lazily on first use, reused while the instance stays warm, and
   * re-enrolled when its TTL nears expiry. Built for serverless and
   * read-only-filesystem environments.
   */
  inMemory(): BootstrappedClient {
    return new BootstrappedClient(this.vaultId, this.token, this.options, this.factory)
  }
}

// ── Memory-only client ──

/**
 * A read client backed by a lazily-enrolled, memory-only ephemeral identity.
 * Wraps (does not modify) the disk-based {@link SikkerKey}: each call resolves
 * the underlying client (enrolling on first use, re-enrolling near expiry) and
 * delegates to it.
 */
export class BootstrappedClient {
  private readonly apiUrl: string
  private readonly renewSkewMs: number
  private cached: { client: SikkerKey; expiresAt: number } | null = null
  private pending: Promise<{ client: SikkerKey; expiresAt: number }> | null = null

  constructor(
    private readonly vaultId: string,
    private readonly token: string,
    private readonly options: BootstrapOptions,
    private readonly factory: SikkerKeyFactory,
  ) {
    if (!vaultId) throw new ConfigurationError('SikkerKey.bootstrap requires a vault ID')
    if (!token) throw new ConfigurationError('SikkerKey.bootstrap requires an enrollment token')
    // SikkerKey is a managed service; the API URL is fixed and never set by
    // callers. The env override exists only for local development.
    const url = process.env.SIKKERKEY_API_URL ?? DEFAULT_API_URL
    if (!url.startsWith('https://') && !url.startsWith('http://localhost')) {
      throw new ConfigurationError(
        `API URL must use HTTPS: ${url}. Use http://localhost only for local development.`
      )
    }
    this.apiUrl = url.replace(/\/+$/, '')
    this.renewSkewMs = options.renewSkewMs ?? DEFAULT_RENEW_SKEW_MS
  }

  /** Force enrollment now and return the underlying client (for getters, watch, etc.). */
  async ready(): Promise<SikkerKey> {
    return (await this.ensure()).client
  }

  /** Fetch a secret value by ID. */
  async getSecret(secretId: string): Promise<string> {
    return (await this.ensure()).client.getSecret(secretId)
  }

  /** Fetch a structured secret as a field map. */
  async getFields(secretId: string): Promise<Record<string, string>> {
    return (await this.ensure()).client.getFields(secretId)
  }

  /** Fetch a single field from a structured secret. */
  async getField(secretId: string, field: string): Promise<string> {
    return (await this.ensure()).client.getField(secretId, field)
  }

  /** List all secrets this machine can access. */
  async listSecrets(): Promise<SecretListItem[]> {
    return (await this.ensure()).client.listSecrets()
  }

  /** List secrets in a specific project. */
  async listSecretsByProject(projectId: string): Promise<SecretListItem[]> {
    return (await this.ensure()).client.listSecretsByProject(projectId)
  }

  /** Export all accessible secrets as a flat key-value map. */
  async export(projectId?: string): Promise<Record<string, string>> {
    return (await this.ensure()).client.export(projectId)
  }

  /** Stop the underlying client (clears any watch timers) and drop the cached identity. */
  close(): void {
    this.cached?.client.close()
    this.cached = null
  }

  // ── Internal ──

  private async ensure(): Promise<{ client: SikkerKey; expiresAt: number }> {
    if (this.cached && Date.now() < this.cached.expiresAt - this.renewSkewMs) {
      return this.cached
    }
    // Single in-flight enrollment: concurrent first-calls share one round trip.
    if (this.pending) return this.pending
    this.pending = this.enroll()
      .then(result => {
        this.cached = result
        this.pending = null
        return result
      })
      .catch(err => {
        this.pending = null
        throw err
      })
    return this.pending
  }

  private async enroll(): Promise<{ client: SikkerKey; expiresAt: number }> {
    // Generate the keypair in memory. The private key never leaves this process.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
    const jwk = publicKey.export({ format: 'jwk' }) as { x?: string }
    if (!jwk.x) throw new ConfigurationError('Failed to derive Ed25519 public key')
    // Server expects the raw 32-byte public key as standard base64 (44 chars).
    const publicKeyB64 = Buffer.from(jwk.x, 'base64url').toString('base64')

    const hostname = this.options.hostname ?? process.env.HOSTNAME ?? 'serverless'
    const body = JSON.stringify({
      token: this.token,
      publicKey: publicKeyB64,
      hostname,
      ...(this.options.name ? { name: this.options.name } : {}),
    })

    const resp = await enrollRegister(this.apiUrl, this.vaultId, body)

    const identity: EnrollIdentity = {
      machineId: resp.machineId,
      machineName: resp.machineName,
      vaultId: resp.vaultId,
      apiUrl: this.apiUrl,
      privateKeyPath: '', // memory-only: never read after construction
    }
    return { client: this.factory(identity, privateKey), expiresAt: resp.expiresAt }
  }
}

// ── Enrollment transport ──

function enrollRegister(apiUrl: string, vaultId: string, body: string): Promise<EnrollResponse> {
  const url = new URL(`/v1/${encodeURIComponent(vaultId)}/enroll/register`, apiUrl)
  const transport = url.protocol === 'https:' ? https : http
  return new Promise((resolve, reject) => {
    const req = transport.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body).toString(),
      },
      timeout: ENROLL_TIMEOUT_MS,
    }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString()
        const code = res.statusCode ?? 0
        if (code >= 200 && code < 300) {
          try {
            const parsed = JSON.parse(text) as EnrollResponse
            if (!parsed.machineId || !parsed.vaultId) {
              reject(new ApiError('Malformed enrollment response', code))
              return
            }
            resolve(parsed)
          } catch {
            reject(new ApiError('Failed to parse enrollment response', code))
          }
          return
        }
        let message: string
        try { message = JSON.parse(text).error ?? text } catch { message = text || `HTTP ${code}` }
        reject(enrollError(code, message))
      })
      res.on('error', reject)
    })
    req.on('error', (e) => reject(new ApiError(`Enrollment network error: ${(e as Error).message}`, 0)))
    req.on('timeout', () => { req.destroy(); reject(new ApiError('Enrollment request timeout', 0)) })
    req.write(body)
    req.end()
  })
}

function enrollError(status: number, message: string): Error {
  switch (status) {
    case 401: return new AuthenticationError(message)
    case 403: return new AccessDeniedError(message)
    case 404: return new NotFoundError(message)
    case 409: return new ConflictError(message)
    case 429: return new RateLimitedError(message)
    case 503: return new ServerSealedError(message)
    default: return new ApiError(message || `Enrollment failed (HTTP ${status})`, status)
  }
}
