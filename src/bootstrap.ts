import * as crypto from 'crypto'
import * as http from 'http'
import * as https from 'https'
import {
  SikkerKeyError,
  ApiError,
  AuthenticationError,
  AccessDeniedError,
  ConfigurationError,
  ConflictError,
  NotFoundError,
  RateLimitedError,
  ServerSealedError,
} from './exceptions'
import type { SikkerKey } from './client'

// ── Constants ──

const DEFAULT_API_URL = 'https://api.sikkerkey.com'
const ENROLL_TIMEOUT_MS = 15_000

// ── Types ──

export interface BootstrapOptions {
  /** Hostname label recorded on the enrolled machine. If the enrollment token sets a hostname pattern, this must match it. */
  hostname?: string
  /** Optional machine name to request. Overridden when the enrollment token defines a name pattern (the server generates the name from it). */
  name?: string
}

interface EnrollIdentity {
  machineId: string
  machineName: string
  vaultId: string
  apiUrl: string
  privateKeyPath: string
}

/** Builds a SikkerKey from an enrolled identity + in-memory private key. Supplied by SikkerKey.bootstrap so the private constructor never leaks. */
export type SikkerKeyFactory = (identity: EnrollIdentity, privateKey: crypto.KeyObject) => SikkerKey

interface EnrollResponse {
  machineId: string
  machineName: string
  vaultId: string
  expiresAt: number
  /** Retrieval-plane base URL (the machine-service); stored as the identity's read URL. */
  apiUrl?: string
}

// ── Builder ──

/** Returned by `SikkerKey.bootstrap()`. Call `.inMemory()` to enroll and get a ready client. */
export class SikkerKeyBootstrap {
  constructor(
    private readonly vaultId: string,
    private readonly token: string,
    private readonly options: BootstrapOptions,
    private readonly factory: SikkerKeyFactory,
  ) {}

  /**
   * Enroll an ephemeral machine in memory and return a ready client.
   *
   * Generates an Ed25519 keypair in memory, registers an ephemeral machine
   * with the enrollment token, and returns a client whose identity lives only
   * in process memory. Nothing is written to disk. Built for serverless and
   * read-only-filesystem environments.
   *
   * Enrollment happens once, here. After it resolves, the returned client is an
   * ordinary {@link SikkerKey}: it signs each read with the in-memory key, no
   * different from a disk-based client. The ephemeral machine lives for the
   * lifetime set on the enrollment token; reading after it expires fails like
   * any expired machine, so set the token's machine lifetime to suit the
   * workload. The common path is to read at startup and hold the values.
   */
  async inMemory(): Promise<SikkerKey> {
    if (!this.vaultId) throw new ConfigurationError('SikkerKey.bootstrap requires a vault ID')
    if (!this.token) throw new ConfigurationError('SikkerKey.bootstrap requires an enrollment token')

    // SikkerKey is a managed service; the API URL is fixed and never set by
    // callers. The env override exists only for local development.
    const raw = process.env.SIKKERKEY_API_URL ?? DEFAULT_API_URL
    if (!raw.startsWith('https://') && !raw.startsWith('http://localhost')) {
      throw new ConfigurationError(
        `API URL must use HTTPS: ${raw}. Use http://localhost only for local development.`,
      )
    }
    const apiUrl = raw.replace(/\/+$/, '')

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

    const resp = await enrollRegister(apiUrl, this.vaultId, body)

    const identity: EnrollIdentity = {
      machineId: resp.machineId,
      machineName: resp.machineName,
      vaultId: resp.vaultId,
      // Enrollment ran against the backend (apiUrl); runtime reads go to the
      // retrieval plane the backend hands back. Fall back to the enroll URL
      // only if an older endpoint omits it.
      apiUrl: resp.apiUrl && resp.apiUrl.length > 0 ? resp.apiUrl : apiUrl,
      privateKeyPath: '', // memory-only: never read
    }
    return this.factory(identity, privateKey)
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

function enrollError(status: number, message: string): SikkerKeyError {
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
