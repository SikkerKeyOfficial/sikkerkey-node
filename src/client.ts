import * as crypto from 'crypto'
import * as fs from 'fs'
import * as path from 'path'
import * as http from 'http'
import * as https from 'https'
import {
  ApiError,
  AuthenticationError,
  AccessDeniedError,
  ConfigurationError,
  ConflictError,
  FieldNotFoundError,
  NotFoundError,
  RateLimitedError,
  SecretStructureError,
  ServerSealedError,
  SikkerKeyError,
} from './exceptions'

// ── Types ──

export interface SecretListItem {
  id: string
  name: string
  fieldNames: string | null
  projectId: string | null
}

export type WatchStatus = 'changed' | 'deleted' | 'access_denied' | 'error'

export interface WatchEvent {
  secretId: string
  status: WatchStatus
  value: string | null
  fields: Record<string, string> | null
  error: string | null
}

interface Identity {
  machineId: string
  machineName: string
  vaultId: string
  apiUrl: string
  privateKeyPath: string
}

// ── Constants ──

const RETRYABLE_CODES = new Set([429, 503])
const MAX_RETRIES = 3
const BACKOFF_MS = [1000, 2000, 4000]

// ── Client ──

export class SikkerKey {
  private identity: Identity
  private privateKey: crypto.KeyObject
  private watchers: Map<string, (event: WatchEvent) => void> = new Map()
  private pollIntervalMs: number = 15_000
  private pollTimer: ReturnType<typeof setInterval> | null = null

  private constructor(identity: Identity, privateKey: crypto.KeyObject) {
    this.identity = identity
    this.privateKey = privateKey
  }

  /** Create a SikkerKey client. Pass a vault ID, path to identity.json, or undefined to auto-detect. */
  static create(vaultOrPath?: string): SikkerKey {
    const identityFile = resolveIdentity(vaultOrPath)
    const { identity, privateKey } = loadIdentity(identityFile)
    return new SikkerKey(identity, privateKey)
  }

  get machineId(): string { return this.identity.machineId }
  get machineName(): string { return this.identity.machineName }
  get vaultId(): string { return this.identity.vaultId }
  get apiUrl(): string { return this.identity.apiUrl }

  // ── Read ──

  /** Fetch a secret value by ID. */
  async getSecret(secretId: string): Promise<string> {
    const body = await this.request('GET', `/v1/secret/${secretId}`)
    return JSON.parse(body).value
  }

  /** Fetch a structured secret as a field map. */
  async getFields(secretId: string): Promise<Record<string, string>> {
    const raw = await this.getSecret(secretId)
    try {
      const parsed = JSON.parse(raw)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error()
      const result: Record<string, string> = {}
      for (const [k, v] of Object.entries(parsed)) result[k] = String(v)
      return result
    } catch {
      throw new SecretStructureError(`Secret ${secretId} is not a structured secret`)
    }
  }

  /** Fetch a single field from a structured secret. */
  async getField(secretId: string, field: string): Promise<string> {
    const fields = await this.getFields(secretId)
    if (!(field in fields)) {
      throw new FieldNotFoundError(
        `Field '${field}' not found in secret ${secretId}. Available: ${Object.keys(fields).join(', ')}`
      )
    }
    return fields[field]
  }

  // ── List ──

  /** List all secrets this machine can access. */
  async listSecrets(): Promise<SecretListItem[]> {
    const body = await this.request('GET', '/v1/secrets')
    return JSON.parse(body).secrets
  }

  /** List secrets in a specific project. */
  async listSecretsByProject(projectId: string): Promise<SecretListItem[]> {
    const body = await this.request('POST', '/v1/secrets/list', JSON.stringify({ projectId }))
    return JSON.parse(body).secrets
  }

  // ── Export ──

  /** Export all accessible secrets as a flat key-value map (single round trip). */
  async export(projectId?: string): Promise<Record<string, string>> {
    const payload = projectId ? JSON.stringify({ projectId }) : undefined
    const body = await this.request('POST', '/v1/secrets/export', payload)
    const entries: Array<{ id: string; name: string; value: string; fieldNames: string | null }> = JSON.parse(body).secrets
    const result: Record<string, string> = {}
    for (const entry of entries) {
      const envName = toEnvName(entry.name)
      if (entry.fieldNames != null) {
        try {
          const fields = JSON.parse(entry.value)
          if (typeof fields === 'object' && fields !== null && !Array.isArray(fields) && Object.keys(fields).length > 0) {
            for (const [k, v] of Object.entries(fields)) {
              result[`${envName}_${toEnvName(k)}`] = String(v)
            }
            continue
          }
        } catch { /* not structured */ }
      }
      result[envName] = entry.value
    }
    return result
  }

  // ── List Vaults ──

  /** List all vault IDs registered on this machine. */
  static listVaults(): string[] {
    const vaultsDir = getVaultsDir()
    if (!fs.existsSync(vaultsDir)) return []
    return fs.readdirSync(vaultsDir)
      .filter(d => {
        const dir = path.join(vaultsDir, d)
        return fs.statSync(dir).isDirectory() && fs.existsSync(path.join(dir, 'identity.json'))
      })
      .sort()
  }

  // ── Watch ──

  /** Register a callback that fires when the given secret changes, is deleted, or becomes inaccessible. */
  watch(secretId: string, callback: (event: WatchEvent) => void): void {
    this.watchers.set(secretId, callback)
    if (this.pollTimer === null) {
      this.pollTimer = setInterval(() => { this.pollWatchers() }, this.pollIntervalMs)
      this.pollTimer.unref()
    }
  }

  /** Stop watching a secret. If no watches remain, polling stops automatically. */
  unwatch(secretId: string): void {
    this.watchers.delete(secretId)
    if (this.watchers.size === 0 && this.pollTimer !== null) {
      clearInterval(this.pollTimer)
      this.pollTimer = null
    }
  }

  /** Set the polling interval in seconds (minimum 10). Default is 15. */
  setPollInterval(seconds: number): void {
    const clamped = Math.max(10, seconds)
    this.pollIntervalMs = clamped * 1000
    if (this.pollTimer !== null) {
      clearInterval(this.pollTimer)
      this.pollTimer = setInterval(() => { this.pollWatchers() }, this.pollIntervalMs)
      this.pollTimer.unref()
    }
  }

  /** Stop all watching and clear all registered callbacks. */
  close(): void {
    if (this.pollTimer !== null) {
      clearInterval(this.pollTimer)
      this.pollTimer = null
    }
    this.watchers.clear()
  }

  private async pollWatchers(): Promise<void> {
    const ids = Array.from(this.watchers.keys())
    if (ids.length === 0) return

    let changes: Record<string, { status: string }>
    try {
      const body = await this.request('POST', '/v1/secrets/poll', JSON.stringify({ watch: ids }))
      changes = JSON.parse(body).changes
    } catch {
      return
    }

    for (const [secretId, info] of Object.entries(changes)) {
      const callback = this.watchers.get(secretId)
      if (!callback) continue

      const status = info.status as WatchStatus

      if (status === 'changed') {
        try {
          const value = await this.getSecret(secretId)
          let fields: Record<string, string> | null = null
          try {
            const parsed = JSON.parse(value)
            if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
              fields = {}
              for (const [k, v] of Object.entries(parsed)) fields[k] = String(v)
            }
          } catch { /* not structured */ }
          callback({ secretId, status: 'changed', value, fields, error: null })
        } catch (e) {
          callback({ secretId, status: 'error', value: null, fields: null, error: (e as Error).message })
        }
        continue
      }

      if (status === 'deleted' || status === 'access_denied') {
        callback({ secretId, status, value: null, fields: null, error: null })
        this.watchers.delete(secretId)
        if (this.watchers.size === 0 && this.pollTimer !== null) {
          clearInterval(this.pollTimer)
          this.pollTimer = null
        }
        continue
      }

      callback({ secretId, status: 'error', value: null, fields: null, error: `Unknown status: ${status}` })
    }
  }

  // ── Internal ──

  private async request(method: string, reqPath: string, body?: string, expectStatus: number = 200): Promise<string> {
    let lastError: SikkerKeyError | null = null

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        await sleep(BACKOFF_MS[Math.min(attempt - 1, BACKOFF_MS.length - 1)])
      }

      const timestamp = Math.floor(Date.now() / 1000).toString()
      const nonce = crypto.randomBytes(16).toString('base64')
      const bodyHash = crypto.createHash('sha256').update(body ?? '').digest('hex')
      const signPayload = `${method}:${reqPath}:${timestamp}:${nonce}:${bodyHash}`
      const signature = crypto.sign(null, Buffer.from(signPayload), this.privateKey).toString('base64')

      const url = new URL(reqPath, this.identity.apiUrl)
      const isHttps = url.protocol === 'https:'
      const transport = isHttps ? https : http

      let code: number
      let responseBody: string
      try {
        const result = await new Promise<{ code: number; body: string }>((resolve, reject) => {
          const req = transport.request(url, {
            method,
            headers: {
              'X-Machine-Id': this.identity.machineId,
              'X-Timestamp': timestamp,
              'X-Nonce': nonce,
              'X-Signature': signature,
              ...(body != null ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body).toString() } : {}),
            },
            timeout: 15_000,
          }, (res) => {
            const chunks: Buffer[] = []
            res.on('data', (chunk: Buffer) => chunks.push(chunk))
            res.on('end', () => resolve({ code: res.statusCode ?? 0, body: Buffer.concat(chunks).toString() }))
            res.on('error', reject)
          })
          req.on('error', reject)
          req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')) })
          if (body != null) req.write(body)
          req.end()
        })
        code = result.code
        responseBody = result.body
      } catch (e) {
        lastError = new ApiError(`Network error: ${(e as Error).message}`, 0)
        continue
      }

      if (code === expectStatus) return responseBody

      let errorMsg: string
      try {
        errorMsg = JSON.parse(responseBody).error ?? responseBody
      } catch {
        errorMsg = responseBody || `HTTP ${code}`
      }

      const exception = makeException(code, errorMsg)

      if (RETRYABLE_CODES.has(code) && attempt < MAX_RETRIES) {
        lastError = exception
        continue
      }

      throw exception
    }

    throw lastError ?? new ApiError(`Request failed after ${MAX_RETRIES} retries`, 0)
  }
}

// ── Identity resolution ──

function getBaseDir(): string {
  return process.env.SIKKERKEY_HOME ?? path.join(process.env.HOME ?? '/tmp', '.sikkerkey')
}

function getVaultsDir(): string {
  return path.join(getBaseDir(), 'vaults')
}

function resolveIdentity(vaultOrPath?: string): string {
  if (vaultOrPath && (vaultOrPath.startsWith('/') || vaultOrPath.includes('identity.json'))) {
    return vaultOrPath
  }

  if (vaultOrPath) {
    const vaultId = vaultOrPath.startsWith('vault_') ? vaultOrPath : `vault_${vaultOrPath}`
    const filePath = path.join(getVaultsDir(), vaultId, 'identity.json')
    if (fs.existsSync(filePath)) return filePath
    throw new ConfigurationError(
      `No identity found for vault '${vaultId}'. Expected: ${filePath}. Run the bootstrap command first.`
    )
  }

  const envPath = process.env.SIKKERKEY_IDENTITY
  if (envPath) return envPath

  const vaultsDir = getVaultsDir()
  if (fs.existsSync(vaultsDir)) {
    const found = fs.readdirSync(vaultsDir)
      .filter(d => {
        const dir = path.join(vaultsDir, d)
        return fs.statSync(dir).isDirectory() && fs.existsSync(path.join(dir, 'identity.json'))
      })
      .map(d => path.join(vaultsDir, d, 'identity.json'))

    if (found.length === 1) return found[0]
    if (found.length > 1) {
      const names = found.map(f => path.basename(path.dirname(f))).join(', ')
      throw new ConfigurationError(
        `Multiple vaults registered: ${names}. Specify which vault to use: SikkerKey.create("vault_id")`
      )
    }
  }

  throw new ConfigurationError(
    `No SikkerKey identity found. Run the bootstrap command first.\n  Checked: ${vaultsDir}/*/identity.json`
  )
}

function loadIdentity(filePath: string): { identity: Identity; privateKey: crypto.KeyObject } {
  if (!fs.existsSync(filePath)) {
    throw new ConfigurationError(`Identity file not found: ${filePath}. Run the bootstrap command first.`)
  }

  let identity: Identity
  try {
    identity = JSON.parse(fs.readFileSync(filePath, 'utf-8'))
  } catch (e) {
    throw new ConfigurationError(`Failed to parse identity file: ${(e as Error).message}`)
  }

  if (!identity.apiUrl.startsWith('https://') && !identity.apiUrl.startsWith('http://localhost')) {
    throw new ConfigurationError(
      `API URL must use HTTPS: ${identity.apiUrl}. Use http://localhost only for local development.`
    )
  }

  if (!fs.existsSync(identity.privateKeyPath)) {
    throw new ConfigurationError(`Private key not found: ${identity.privateKeyPath}`)
  }

  let privateKey: crypto.KeyObject
  try {
    const pem = fs.readFileSync(identity.privateKeyPath, 'utf-8')
    privateKey = crypto.createPrivateKey(pem)
    if (privateKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('Key is not Ed25519')
    }
  } catch (e) {
    throw new ConfigurationError(`Failed to load private key: ${(e as Error).message}`)
  }

  return { identity, privateKey }
}

// ── Helpers ──

function makeException(code: number, message: string): ApiError {
  switch (code) {
    case 401: return new AuthenticationError(message)
    case 403: return new AccessDeniedError(message)
    case 404: return new NotFoundError(message)
    case 409: return new ConflictError(message)
    case 429: return new RateLimitedError(message)
    case 503: return new ServerSealedError(message)
    default: return new ApiError(message, code)
  }
}

function toEnvName(name: string): string {
  return name.toUpperCase().replace(/[^A-Z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '')
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
