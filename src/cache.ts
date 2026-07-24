// On-disk fallback secret cache — the Node port of the .skc format defined by the
// SikkerKey CLI. Files written here are byte-compatible with the CLI and the other
// SDKs: same key derivation, same AES-256-GCM sealing, same AAD, same envelope, so
// a cache written by one is readable by all.
//
// It is strictly opt-in (SikkerKey.enableCache) and inert until then: nothing in
// this file runs unless the client constructs a SecretCache, which only happens
// when caching is enabled.
//
//   key   = HKDF-SHA256(ikm = ed25519_seed, salt = vaultId, info = "sikkerkey-cache-v1")  → 32 bytes
//   entry = AES-256-GCM(key, nonce = random 12B, plaintext = {name,value,fieldNames} JSON,
//                       aad = "sikkerkey-cache-v1\0{vaultId}\0{machineId}\0{secretId}\0{cachedAt}")
//
// One file per secret at ~/.sikkerkey/vaults/{vaultId}/cache/{secretId}.skc, written
// atomically. The AAD binds each entry to its vault/machine/secret/timestamp, so an
// entry can't be forged, tampered, or swapped without the key.

import * as crypto from 'crypto'
import * as fs from 'fs'
import * as path from 'path'

const FORMAT_VERSION = 1
const KDF_INFO = 'sikkerkey-cache-v1'
const FILE_EXT = '.skc'
// Guards the on-disk filename against traversal; real secret ids are sk_<alnum>.
const SAFE_SECRET_ID = /^[A-Za-z0-9_-]+$/

export interface CacheResult {
  secretId: string
  name: string
  value: string
  fieldNames: string | null
  cachedAt: number // epoch seconds
}

// Mirrors the CLI's config.baseDir so the cache lands beside the identity it
// belongs to. Kept in sync with client.ts's getBaseDir (a cache.ts → client.ts
// import would be circular).
function baseDir(): string {
  return process.env.SIKKERKEY_HOME ?? path.join(process.env.HOME ?? '/tmp', '.sikkerkey')
}

export function cacheDir(vaultId: string): string {
  return path.join(baseDir(), 'vaults', vaultId, 'cache')
}

/** Derive the 32-byte AES-256 cache key from the Ed25519 seed, bound to the vault. */
export function deriveKey(seed: Buffer, vaultId: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync('sha256', seed, Buffer.from(vaultId, 'utf8'), Buffer.from(KDF_INFO, 'utf8'), 32),
  )
}

export class SecretCache {
  constructor(
    private readonly vaultId: string,
    private readonly machineId: string,
    private readonly key: Buffer,
  ) {}

  /** Seal a secret to the cache, replacing any existing entry atomically. */
  store(secretId: string, name: string, value: string, fieldNames: string | null): void {
    if (!SAFE_SECRET_ID.test(secretId)) {
      throw new Error(`refusing to cache unsafe secret id ${JSON.stringify(secretId)}`)
    }
    const cachedAt = Math.floor(Date.now() / 1000)
    const payload: Record<string, unknown> = { value }
    if (name !== '') payload.name = name
    if (fieldNames !== null) payload.fieldNames = fieldNames

    const { nonce, ct } = seal(this.key, Buffer.from(JSON.stringify(payload), 'utf8'), this.aad(secretId, cachedAt))
    const envelope = JSON.stringify({
      v: FORMAT_VERSION,
      nonce: nonce.toString('base64'),
      ct: ct.toString('base64'),
      cachedAt,
    })
    writeAtomic(this.filePath(secretId), envelope)
  }

  /** Return the cached entry for a secret, or null on a miss. A decrypt failure
   *  (tampered file, or one from a different identity) throws. */
  load(secretId: string): CacheResult | null {
    if (!SAFE_SECRET_ID.test(secretId)) return null
    let data: string
    try {
      data = fs.readFileSync(this.filePath(secretId), 'utf8')
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw e
    }
    return this.decode(secretId, data)
  }

  /** Every cached entry for the vault; tampered/foreign entries are skipped. */
  loadAll(): CacheResult[] {
    const dir = cacheDir(this.vaultId)
    let names: string[]
    try {
      names = fs.readdirSync(dir)
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw e
    }
    const out: CacheResult[] = []
    for (const n of names) {
      if (!n.endsWith(FILE_EXT)) continue
      const secretId = n.slice(0, -FILE_EXT.length)
      try {
        const res = this.decode(secretId, fs.readFileSync(path.join(dir, n), 'utf8'))
        if (res) out.push(res)
      } catch {
        /* tampered / foreign / unknown format — skip */
      }
    }
    return out
  }

  private decode(secretId: string, data: string): CacheResult | null {
    const env = JSON.parse(data)
    if (env.v !== FORMAT_VERSION) return null // a newer format wrote this; treat as a miss
    const nonce = Buffer.from(String(env.nonce), 'base64')
    const ct = Buffer.from(String(env.ct), 'base64')
    const pt = open(this.key, nonce, ct, this.aad(secretId, env.cachedAt))
    const p = JSON.parse(pt.toString('utf8'))
    return {
      secretId,
      name: typeof p.name === 'string' ? p.name : '',
      value: String(p.value ?? ''),
      fieldNames: typeof p.fieldNames === 'string' ? p.fieldNames : null,
      cachedAt: Number(env.cachedAt),
    }
  }

  private filePath(secretId: string): string {
    return path.join(cacheDir(this.vaultId), secretId + FILE_EXT)
  }

  // Binds an entry to its context: domain || vault || machine || secret || timestamp,
  // null-separated (none of the tokens contain a null byte).
  private aad(secretId: string, cachedAt: number): Buffer {
    return Buffer.from(`${KDF_INFO}\x00${this.vaultId}\x00${this.machineId}\x00${secretId}\x00${cachedAt}`, 'utf8')
  }
}

/** Remove the entire cache directory for a vault. */
export function clearCache(vaultId: string): void {
  fs.rmSync(cacheDir(vaultId), { recursive: true, force: true })
}

/** How many secrets are currently cached for a vault. */
export function countCache(vaultId: string): number {
  try {
    return fs.readdirSync(cacheDir(vaultId)).filter(n => n.endsWith(FILE_EXT)).length
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return 0
    throw e
  }
}

// ── Crypto ──

function seal(key: Buffer, plaintext: Buffer, aad: Buffer): { nonce: Buffer; ct: Buffer } {
  const nonce = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  // Match Go's gcm.Seal output: ciphertext || tag(16).
  return { nonce, ct: Buffer.concat([enc, tag]) }
}

function open(key: Buffer, nonce: Buffer, ct: Buffer, aad: Buffer): Buffer {
  if (ct.length < 16) throw new Error('ciphertext too short')
  const enc = ct.subarray(0, ct.length - 16)
  const tag = ct.subarray(ct.length - 16)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(enc), decipher.final()])
}

// Write via a temp file + rename so a reader never sees a half-written entry and
// concurrent writers never corrupt each other.
function writeAtomic(filePath: string, data: string): void {
  const dir = path.dirname(filePath)
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const tmp = path.join(dir, `.skc-${process.pid}-${crypto.randomBytes(6).toString('hex')}`)
  fs.writeFileSync(tmp, data, { mode: 0o600 })
  try {
    fs.renameSync(tmp, filePath)
  } catch (e) {
    try {
      fs.rmSync(tmp, { force: true })
    } catch {
      /* ignore */
    }
    throw e
  }
}
