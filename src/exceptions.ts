/** Base error for all SikkerKey SDK errors. */
export class SikkerKeyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SikkerKeyError'
  }
}

/** Identity file missing, malformed, or private key not found. */
export class ConfigurationError extends SikkerKeyError {
  constructor(message: string) {
    super(message)
    this.name = 'ConfigurationError'
  }
}

/** HTTP error from the SikkerKey API. */
export class ApiError extends SikkerKeyError {
  readonly httpStatus: number

  constructor(message: string, httpStatus: number = 0) {
    super(message)
    this.name = 'ApiError'
    this.httpStatus = httpStatus
  }
}

/** 401 — signature verification failed or machine unknown. */
export class AuthenticationError extends ApiError {
  constructor(message: string) {
    super(message, 401)
    this.name = 'AuthenticationError'
  }
}

/** 403 — machine not approved, disabled, or no access grant. */
export class AccessDeniedError extends ApiError {
  constructor(message: string) {
    super(message, 403)
    this.name = 'AccessDeniedError'
  }
}

/** 404 — secret or resource not found. */
export class NotFoundError extends ApiError {
  constructor(message: string) {
    super(message, 404)
    this.name = 'NotFoundError'
  }
}

/** 409 — conflict (e.g. cannot rotate dynamic secret). */
export class ConflictError extends ApiError {
  constructor(message: string) {
    super(message, 409)
    this.name = 'ConflictError'
  }
}

/** 429 — too many requests. */
export class RateLimitedError extends ApiError {
  constructor(message: string) {
    super(message, 429)
    this.name = 'RateLimitedError'
  }
}

/** 503 — server is sealed, awaiting unseal. */
export class ServerSealedError extends ApiError {
  constructor(message: string) {
    super(message, 503)
    this.name = 'ServerSealedError'
  }
}

/** Wrong secret type for the operation. */
export class SecretStructureError extends SikkerKeyError {
  constructor(message: string) {
    super(message)
    this.name = 'SecretStructureError'
  }
}

/** Field not found in a structured secret. */
export class FieldNotFoundError extends SikkerKeyError {
  constructor(message: string) {
    super(message)
    this.name = 'FieldNotFoundError'
  }
}
