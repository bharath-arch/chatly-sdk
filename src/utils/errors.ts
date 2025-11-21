/**
 * Base SDK Error class
 */
export class SDKError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly retryable: boolean = false,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      retryable: this.retryable,
      details: this.details,
    };
  }
}

/**
 * Network-related errors (connection, timeout, etc.)
 */
export class NetworkError extends SDKError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'NETWORK_ERROR', true, details);
  }
}

/**
 * Encryption/Decryption errors
 */
export class EncryptionError extends SDKError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ENCRYPTION_ERROR', false, details);
  }
}

/**
 * Authentication/Authorization errors
 */
export class AuthError extends SDKError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'AUTH_ERROR', false, details);
  }
}

/**
 * Validation errors (invalid input)
 */
export class ValidationError extends SDKError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'VALIDATION_ERROR', false, details);
  }
}

/**
 * Storage-related errors
 */
export class StorageError extends SDKError {
  constructor(message: string, retryable: boolean = true, details?: Record<string, unknown>) {
    super(message, 'STORAGE_ERROR', retryable, details);
  }
}

/**
 * Session-related errors
 */
export class SessionError extends SDKError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'SESSION_ERROR', false, details);
  }
}

/**
 * Transport-related errors
 */
export class TransportError extends SDKError {
  constructor(message: string, retryable: boolean = true, details?: Record<string, unknown>) {
    super(message, 'TRANSPORT_ERROR', retryable, details);
  }
}

/**
 * Configuration errors
 */
export class ConfigError extends SDKError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'CONFIG_ERROR', false, details);
  }
}
