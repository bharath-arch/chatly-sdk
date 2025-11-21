/**
 * SDK Configuration Constants
 */

// Cryptography
export const SUPPORTED_CURVE = "prime256v1";
export const ALGORITHM = "aes-256-gcm";
export const IV_LENGTH = 12; // 96 bits for GCM
export const SALT_LENGTH = 16;
export const KEY_LENGTH = 32; // 256 bits
export const TAG_LENGTH = 16;
export const PBKDF2_ITERATIONS = 100000;

// Validation
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 20;
export const MESSAGE_MAX_LENGTH = 10000;
export const GROUP_NAME_MAX_LENGTH = 100;
export const GROUP_MIN_MEMBERS = 2;
export const GROUP_MAX_MEMBERS = 256;

// Transport
export const RECONNECT_MAX_ATTEMPTS = 5;
export const RECONNECT_BASE_DELAY = 1000; // 1 second
export const RECONNECT_MAX_DELAY = 30000; // 30 seconds
export const HEARTBEAT_INTERVAL = 30000; // 30 seconds
export const CONNECTION_TIMEOUT = 10000; // 10 seconds

// Message Queue
export const MAX_QUEUE_SIZE = 1000;
export const MESSAGE_RETRY_ATTEMPTS = 3;
export const MESSAGE_RETRY_DELAY = 2000; // 2 seconds

// Events
export const EVENTS = {
  MESSAGE_SENT: 'message:sent',
  MESSAGE_RECEIVED: 'message:received',
  MESSAGE_FAILED: 'message:failed',
  CONNECTION_STATE_CHANGED: 'connection:state',
  SESSION_CREATED: 'session:created',
  GROUP_CREATED: 'group:created',
  ERROR: 'error',
  USER_CREATED: 'user:created',
} as const;

// Connection States
export enum ConnectionState {
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  CONNECTED = 'connected',
  RECONNECTING = 'reconnecting',
  FAILED = 'failed',
}

// Message Status
export enum MessageStatus {
  PENDING = 'pending',
  SENT = 'sent',
  DELIVERED = 'delivered',
  FAILED = 'failed',
}
