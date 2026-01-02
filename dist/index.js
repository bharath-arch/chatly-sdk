// src/index.ts
import { EventEmitter } from "events";

// src/crypto/e2e.ts
import { createECDH as createECDH2, createCipheriv, createDecipheriv, randomBytes as randomBytes2, pbkdf2Sync } from "crypto";

// src/crypto/utils.ts
function bufferToBase64(buffer) {
  return buffer.toString("base64");
}
function base64ToBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (!data) return Buffer.alloc(0);
  return Buffer.from(data, "base64");
}

// src/crypto/keys.ts
import { createECDH } from "crypto";
var SUPPORTED_CURVE = "prime256v1";
function generateIdentityKeyPair() {
  const ecdh = createECDH(SUPPORTED_CURVE);
  ecdh.generateKeys();
  return {
    publicKey: bufferToBase64(ecdh.getPublicKey()),
    privateKey: bufferToBase64(ecdh.getPrivateKey())
  };
}

// src/crypto/e2e.ts
import { createHash } from "crypto";
var ALGORITHM = "aes-256-gcm";
var IV_LENGTH = 12;
var SALT_LENGTH = 16;
var KEY_LENGTH = 32;
var TAG_LENGTH = 16;
var PBKDF2_ITERATIONS = 1e5;
function deriveSharedSecret(local, remotePublicKey) {
  const ecdh = createECDH2(SUPPORTED_CURVE);
  ecdh.setPrivateKey(base64ToBuffer(local.privateKey));
  const remotePublicKeyBuffer = base64ToBuffer(remotePublicKey);
  const sharedSecret = ecdh.computeSecret(remotePublicKeyBuffer);
  const a = base64ToBuffer(local.publicKey);
  const b = base64ToBuffer(remotePublicKey);
  const [first, second] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  const hash = createHash("sha256").update(first).update(second).digest();
  const salt = hash.slice(0, SALT_LENGTH);
  const derivedKey = pbkdf2Sync(sharedSecret, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
  return derivedKey;
}
function deriveLegacySharedSecret(local, remotePublicKey) {
  const ecdh = createECDH2(SUPPORTED_CURVE);
  ecdh.setPrivateKey(base64ToBuffer(local.privateKey));
  return ecdh.computeSecret(base64ToBuffer(remotePublicKey));
}
function encryptMessage(plaintext, secret) {
  const iv = randomBytes2(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, secret, iv);
  let ciphertext = cipher.update(plaintext, "utf8");
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);
  const tag = cipher.getAuthTag();
  const encrypted = Buffer.concat([ciphertext, tag]);
  return {
    ciphertext: bufferToBase64(encrypted),
    iv: bufferToBase64(iv)
  };
}
function decryptMessage(ciphertext, iv, secret) {
  const encryptedBuffer = base64ToBuffer(ciphertext);
  const ivBuffer = base64ToBuffer(iv);
  const tag = encryptedBuffer.slice(-TAG_LENGTH);
  const actualCiphertext = encryptedBuffer.slice(0, -TAG_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, secret, ivBuffer);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(actualCiphertext);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString("utf8");
}

// src/crypto/uuid.ts
function generateUUID() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = bytes[6] & 15 | 64;
    bytes[8] = bytes[8] & 63 | 128;
    const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20, 32)
    ].join("-");
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}

// src/utils/logger.ts
var LogLevel = /* @__PURE__ */ ((LogLevel3) => {
  LogLevel3[LogLevel3["DEBUG"] = 0] = "DEBUG";
  LogLevel3[LogLevel3["INFO"] = 1] = "INFO";
  LogLevel3[LogLevel3["WARN"] = 2] = "WARN";
  LogLevel3[LogLevel3["ERROR"] = 3] = "ERROR";
  LogLevel3[LogLevel3["NONE"] = 4] = "NONE";
  return LogLevel3;
})(LogLevel || {});
var Logger = class {
  config;
  constructor(config = {}) {
    this.config = {
      level: config.level ?? 1 /* INFO */,
      prefix: config.prefix ?? "[ChatSDK]",
      timestamp: config.timestamp ?? true
    };
  }
  shouldLog(level) {
    return level >= this.config.level;
  }
  formatMessage(level, message, data) {
    const parts = [];
    if (this.config.timestamp) {
      parts.push((/* @__PURE__ */ new Date()).toISOString());
    }
    parts.push(this.config.prefix);
    parts.push(`[${level}]`);
    parts.push(message);
    let formatted = parts.join(" ");
    if (data !== void 0) {
      formatted += " " + JSON.stringify(data, null, 2);
    }
    return formatted;
  }
  debug(message, data) {
    if (this.shouldLog(0 /* DEBUG */)) {
      console.debug(this.formatMessage("DEBUG", message, data));
    }
  }
  info(message, data) {
    if (this.shouldLog(1 /* INFO */)) {
      console.info(this.formatMessage("INFO", message, data));
    }
  }
  warn(message, data) {
    if (this.shouldLog(2 /* WARN */)) {
      console.warn(this.formatMessage("WARN", message, data));
    }
  }
  error(message, error) {
    if (this.shouldLog(3 /* ERROR */)) {
      const errorData = error instanceof Error ? { message: error.message, stack: error.stack } : error;
      console.error(this.formatMessage("ERROR", message, errorData));
    }
  }
  setLevel(level) {
    this.config.level = level;
  }
  getLevel() {
    return this.config.level;
  }
};
var logger = new Logger();

// src/chat/ChatSession.ts
var ChatSession = class {
  constructor(id, userA, userB, storageProvider) {
    this.id = id;
    this.userA = userA;
    this.userB = userB;
    this.storageProvider = storageProvider;
  }
  sharedSecret = null;
  ephemeralKeyPair = null;
  /**
   * Initialize the session by deriving the shared secret
   * ECDH is commutative, so we can use either user's keys
   */
  async initialize() {
    const localKeyPair = {
      publicKey: this.userA.publicKey,
      privateKey: this.userA.privateKey
    };
    this.sharedSecret = deriveSharedSecret(localKeyPair, this.userB.publicKey);
  }
  /**
   * Initialize from a specific user's perspective (useful when decrypting)
   */
  async initializeForUser(user) {
    const otherUser = user.id === this.userA.id ? this.userB : this.userA;
    const localKeyPair = {
      publicKey: user.publicKey,
      privateKey: user.privateKey
    };
    logger.debug(`[ChatSession] Initializing for user ${user.id}`, {
      hasLocalPriv: !!user.privateKey,
      privType: typeof user.privateKey,
      hasRemotePub: !!otherUser.publicKey,
      pubType: typeof otherUser.publicKey
    });
    this.sharedSecret = deriveSharedSecret(localKeyPair, otherUser.publicKey);
  }
  /**
   * Encrypt a message for this session
   */
  async encrypt(plaintext, senderId) {
    if (!this.sharedSecret) {
      await this.initialize();
    }
    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }
    const { ciphertext, iv } = encryptMessage(plaintext, this.sharedSecret);
    return {
      id: generateUUID(),
      senderId,
      receiverId: senderId === this.userA.id ? this.userB.id : this.userA.id,
      ciphertext,
      iv,
      timestamp: Date.now(),
      type: "text"
    };
  }
  /**
   * Encrypt a media message for this session
   */
  async encryptMedia(plaintext, media, senderId) {
    if (!this.sharedSecret) {
      await this.initialize();
    }
    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }
    const { ciphertext, iv } = encryptMessage(plaintext, this.sharedSecret);
    const { ciphertext: encryptedMediaData, iv: mediaIv } = encryptMessage(
      media.data || "",
      this.sharedSecret
    );
    const encryptedMedia = {
      ...media,
      data: encryptedMediaData,
      iv: mediaIv
    };
    if (this.storageProvider) {
      const filename = `${this.id}/${generateUUID()}-${media.metadata.filename}`;
      const uploadResult = await this.storageProvider.upload(
        encryptedMediaData,
        filename,
        media.metadata.mimeType
      );
      encryptedMedia.storage = this.storageProvider.name;
      encryptedMedia.storageKey = uploadResult.storageKey;
      encryptedMedia.url = uploadResult.url;
      encryptedMedia.data = void 0;
    }
    return {
      id: generateUUID(),
      senderId,
      receiverId: senderId === this.userA.id ? this.userB.id : this.userA.id,
      ciphertext,
      iv,
      timestamp: Date.now(),
      type: "media",
      media: encryptedMedia
    };
  }
  /**
   * Decrypt a message in this session
   */
  async decrypt(message, user) {
    if (!this.sharedSecret || user.id !== this.userA.id && user.id !== this.userB.id) {
      await this.initializeForUser(user);
    }
    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }
    try {
      return decryptMessage(message.ciphertext, message.iv, this.sharedSecret);
    } catch (error) {
      const legacySecret = this.deriveLegacySecret(user);
      try {
        return decryptMessage(message.ciphertext, message.iv, legacySecret);
      } catch (innerError) {
        throw error;
      }
    }
  }
  deriveLegacySecret(user) {
    const otherUser = user.id === this.userA.id ? this.userB : this.userA;
    logger.debug(`[ChatSession] Deriving legacy secret for user ${user.id}`, {
      hasPriv: !!user.privateKey,
      privType: typeof user.privateKey,
      remotePubType: typeof otherUser.publicKey
    });
    const localKeyPair = {
      publicKey: user.publicKey,
      privateKey: user.privateKey
    };
    return deriveLegacySharedSecret(localKeyPair, otherUser.publicKey);
  }
  /**
   * Decrypt a media message in this session
   */
  async decryptMedia(message, user) {
    if (!message.media) {
      throw new Error("Message does not contain media");
    }
    if (!this.sharedSecret || user.id !== this.userA.id && user.id !== this.userB.id) {
      await this.initializeForUser(user);
    }
    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }
    const text = decryptMessage(message.ciphertext, message.iv, this.sharedSecret);
    let encryptedMediaData = message.media.data;
    if (!encryptedMediaData && message.media.storageKey && this.storageProvider) {
      encryptedMediaData = await this.storageProvider.download(message.media.storageKey);
    }
    if (!message.media.iv && !encryptedMediaData) {
      throw new Error("Media data or IV missing");
    }
    let decryptedMediaData;
    try {
      decryptedMediaData = decryptMessage(
        encryptedMediaData || "",
        message.media.iv || message.iv,
        this.sharedSecret
      );
    } catch (error) {
      const legacySecret = this.deriveLegacySecret(user);
      try {
        decryptedMediaData = decryptMessage(
          encryptedMediaData || "",
          message.media.iv || message.iv,
          legacySecret
        );
      } catch (innerError) {
        throw error;
      }
    }
    const decryptedMedia = {
      ...message.media,
      data: decryptedMediaData
    };
    return { text, media: decryptedMedia };
  }
};

// src/crypto/group.ts
import { pbkdf2Sync as pbkdf2Sync2 } from "crypto";
var KEY_LENGTH2 = 32;
var PBKDF2_ITERATIONS2 = 1e5;
function deriveGroupKey(groupId) {
  const salt = Buffer.from(groupId, "utf8");
  const key = pbkdf2Sync2(groupId, salt, PBKDF2_ITERATIONS2, KEY_LENGTH2, "sha256");
  return {
    groupId,
    key: bufferToBase64(key)
  };
}

// src/chat/GroupSession.ts
var GroupSession = class {
  constructor(group, storageProvider) {
    this.group = group;
    this.storageProvider = storageProvider;
  }
  groupKey = null;
  /**
   * Initialize the session by deriving the group key
   */
  async initialize() {
    const groupKeyData = deriveGroupKey(this.group.id);
    this.groupKey = base64ToBuffer(groupKeyData.key);
  }
  /**
   * Encrypt a message for this group
   */
  async encrypt(plaintext, senderId) {
    if (!this.groupKey) {
      await this.initialize();
    }
    if (!this.groupKey) {
      throw new Error("Failed to initialize group session");
    }
    const { ciphertext, iv } = encryptMessage(plaintext, this.groupKey);
    return {
      id: generateUUID(),
      senderId,
      groupId: this.group.id,
      ciphertext,
      iv,
      timestamp: Date.now(),
      type: "text"
    };
  }
  /**
   * Encrypt a media message for this group
   */
  async encryptMedia(plaintext, media, senderId) {
    if (!this.groupKey) {
      await this.initialize();
    }
    if (!this.groupKey) {
      throw new Error("Failed to initialize group session");
    }
    const { ciphertext, iv } = encryptMessage(plaintext, this.groupKey);
    const { ciphertext: encryptedMediaData, iv: mediaIv } = encryptMessage(
      media.data || "",
      this.groupKey
    );
    const encryptedMedia = {
      ...media,
      data: encryptedMediaData,
      iv: mediaIv
    };
    if (this.storageProvider) {
      const filename = `groups/${this.group.id}/${generateUUID()}-${media.metadata.filename}`;
      const uploadResult = await this.storageProvider.upload(
        encryptedMediaData,
        filename,
        media.metadata.mimeType
      );
      encryptedMedia.storage = this.storageProvider.name;
      encryptedMedia.storageKey = uploadResult.storageKey;
      encryptedMedia.url = uploadResult.url;
      encryptedMedia.data = void 0;
    }
    return {
      id: generateUUID(),
      senderId,
      groupId: this.group.id,
      ciphertext,
      iv,
      timestamp: Date.now(),
      type: "media",
      media: encryptedMedia
    };
  }
  /**
   * Decrypt a message in this group
   */
  async decrypt(message) {
    if (!this.groupKey) {
      await this.initialize();
    }
    if (!this.groupKey) {
      throw new Error("Failed to initialize group session");
    }
    return decryptMessage(message.ciphertext, message.iv, this.groupKey);
  }
  /**
   * Decrypt a media message in this group
   */
  async decryptMedia(message) {
    if (!message.media) {
      throw new Error("Message does not contain media");
    }
    if (!this.groupKey) {
      await this.initialize();
    }
    if (!this.groupKey) {
      throw new Error("Failed to initialize group session");
    }
    const text = decryptMessage(message.ciphertext, message.iv, this.groupKey);
    let encryptedMediaData = message.media.data;
    if (!encryptedMediaData && message.media.storageKey && this.storageProvider) {
      encryptedMediaData = await this.storageProvider.download(message.media.storageKey);
    }
    if (!message.media.iv && !encryptedMediaData) {
      throw new Error("Media data or IV missing");
    }
    const decryptedMediaData = decryptMessage(
      encryptedMediaData || "",
      message.media.iv || message.iv,
      // Fallback to message IV for backward compatibility
      this.groupKey
    );
    const decryptedMedia = {
      ...message.media,
      data: decryptedMediaData
    };
    return { text, media: decryptedMedia };
  }
};

// src/utils/errors.ts
var SDKError = class extends Error {
  constructor(message, code, retryable = false, details) {
    super(message);
    this.code = code;
    this.retryable = retryable;
    this.details = details;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      retryable: this.retryable,
      details: this.details
    };
  }
};
var NetworkError = class extends SDKError {
  constructor(message, details) {
    super(message, "NETWORK_ERROR", true, details);
  }
};
var EncryptionError = class extends SDKError {
  constructor(message, details) {
    super(message, "ENCRYPTION_ERROR", false, details);
  }
};
var AuthError = class extends SDKError {
  constructor(message, details) {
    super(message, "AUTH_ERROR", false, details);
  }
};
var ValidationError = class extends SDKError {
  constructor(message, details) {
    super(message, "VALIDATION_ERROR", false, details);
  }
};
var StorageError = class extends SDKError {
  constructor(message, retryable = true, details) {
    super(message, "STORAGE_ERROR", retryable, details);
  }
};
var SessionError = class extends SDKError {
  constructor(message, details) {
    super(message, "SESSION_ERROR", false, details);
  }
};
var TransportError = class extends SDKError {
  constructor(message, retryable = true, details) {
    super(message, "TRANSPORT_ERROR", retryable, details);
  }
};
var ConfigError = class extends SDKError {
  constructor(message, details) {
    super(message, "CONFIG_ERROR", false, details);
  }
};

// src/utils/validation.ts
var USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/;
var MAX_MESSAGE_LENGTH = 1e4;
var MIN_GROUP_MEMBERS = 2;
var MAX_GROUP_MEMBERS = 256;
var MAX_GROUP_NAME_LENGTH = 100;
function validateUsername(username) {
  if (!username || typeof username !== "string") {
    throw new ValidationError("Username is required", { username });
  }
  if (!USERNAME_REGEX.test(username)) {
    throw new ValidationError(
      "Username must be 3-20 characters and contain only letters, numbers, underscores, and hyphens",
      { username }
    );
  }
}
function validateMessage(message) {
  if (!message || typeof message !== "string") {
    throw new ValidationError("Message content is required");
  }
  if (message.length === 0) {
    throw new ValidationError("Message cannot be empty");
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    throw new ValidationError(
      `Message exceeds maximum length of ${MAX_MESSAGE_LENGTH} characters`,
      { length: message.length, max: MAX_MESSAGE_LENGTH }
    );
  }
}
function validateGroupName(name) {
  if (!name || typeof name !== "string") {
    throw new ValidationError("Group name is required");
  }
  if (name.trim().length === 0) {
    throw new ValidationError("Group name cannot be empty");
  }
  if (name.length > MAX_GROUP_NAME_LENGTH) {
    throw new ValidationError(
      `Group name exceeds maximum length of ${MAX_GROUP_NAME_LENGTH} characters`,
      { length: name.length, max: MAX_GROUP_NAME_LENGTH }
    );
  }
}
function validateGroupMembers(memberCount) {
  if (memberCount < MIN_GROUP_MEMBERS) {
    throw new ValidationError(
      `Group must have at least ${MIN_GROUP_MEMBERS} members`,
      { count: memberCount, min: MIN_GROUP_MEMBERS }
    );
  }
  if (memberCount > MAX_GROUP_MEMBERS) {
    throw new ValidationError(
      `Group cannot have more than ${MAX_GROUP_MEMBERS} members`,
      { count: memberCount, max: MAX_GROUP_MEMBERS }
    );
  }
}
function validateUserId(userId) {
  if (!userId || typeof userId !== "string") {
    throw new ValidationError("User ID is required");
  }
  if (userId.trim().length === 0) {
    throw new ValidationError("User ID cannot be empty");
  }
}

// src/constants.ts
var SUPPORTED_CURVE2 = "prime256v1";
var ALGORITHM2 = "aes-256-gcm";
var IV_LENGTH2 = 12;
var SALT_LENGTH2 = 16;
var KEY_LENGTH3 = 32;
var TAG_LENGTH2 = 16;
var PBKDF2_ITERATIONS3 = 1e5;
var USERNAME_MIN_LENGTH = 3;
var USERNAME_MAX_LENGTH = 20;
var MESSAGE_MAX_LENGTH = 1e4;
var GROUP_NAME_MAX_LENGTH = 100;
var GROUP_MIN_MEMBERS = 2;
var GROUP_MAX_MEMBERS = 256;
var RECONNECT_MAX_ATTEMPTS = 5;
var RECONNECT_BASE_DELAY = 1e3;
var RECONNECT_MAX_DELAY = 3e4;
var HEARTBEAT_INTERVAL = 3e4;
var CONNECTION_TIMEOUT = 1e4;
var MAX_QUEUE_SIZE = 1e3;
var MESSAGE_RETRY_ATTEMPTS = 3;
var MESSAGE_RETRY_DELAY = 2e3;
var EVENTS = {
  MESSAGE_SENT: "message:sent",
  MESSAGE_RECEIVED: "message:received",
  MESSAGE_FAILED: "message:failed",
  CONNECTION_STATE_CHANGED: "connection:state",
  SESSION_CREATED: "session:created",
  GROUP_CREATED: "group:created",
  ERROR: "error",
  USER_CREATED: "user:created"
};
var ConnectionState = /* @__PURE__ */ ((ConnectionState2) => {
  ConnectionState2["DISCONNECTED"] = "disconnected";
  ConnectionState2["CONNECTING"] = "connecting";
  ConnectionState2["CONNECTED"] = "connected";
  ConnectionState2["RECONNECTING"] = "reconnecting";
  ConnectionState2["FAILED"] = "failed";
  return ConnectionState2;
})(ConnectionState || {});
var MessageStatus = /* @__PURE__ */ ((MessageStatus2) => {
  MessageStatus2["PENDING"] = "pending";
  MessageStatus2["SENT"] = "sent";
  MessageStatus2["DELIVERED"] = "delivered";
  MessageStatus2["FAILED"] = "failed";
  return MessageStatus2;
})(MessageStatus || {});

// src/utils/messageQueue.ts
var MessageQueue = class {
  queue = /* @__PURE__ */ new Map();
  maxSize;
  maxRetries;
  retryDelay;
  constructor(maxSize = MAX_QUEUE_SIZE, maxRetries = MESSAGE_RETRY_ATTEMPTS, retryDelay = MESSAGE_RETRY_DELAY) {
    this.maxSize = maxSize;
    this.maxRetries = maxRetries;
    this.retryDelay = retryDelay;
  }
  /**
   * Add a message to the queue
   */
  enqueue(message) {
    if (this.queue.size >= this.maxSize) {
      logger.warn("Message queue is full, removing oldest message");
      const firstKey = this.queue.keys().next().value;
      if (firstKey) {
        this.queue.delete(firstKey);
      }
    }
    this.queue.set(message.id, {
      message,
      status: "pending" /* PENDING */,
      attempts: 0
    });
    logger.debug("Message enqueued", { messageId: message.id });
  }
  /**
   * Mark a message as sent
   */
  markSent(messageId) {
    const queued = this.queue.get(messageId);
    if (queued) {
      queued.status = "sent" /* SENT */;
      logger.debug("Message marked as sent", { messageId });
      this.queue.delete(messageId);
    }
  }
  /**
   * Mark a message as failed
   */
  markFailed(messageId, error) {
    const queued = this.queue.get(messageId);
    if (queued) {
      queued.status = "failed" /* FAILED */;
      queued.error = error;
      queued.attempts++;
      queued.lastAttempt = Date.now();
      logger.warn("Message failed", {
        messageId,
        attempts: queued.attempts,
        error: error.message
      });
      if (queued.attempts >= this.maxRetries) {
        logger.error("Message exceeded max retries, removing from queue", {
          messageId,
          attempts: queued.attempts
        });
        this.queue.delete(messageId);
      }
    }
  }
  /**
   * Get messages that need to be retried
   */
  getRetryableMessages() {
    const now = Date.now();
    const retryable = [];
    for (const queued of this.queue.values()) {
      if (queued.status === "failed" /* FAILED */ && queued.attempts < this.maxRetries && (!queued.lastAttempt || now - queued.lastAttempt >= this.retryDelay)) {
        retryable.push(queued);
      }
    }
    return retryable;
  }
  /**
   * Get all pending messages
   */
  getPendingMessages() {
    return Array.from(this.queue.values()).filter(
      (q) => q.status === "pending" /* PENDING */
    );
  }
  /**
   * Get queue size
   */
  size() {
    return this.queue.size;
  }
  /**
   * Clear the queue
   */
  clear() {
    this.queue.clear();
    logger.debug("Message queue cleared");
  }
  /**
   * Get message by ID
   */
  get(messageId) {
    return this.queue.get(messageId);
  }
  /**
   * Remove message from queue
   */
  remove(messageId) {
    this.queue.delete(messageId);
    logger.debug("Message removed from queue", { messageId });
  }
  /**
   * Get all messages in queue
   */
  getAll() {
    return Array.from(this.queue.values());
  }
};

// src/stores/memory/userStore.ts
var InMemoryUserStore = class {
  users = /* @__PURE__ */ new Map();
  async create(user) {
    const stored = { ...user, createdAt: Date.now() };
    this.users.set(stored.id, stored);
    return stored;
  }
  async findById(id) {
    return this.users.get(id);
  }
  async save(user) {
    this.users.set(user.id, user);
  }
  async list() {
    return Array.from(this.users.values());
  }
};

// src/stores/memory/messageStore.ts
var InMemoryMessageStore = class {
  messages = [];
  async create(message) {
    this.messages.push(message);
    return message;
  }
  async findById(id) {
    return this.messages.find((msg) => msg.id === id);
  }
  async listByUser(userId) {
    return this.messages.filter(
      (msg) => msg.senderId === userId || msg.receiverId === userId
    );
  }
  async listByGroup(groupId) {
    return this.messages.filter((msg) => msg.groupId === groupId);
  }
  async delete(id) {
    this.messages = this.messages.filter((msg) => msg.id !== id);
  }
};

// src/stores/memory/groupStore.ts
var InMemoryGroupStore = class {
  groups = /* @__PURE__ */ new Map();
  async create(group) {
    this.groups.set(group.id, group);
    return group;
  }
  async findById(id) {
    return this.groups.get(id);
  }
  async list() {
    return Array.from(this.groups.values());
  }
};

// src/transport/memoryTransport.ts
var InMemoryTransport = class {
  messageHandler = null;
  connectionState = "disconnected" /* DISCONNECTED */;
  stateHandler = null;
  errorHandler = null;
  async connect(userId) {
    this.connectionState = "connected" /* CONNECTED */;
    if (this.stateHandler) {
      this.stateHandler(this.connectionState);
    }
  }
  async disconnect() {
    this.connectionState = "disconnected" /* DISCONNECTED */;
    if (this.stateHandler) {
      this.stateHandler(this.connectionState);
    }
  }
  async reconnect() {
    this.connectionState = "connecting" /* CONNECTING */;
    if (this.stateHandler) {
      this.stateHandler(this.connectionState);
    }
    await new Promise((resolve2) => setTimeout(resolve2, 100));
    this.connectionState = "connected" /* CONNECTED */;
    if (this.stateHandler) {
      this.stateHandler(this.connectionState);
    }
  }
  async send(message) {
    if (this.messageHandler) {
      setTimeout(() => {
        this.messageHandler(message);
      }, 10);
    }
  }
  onMessage(handler) {
    this.messageHandler = handler;
  }
  onConnectionStateChange(handler) {
    this.stateHandler = handler;
  }
  onError(handler) {
    this.errorHandler = handler;
  }
  getConnectionState() {
    return this.connectionState;
  }
  isConnected() {
    return this.connectionState === "connected" /* CONNECTED */;
  }
  // Test helper to simulate receiving a message
  simulateReceive(message) {
    if (this.messageHandler) {
      this.messageHandler(message);
    }
  }
  // Test helper to simulate an error
  simulateError(error) {
    if (this.errorHandler) {
      this.errorHandler(error);
    }
  }
};

// src/transport/websocketClient.ts
var WebSocketClient = class {
  ws = null;
  url;
  messageHandler = null;
  stateHandler = null;
  errorHandler = null;
  connectionState = "disconnected" /* DISCONNECTED */;
  reconnectAttempts = 0;
  reconnectTimer = null;
  heartbeatTimer = null;
  currentUserId = null;
  shouldReconnect = true;
  constructor(url) {
    this.url = url;
  }
  async connect(userId) {
    this.currentUserId = userId;
    this.shouldReconnect = true;
    return this.doConnect();
  }
  async doConnect() {
    if (this.connectionState === "connecting" /* CONNECTING */) {
      logger.warn("Already connecting, skipping duplicate connect attempt");
      return;
    }
    this.updateState("connecting" /* CONNECTING */);
    logger.info("Connecting to WebSocket", { url: this.url, userId: this.currentUserId });
    return new Promise((resolve2, reject) => {
      try {
        const wsUrl = this.currentUserId ? `${this.url}?userId=${this.currentUserId}` : this.url;
        this.ws = new WebSocket(wsUrl);
        const connectionTimeout = setTimeout(() => {
          if (this.connectionState === "connecting" /* CONNECTING */) {
            this.ws?.close();
            const error = new NetworkError("Connection timeout");
            this.handleError(error);
            reject(error);
          }
        }, CONNECTION_TIMEOUT);
        this.ws.onopen = () => {
          clearTimeout(connectionTimeout);
          this.reconnectAttempts = 0;
          this.updateState("connected" /* CONNECTED */);
          logger.info("WebSocket connected");
          this.startHeartbeat();
          resolve2();
        };
        this.ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            if (message.type === "pong") {
              logger.debug("Received pong");
              return;
            }
            if (this.messageHandler) {
              this.messageHandler(message);
            }
          } catch (error) {
            const parseError = new TransportError(
              "Failed to parse message",
              false,
              { error: error instanceof Error ? error.message : String(error) }
            );
            logger.error("Message parse error", parseError);
            this.handleError(parseError);
          }
        };
        this.ws.onerror = (event) => {
          clearTimeout(connectionTimeout);
          const error = new NetworkError("WebSocket error", {
            event: event.type
          });
          logger.error("WebSocket error", error);
          this.handleError(error);
          reject(error);
        };
        this.ws.onclose = (event) => {
          clearTimeout(connectionTimeout);
          this.stopHeartbeat();
          logger.info("WebSocket closed", {
            code: event.code,
            reason: event.reason,
            wasClean: event.wasClean
          });
          if (this.connectionState !== "disconnected" /* DISCONNECTED */) {
            this.updateState("disconnected" /* DISCONNECTED */);
            if (this.shouldReconnect && this.reconnectAttempts < RECONNECT_MAX_ATTEMPTS) {
              this.scheduleReconnect();
            } else if (this.reconnectAttempts >= RECONNECT_MAX_ATTEMPTS) {
              this.updateState("failed" /* FAILED */);
              const error = new NetworkError("Max reconnection attempts exceeded");
              this.handleError(error);
            }
          }
        };
      } catch (error) {
        const connectError = new NetworkError(
          "Failed to create WebSocket connection",
          { error: error instanceof Error ? error.message : String(error) }
        );
        logger.error("Connection error", connectError);
        this.handleError(connectError);
        reject(connectError);
      }
    });
  }
  async disconnect() {
    logger.info("Disconnecting WebSocket");
    this.shouldReconnect = false;
    this.clearReconnectTimer();
    this.stopHeartbeat();
    if (this.ws) {
      this.ws.close(1e3, "Client disconnect");
      this.ws = null;
    }
    this.updateState("disconnected" /* DISCONNECTED */);
  }
  async reconnect() {
    logger.info("Manual reconnect requested");
    this.reconnectAttempts = 0;
    this.shouldReconnect = true;
    await this.disconnect();
    if (this.currentUserId) {
      await this.doConnect();
    } else {
      throw new TransportError("Cannot reconnect: no user ID set");
    }
  }
  scheduleReconnect() {
    this.clearReconnectTimer();
    this.reconnectAttempts++;
    const delay = Math.min(
      RECONNECT_BASE_DELAY * Math.pow(2, this.reconnectAttempts - 1),
      RECONNECT_MAX_DELAY
    );
    const jitter = Math.random() * 1e3;
    const totalDelay = delay + jitter;
    logger.info("Scheduling reconnect", {
      attempt: this.reconnectAttempts,
      delay: totalDelay
    });
    this.updateState("reconnecting" /* RECONNECTING */);
    this.reconnectTimer = setTimeout(async () => {
      try {
        await this.doConnect();
      } catch (error) {
        logger.error("Reconnect failed", error);
      }
    }, totalDelay);
  }
  clearReconnectTimer() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
  startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected()) {
        try {
          this.ws?.send(JSON.stringify({ type: "ping" }));
          logger.debug("Sent ping");
        } catch (error) {
          logger.error("Failed to send heartbeat", error);
        }
      }
    }, HEARTBEAT_INTERVAL);
  }
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
  async send(message) {
    if (!this.isConnected() || !this.ws) {
      throw new NetworkError("WebSocket not connected");
    }
    try {
      this.ws.send(JSON.stringify(message));
      logger.debug("Message sent", { messageId: message.id });
    } catch (error) {
      const sendError = new NetworkError(
        "Failed to send message",
        { error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("Send error", sendError);
      throw sendError;
    }
  }
  onMessage(handler) {
    this.messageHandler = handler;
  }
  onConnectionStateChange(handler) {
    this.stateHandler = handler;
  }
  onError(handler) {
    this.errorHandler = handler;
  }
  getConnectionState() {
    return this.connectionState;
  }
  isConnected() {
    return this.connectionState === "connected" /* CONNECTED */ && this.ws?.readyState === WebSocket.OPEN;
  }
  updateState(newState) {
    if (this.connectionState !== newState) {
      const oldState = this.connectionState;
      this.connectionState = newState;
      logger.info("Connection state changed", {
        from: oldState,
        to: newState
      });
      if (this.stateHandler) {
        this.stateHandler(newState);
      }
    }
  }
  handleError(error) {
    if (this.errorHandler) {
      this.errorHandler(error);
    }
  }
};

// src/models/mediaTypes.ts
var MediaType = /* @__PURE__ */ ((MediaType2) => {
  MediaType2["IMAGE"] = "image";
  MediaType2["AUDIO"] = "audio";
  MediaType2["VIDEO"] = "video";
  MediaType2["DOCUMENT"] = "document";
  return MediaType2;
})(MediaType || {});
var SUPPORTED_MIME_TYPES = {
  image: ["image/jpeg", "image/png", "image/gif", "image/webp"],
  audio: ["audio/mpeg", "audio/mp4", "audio/ogg", "audio/wav", "audio/webm"],
  video: ["video/mp4", "video/webm", "video/ogg"],
  document: [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain"
  ]
};
var FILE_SIZE_LIMITS = {
  image: 10 * 1024 * 1024,
  // 10 MB
  audio: 16 * 1024 * 1024,
  // 16 MB
  video: 100 * 1024 * 1024,
  // 100 MB
  document: 100 * 1024 * 1024
  // 100 MB
};

// src/utils/mediaUtils.ts
async function encodeFileToBase64(file) {
  return new Promise((resolve2, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (!result) {
        reject(new Error("Failed to read file: result is null"));
        return;
      }
      const base64 = result.split(",")[1];
      if (!base64) {
        reject(new Error("Failed to extract base64 data"));
        return;
      }
      resolve2(base64);
    };
    reader.onerror = () => reject(new Error("Failed to read file"));
    reader.readAsDataURL(file);
  });
}
function decodeBase64ToBlob(base64, mimeType) {
  const byteCharacters = atob(base64);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  return new Blob([byteArray], { type: mimeType });
}
function getMediaType(mimeType) {
  if (SUPPORTED_MIME_TYPES.image.includes(mimeType)) {
    return "image" /* IMAGE */;
  }
  if (SUPPORTED_MIME_TYPES.audio.includes(mimeType)) {
    return "audio" /* AUDIO */;
  }
  if (SUPPORTED_MIME_TYPES.video.includes(mimeType)) {
    return "video" /* VIDEO */;
  }
  if (SUPPORTED_MIME_TYPES.document.includes(mimeType)) {
    return "document" /* DOCUMENT */;
  }
  throw new ValidationError(`Unsupported MIME type: ${mimeType}`);
}
function validateMediaFile(file, filename) {
  const mimeType = file.type;
  const mediaType = getMediaType(mimeType);
  const maxSize = FILE_SIZE_LIMITS[mediaType];
  if (file.size > maxSize) {
    throw new ValidationError(
      `File size exceeds limit. Max size for ${mediaType}: ${maxSize / 1024 / 1024}MB`
    );
  }
  if (filename && filename.length > 255) {
    throw new ValidationError("Filename too long (max 255 characters)");
  }
}
async function createMediaMetadata(file, filename) {
  const actualFilename = filename || (file instanceof File ? file.name : "file");
  const metadata = {
    filename: actualFilename,
    mimeType: file.type,
    size: file.size
  };
  if (file.type.startsWith("image/")) {
    try {
      const dimensions = await getImageDimensions(file);
      metadata.width = dimensions.width;
      metadata.height = dimensions.height;
      metadata.thumbnail = await generateThumbnail(file);
    } catch (error) {
    }
  }
  return metadata;
}
function getImageDimensions(file) {
  return new Promise((resolve2, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve2({ width: img.width, height: img.height });
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("Failed to load image"));
    };
    img.src = url;
  });
}
async function generateThumbnail(file) {
  return new Promise((resolve2, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      const maxSize = 200;
      let width = img.width;
      let height = img.height;
      if (width > height) {
        if (width > maxSize) {
          height = height * maxSize / width;
          width = maxSize;
        }
      } else {
        if (height > maxSize) {
          width = width * maxSize / height;
          height = maxSize;
        }
      }
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      if (!ctx) {
        reject(new Error("Failed to get canvas context"));
        return;
      }
      ctx.drawImage(img, 0, 0, width, height);
      const dataUrl = canvas.toDataURL("image/jpeg", 0.7);
      const thumbnail = dataUrl.split(",")[1];
      if (!thumbnail) {
        reject(new Error("Failed to generate thumbnail"));
        return;
      }
      resolve2(thumbnail);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("Failed to load image for thumbnail"));
    };
    img.src = url;
  });
}
async function createMediaAttachment(file, filename) {
  validateMediaFile(file, filename);
  const mediaType = getMediaType(file.type);
  const data = await encodeFileToBase64(file);
  const metadata = await createMediaMetadata(file, filename);
  return {
    type: mediaType,
    data,
    metadata
  };
}
function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

// src/storage/localStorage.ts
import { promises as fs } from "fs";
import * as path from "path";
var LocalStorageProvider = class {
  name = "local";
  storageDir;
  constructor(storageDir = "./storage") {
    this.storageDir = path.resolve(storageDir);
    fs.mkdir(this.storageDir, { recursive: true }).catch(() => {
    });
  }
  async upload(data, filename, mimeType) {
    const buffer = typeof data === "string" ? Buffer.from(data, "base64") : data;
    const filePath = path.join(this.storageDir, filename);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, buffer);
    return {
      storageKey: filename,
      url: `file://${filePath}`
    };
  }
  async download(storageKey) {
    const filePath = path.join(this.storageDir, storageKey);
    const buffer = await fs.readFile(filePath);
    return buffer.toString("base64");
  }
  async delete(storageKey) {
    const filePath = path.join(this.storageDir, storageKey);
    try {
      await fs.unlink(filePath);
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
    }
  }
};

// src/storage/s3Storage.ts
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
var S3StorageProvider = class {
  name = "s3";
  client;
  bucket;
  constructor(config) {
    const s3Config = {
      region: config.region,
      forcePathStyle: config.forcePathStyle
    };
    if (config.credentials) {
      s3Config.credentials = config.credentials;
    }
    if (config.endpoint) {
      s3Config.endpoint = config.endpoint;
    }
    this.client = new S3Client(s3Config);
    this.bucket = config.bucket;
  }
  async upload(data, filename, mimeType) {
    const body = typeof data === "string" ? Buffer.from(data, "base64") : data;
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: filename,
        Body: body,
        ContentType: mimeType
      })
    );
    return {
      storageKey: filename,
      url: `https://${this.bucket}.s3.amazonaws.com/${filename}`
    };
  }
  async download(storageKey) {
    const response = await this.client.send(
      new GetObjectCommand({
        Bucket: this.bucket,
        Key: storageKey
      })
    );
    if (!response.Body) {
      throw new Error("S3 download failed: empty body");
    }
    const bytes = await response.Body.transformToByteArray();
    return Buffer.from(bytes).toString("base64");
  }
  async delete(storageKey) {
    await this.client.send(
      new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: storageKey
      })
    );
  }
};

// src/index.ts
var ChatSDK = class extends EventEmitter {
  config;
  currentUser = null;
  messageQueue;
  constructor(config) {
    super();
    this.config = config;
    this.messageQueue = new MessageQueue();
    if (config.logLevel !== void 0) {
      logger.setLevel(config.logLevel);
    }
    if (this.config.transport) {
      this.setupTransportHandlers();
    }
    logger.info("ChatSDK initialized");
  }
  setupTransportHandlers() {
    if (!this.config.transport) return;
    this.config.transport.onMessage((message) => {
      logger.debug("Message received via transport", { messageId: message.id });
      this.emit(EVENTS.MESSAGE_RECEIVED, message);
      this.config.messageStore.create(message).catch((error) => {
        logger.error("Failed to store received message", error);
      });
    });
    if (this.config.transport.onConnectionStateChange) {
      this.config.transport.onConnectionStateChange((state) => {
        logger.info("Connection state changed", { state });
        this.emit(EVENTS.CONNECTION_STATE_CHANGED, state);
        if (state === "connected" /* CONNECTED */) {
          this.processMessageQueue();
        }
      });
    }
    if (this.config.transport.onError) {
      this.config.transport.onError((error) => {
        logger.error("Transport error", error);
        this.emit(EVENTS.ERROR, error);
      });
    }
  }
  async processMessageQueue() {
    const pending = this.messageQueue.getPendingMessages();
    const retryable = this.messageQueue.getRetryableMessages();
    const toSend = [...pending, ...retryable];
    logger.info("Processing message queue", { count: toSend.length });
    for (const queued of toSend) {
      try {
        await this.config.transport.send(queued.message);
        this.messageQueue.markSent(queued.message.id);
        this.emit(EVENTS.MESSAGE_SENT, queued.message);
      } catch (error) {
        this.messageQueue.markFailed(
          queued.message.id,
          error instanceof Error ? error : new Error(String(error))
        );
        this.emit(EVENTS.MESSAGE_FAILED, queued.message, error);
      }
    }
  }
  /**
   * Create a new user with generated identity keys
   */
  async createUser(username) {
    validateUsername(username);
    const keyPair = generateIdentityKeyPair();
    const user = {
      id: generateUUID(),
      username,
      identityKey: keyPair.publicKey,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey
    };
    try {
      await this.config.userStore.create(user);
      logger.info("User created", { userId: user.id, username: user.username });
      this.emit(EVENTS.USER_CREATED, user);
      return user;
    } catch (error) {
      const storageError = new StorageError(
        "Failed to create user",
        true,
        { username, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("User creation failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  /**
   * Import an existing user from stored data
   */
  async importUser(userData) {
    try {
      await this.config.userStore.save(userData);
      logger.info("User imported", { userId: userData.id });
      return userData;
    } catch (error) {
      const storageError = new StorageError(
        "Failed to import user",
        true,
        { userId: userData.id, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("User import failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  /**
   * Set the current active user
   */
  async setCurrentUser(user) {
    this.currentUser = user;
    logger.info("Current user set", { userId: user.id, username: user.username });
    if (this.config.transport) {
      try {
        await this.config.transport.connect(user.id);
      } catch (error) {
        const transportError = new TransportError(
          "Failed to connect transport",
          true,
          { userId: user.id, error: error instanceof Error ? error.message : String(error) }
        );
        logger.error("Transport connection failed", transportError);
        this.emit(EVENTS.ERROR, transportError);
        throw transportError;
      }
    }
  }
  /**
   * Get the current active user
   */
  getCurrentUser() {
    return this.currentUser;
  }
  /**
   * Start a 1:1 chat session between two users
   */
  async startSession(userA, userB) {
    const ids = [userA.id, userB.id].sort();
    const sessionId = `${ids[0]}-${ids[1]}`;
    try {
      const session = new ChatSession(sessionId, userA, userB, this.config.storageProvider);
      await session.initialize();
      logger.info("Chat session created", { sessionId, users: [userA.id, userB.id] });
      this.emit(EVENTS.SESSION_CREATED, session);
      return session;
    } catch (error) {
      const sessionError = new SessionError(
        "Failed to create chat session",
        { sessionId, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("Session creation failed", sessionError);
      this.emit(EVENTS.ERROR, sessionError);
      throw sessionError;
    }
  }
  /**
   * Create a new group with members
   */
  async createGroup(name, members) {
    validateGroupName(name);
    validateGroupMembers(members.length);
    const group = {
      id: generateUUID(),
      name,
      members,
      createdAt: Date.now()
    };
    try {
      await this.config.groupStore.create(group);
      const session = new GroupSession(group, this.config.storageProvider);
      await session.initialize();
      logger.info("Group created", { groupId: group.id, name: group.name, memberCount: members.length });
      this.emit(EVENTS.GROUP_CREATED, session);
      return session;
    } catch (error) {
      const storageError = new StorageError(
        "Failed to create group",
        true,
        { groupName: name, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("Group creation failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  /**
   * Load an existing group by ID
   */
  async loadGroup(id) {
    try {
      const group = await this.config.groupStore.findById(id);
      if (!group) {
        throw new SessionError(`Group not found: ${id}`, { groupId: id });
      }
      const session = new GroupSession(group, this.config.storageProvider);
      await session.initialize();
      logger.debug("Group loaded", { groupId: id });
      return session;
    } catch (error) {
      if (error instanceof SessionError) {
        this.emit(EVENTS.ERROR, error);
        throw error;
      }
      const storageError = new StorageError(
        "Failed to load group",
        true,
        { groupId: id, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("Group load failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  /**
   * Send a message in a chat session (1:1 or group)
   */
  async sendMessage(session, plaintext) {
    if (!this.currentUser) {
      throw new SessionError("No current user set. Call setCurrentUser() first.");
    }
    validateMessage(plaintext);
    let message;
    try {
      if (session instanceof ChatSession) {
        message = await session.encrypt(plaintext, this.currentUser.id);
      } else {
        message = await session.encrypt(plaintext, this.currentUser.id);
      }
      await this.config.messageStore.create(message);
      logger.debug("Message stored", { messageId: message.id });
      if (this.config.transport) {
        if (this.config.transport.isConnected()) {
          try {
            await this.config.transport.send(message);
            logger.debug("Message sent via transport", { messageId: message.id });
            this.emit(EVENTS.MESSAGE_SENT, message);
          } catch (error) {
            this.messageQueue.enqueue(message);
            this.messageQueue.markFailed(
              message.id,
              error instanceof Error ? error : new Error(String(error))
            );
            logger.warn("Message send failed, queued for retry", { messageId: message.id });
            this.emit(EVENTS.MESSAGE_FAILED, message, error);
          }
        } else {
          this.messageQueue.enqueue(message);
          logger.info("Message queued (offline)", { messageId: message.id });
        }
      }
      return message;
    } catch (error) {
      const sendError = error instanceof Error ? error : new Error(String(error));
      logger.error("Failed to send message", sendError);
      this.emit(EVENTS.ERROR, sendError);
      throw sendError;
    }
  }
  /**
   * Send a media message in a chat session (1:1 or group)
   */
  async sendMediaMessage(session, caption, media) {
    if (!this.currentUser) {
      throw new SessionError("No current user set. Call setCurrentUser() first.");
    }
    let message;
    try {
      if (session instanceof ChatSession) {
        message = await session.encryptMedia(caption, media, this.currentUser.id);
      } else {
        message = await session.encryptMedia(caption, media, this.currentUser.id);
      }
      await this.config.messageStore.create(message);
      logger.debug("Media message stored", { messageId: message.id, mediaType: media.type });
      if (this.config.transport) {
        if (this.config.transport.isConnected()) {
          try {
            await this.config.transport.send(message);
            logger.debug("Media message sent via transport", { messageId: message.id });
            this.emit(EVENTS.MESSAGE_SENT, message);
          } catch (error) {
            this.messageQueue.enqueue(message);
            this.messageQueue.markFailed(
              message.id,
              error instanceof Error ? error : new Error(String(error))
            );
            logger.warn("Media message send failed, queued for retry", { messageId: message.id });
            this.emit(EVENTS.MESSAGE_FAILED, message, error);
          }
        } else {
          this.messageQueue.enqueue(message);
          logger.info("Media message queued (offline)", { messageId: message.id });
        }
      }
      return message;
    } catch (error) {
      const sendError = error instanceof Error ? error : new Error(String(error));
      logger.error("Failed to send media message", sendError);
      this.emit(EVENTS.ERROR, sendError);
      throw sendError;
    }
  }
  /**
   * Decrypt a message
   */
  async decryptMessage(message, user) {
    try {
      if (message.groupId) {
        const group = await this.config.groupStore.findById(message.groupId);
        if (!group) {
          throw new SessionError(`Group not found: ${message.groupId}`, { groupId: message.groupId });
        }
        const session = new GroupSession(group);
        await session.initialize();
        return await session.decrypt(message);
      } else {
        const otherUserId = message.senderId === user.id ? message.receiverId : message.senderId;
        if (!otherUserId) {
          throw new SessionError("Invalid message: missing receiver/sender");
        }
        const otherUser = await this.config.userStore.findById(otherUserId);
        if (!otherUser) {
          throw new SessionError(`User not found: ${otherUserId}`, { userId: otherUserId });
        }
        const ids = [user.id, otherUser.id].sort();
        const sessionId = `${ids[0]}-${ids[1]}`;
        const session = new ChatSession(sessionId, user, otherUser, this.config.storageProvider);
        await session.initializeForUser(user);
        return await session.decrypt(message, user);
      }
    } catch (error) {
      const decryptError = error instanceof Error ? error : new Error(String(error));
      logger.error("Failed to decrypt message", decryptError);
      this.emit(EVENTS.ERROR, decryptError);
      throw decryptError;
    }
  }
  /**
   * Decrypt a media message
   */
  async decryptMediaMessage(message, user) {
    if (!message.media) {
      throw new SessionError("Message does not contain media");
    }
    try {
      if (message.groupId) {
        const group = await this.config.groupStore.findById(message.groupId);
        if (!group) {
          throw new SessionError(`Group not found: ${message.groupId}`, { groupId: message.groupId });
        }
        const session = new GroupSession(group, this.config.storageProvider);
        await session.initialize();
        return await session.decryptMedia(message);
      } else {
        const otherUserId = message.senderId === user.id ? message.receiverId : message.senderId;
        if (!otherUserId) {
          throw new SessionError("Invalid message: missing receiver/sender");
        }
        const otherUser = await this.config.userStore.findById(otherUserId);
        if (!otherUser) {
          throw new SessionError(`User not found: ${otherUserId}`, { userId: otherUserId });
        }
        const ids = [user.id, otherUser.id].sort();
        const sessionId = `${ids[0]}-${ids[1]}`;
        const session = new ChatSession(sessionId, user, otherUser, this.config.storageProvider);
        await session.initializeForUser(user);
        return await session.decryptMedia(message, user);
      }
    } catch (error) {
      const decryptError = error instanceof Error ? error : new Error(String(error));
      logger.error("Failed to decrypt media message", decryptError);
      this.emit(EVENTS.ERROR, decryptError);
      throw decryptError;
    }
  }
  /**
   * Get messages for a user
   */
  async getMessagesForUser(userId) {
    try {
      return await this.config.messageStore.listByUser(userId);
    } catch (error) {
      const storageError = new StorageError(
        "Failed to get messages for user",
        true,
        { userId, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("Get messages failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  /**
   * Get messages for a group
   */
  async getMessagesForGroup(groupId) {
    try {
      return await this.config.messageStore.listByGroup(groupId);
    } catch (error) {
      const storageError = new StorageError(
        "Failed to get messages for group",
        true,
        { groupId, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("Get messages failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  // ========== Public Accessor Methods ==========
  /**
   * Get the transport adapter
   */
  getTransport() {
    return this.config.transport;
  }
  /**
   * Get all users
   */
  async listUsers() {
    try {
      return await this.config.userStore.list();
    } catch (error) {
      const storageError = new StorageError(
        "Failed to list users",
        true,
        { error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("List users failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  /**
   * Get user by ID
   */
  async getUserById(userId) {
    try {
      return await this.config.userStore.findById(userId);
    } catch (error) {
      const storageError = new StorageError(
        "Failed to get user",
        true,
        { userId, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("Get user failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  /**
   * Get all groups
   */
  async listGroups() {
    try {
      return await this.config.groupStore.list();
    } catch (error) {
      const storageError = new StorageError(
        "Failed to list groups",
        true,
        { error: error instanceof Error ? error.message : String(error) }
      );
      logger.error("List groups failed", storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }
  /**
   * Get connection state
   */
  getConnectionState() {
    if (!this.config.transport) {
      return "disconnected" /* DISCONNECTED */;
    }
    return this.config.transport.getConnectionState();
  }
  /**
   * Check if connected
   */
  isConnected() {
    if (!this.config.transport) {
      return false;
    }
    return this.config.transport.isConnected();
  }
  /**
   * Disconnect transport
   */
  async disconnect() {
    if (this.config.transport) {
      await this.config.transport.disconnect();
      logger.info("Transport disconnected");
    }
  }
  /**
   * Reconnect transport
   */
  async reconnect() {
    if (this.config.transport) {
      await this.config.transport.reconnect();
      logger.info("Transport reconnected");
    }
  }
  /**
   * Get message queue status
   */
  getQueueStatus() {
    return {
      size: this.messageQueue.size(),
      pending: this.messageQueue.getPendingMessages().length,
      retryable: this.messageQueue.getRetryableMessages().length
    };
  }
};
export {
  ALGORITHM2 as ALGORITHM,
  AuthError,
  CONNECTION_TIMEOUT,
  ChatSDK,
  ChatSession,
  ConfigError,
  ConnectionState,
  EVENTS,
  EncryptionError,
  FILE_SIZE_LIMITS,
  GROUP_MAX_MEMBERS,
  GROUP_MIN_MEMBERS,
  GROUP_NAME_MAX_LENGTH,
  GroupSession,
  HEARTBEAT_INTERVAL,
  IV_LENGTH2 as IV_LENGTH,
  InMemoryGroupStore,
  InMemoryMessageStore,
  InMemoryTransport,
  InMemoryUserStore,
  KEY_LENGTH3 as KEY_LENGTH,
  LocalStorageProvider,
  LogLevel,
  Logger,
  MAX_QUEUE_SIZE,
  MESSAGE_MAX_LENGTH,
  MESSAGE_RETRY_ATTEMPTS,
  MESSAGE_RETRY_DELAY,
  MediaType,
  MessageStatus,
  NetworkError,
  PBKDF2_ITERATIONS3 as PBKDF2_ITERATIONS,
  RECONNECT_BASE_DELAY,
  RECONNECT_MAX_ATTEMPTS,
  RECONNECT_MAX_DELAY,
  S3StorageProvider,
  SALT_LENGTH2 as SALT_LENGTH,
  SDKError,
  SUPPORTED_CURVE2 as SUPPORTED_CURVE,
  SUPPORTED_MIME_TYPES,
  SessionError,
  StorageError,
  TAG_LENGTH2 as TAG_LENGTH,
  TransportError,
  USERNAME_MAX_LENGTH,
  USERNAME_MIN_LENGTH,
  ValidationError,
  WebSocketClient,
  createMediaAttachment,
  createMediaMetadata,
  decodeBase64ToBlob,
  encodeFileToBase64,
  formatFileSize,
  getMediaType,
  logger,
  validateGroupMembers,
  validateGroupName,
  validateMediaFile,
  validateMessage,
  validateUserId,
  validateUsername
};
