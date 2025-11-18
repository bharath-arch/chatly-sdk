// src/crypto/e2e.ts
import { createECDH as createECDH2, createCipheriv, createDecipheriv, randomBytes as randomBytes2, pbkdf2Sync } from "crypto";

// src/crypto/utils.ts
function bufferToBase64(buffer) {
  return buffer.toString("base64");
}
function base64ToBuffer(data) {
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

// src/chat/ChatSession.ts
var ChatSession = class {
  constructor(id, userA, userB) {
    this.id = id;
    this.userA = userA;
    this.userB = userB;
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
   * Decrypt a message in this session
   */
  async decrypt(message, user) {
    if (!this.sharedSecret || user.id !== this.userA.id && user.id !== this.userB.id) {
      await this.initializeForUser(user);
    }
    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }
    return decryptMessage(message.ciphertext, message.iv, this.sharedSecret);
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
  constructor(group) {
    this.group = group;
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
  async listByUser(userId) {
    return this.messages.filter(
      (msg) => msg.senderId === userId || msg.receiverId === userId
    );
  }
  async listByGroup(groupId) {
    return this.messages.filter((msg) => msg.groupId === groupId);
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
  handler;
  connected = false;
  async connect(_userId) {
    this.connected = true;
  }
  async send(message) {
    if (!this.connected) {
      throw new Error("Transport not connected");
    }
    this.handler?.(message);
  }
  onMessage(handler) {
    this.handler = handler;
  }
};

// src/index.ts
var ChatSDK = class {
  config;
  currentUser = null;
  constructor(config) {
    this.config = config;
  }
  /**
   * Create a new user with generated identity keys
   */
  async createUser(username) {
    const keyPair = generateIdentityKeyPair();
    const user = {
      id: generateUUID(),
      username,
      identityKey: keyPair.publicKey,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey
    };
    await this.config.userStore.create(user);
    return user;
  }
  /**
   * Import an existing user from stored data
   */
  async importUser(userData) {
    await this.config.userStore.save(userData);
    return userData;
  }
  /**
   * Set the current active user
   */
  setCurrentUser(user) {
    this.currentUser = user;
    if (this.config.transport) {
      this.config.transport.connect(user.id);
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
    const session = new ChatSession(sessionId, userA, userB);
    await session.initialize();
    return session;
  }
  /**
   * Create a new group with members
   */
  async createGroup(name, members) {
    if (members.length < 2) {
      throw new Error("Group must have at least 2 members");
    }
    const group = {
      id: generateUUID(),
      name,
      members,
      createdAt: Date.now()
    };
    await this.config.groupStore.create(group);
    const session = new GroupSession(group);
    await session.initialize();
    return session;
  }
  /**
   * Load an existing group by ID
   */
  async loadGroup(id) {
    const group = await this.config.groupStore.findById(id);
    if (!group) {
      throw new Error(`Group not found: ${id}`);
    }
    const session = new GroupSession(group);
    await session.initialize();
    return session;
  }
  /**
   * Send a message in a chat session (1:1 or group)
   */
  async sendMessage(session, plaintext) {
    if (!this.currentUser) {
      throw new Error("No current user set. Call setCurrentUser() first.");
    }
    let message;
    if (session instanceof ChatSession) {
      message = await session.encrypt(plaintext, this.currentUser.id);
    } else {
      message = await session.encrypt(plaintext, this.currentUser.id);
    }
    await this.config.messageStore.create(message);
    if (this.config.transport) {
      await this.config.transport.send(message);
    }
    return message;
  }
  /**
   * Decrypt a message
   */
  async decryptMessage(message, user) {
    if (message.groupId) {
      const group = await this.config.groupStore.findById(message.groupId);
      if (!group) {
        throw new Error(`Group not found: ${message.groupId}`);
      }
      const session = new GroupSession(group);
      await session.initialize();
      return await session.decrypt(message);
    } else {
      const otherUserId = message.senderId === user.id ? message.receiverId : message.senderId;
      if (!otherUserId) {
        throw new Error("Invalid message: missing receiver/sender");
      }
      const otherUser = await this.config.userStore.findById(otherUserId);
      if (!otherUser) {
        throw new Error(`User not found: ${otherUserId}`);
      }
      const ids = [user.id, otherUser.id].sort();
      const sessionId = `${ids[0]}-${ids[1]}`;
      const session = new ChatSession(sessionId, user, otherUser);
      await session.initializeForUser(user);
      return await session.decrypt(message, user);
    }
  }
  /**
   * Get messages for a user
   */
  async getMessagesForUser(userId) {
    return await this.config.messageStore.listByUser(userId);
  }
  /**
   * Get messages for a group
   */
  async getMessagesForGroup(groupId) {
    return await this.config.messageStore.listByGroup(groupId);
  }
};
export {
  ChatSDK,
  ChatSession,
  GroupSession,
  InMemoryGroupStore,
  InMemoryMessageStore,
  InMemoryTransport,
  InMemoryUserStore
};
