import type { User, StoredUser } from "./models/user.js";
import type { Message } from "./models/message.js";
import type { Group } from "./models/group.js";
import type {
  UserStoreAdapter,
  MessageStoreAdapter,
  GroupStoreAdapter,
} from "./stores/adapters.js";
import type { TransportAdapter } from "./transport/adapters.js";
import { ChatSession } from "./chat/ChatSession.js";
import { GroupSession } from "./chat/GroupSession.js";
import { generateIdentityKeyPair } from "./crypto/keys.js";
import { generateUUID } from "./crypto/uuid.js";

export interface ChatSDKConfig {
  userStore: UserStoreAdapter;
  messageStore: MessageStoreAdapter;
  groupStore: GroupStoreAdapter;
  transport?: TransportAdapter;
}

/**
 * Main ChatSDK class - production-ready WhatsApp-style chat SDK
 */
export class ChatSDK {
  private config: ChatSDKConfig;
  private currentUser: User | null = null;

  constructor(config: ChatSDKConfig) {
    this.config = config;
  }

  /**
   * Create a new user with generated identity keys
   */
  async createUser(username: string): Promise<User> {
    const keyPair = generateIdentityKeyPair();
    const user: User = {
      id: generateUUID(),
      username,
      identityKey: keyPair.publicKey,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };

    await this.config.userStore.create(user);
    return user;
  }

  /**
   * Import an existing user from stored data
   */
  async importUser(userData: StoredUser): Promise<User> {
    await this.config.userStore.save(userData);
    return userData;
  }

  /**
   * Set the current active user
   */
  setCurrentUser(user: User): void {
    this.currentUser = user;
    if (this.config.transport) {
      this.config.transport.connect(user.id);
    }
  }

  /**
   * Get the current active user
   */
  getCurrentUser(): User | null {
    return this.currentUser;
  }

  /**
   * Start a 1:1 chat session between two users
   */
  async startSession(userA: User, userB: User): Promise<ChatSession> {
    // Create consistent session ID regardless of user order
    const ids = [userA.id, userB.id].sort();
    const sessionId = `${ids[0]}-${ids[1]}`;
    const session = new ChatSession(sessionId, userA, userB);
    await session.initialize();
    return session;
  }

  /**
   * Create a new group with members
   */
  async createGroup(name: string, members: User[]): Promise<GroupSession> {
    if (members.length < 2) {
      throw new Error("Group must have at least 2 members");
    }

    const group: Group = {
      id: generateUUID(),
      name,
      members,
      createdAt: Date.now(),
    };

    await this.config.groupStore.create(group);
    const session = new GroupSession(group);
    await session.initialize();
    return session;
  }

  /**
   * Load an existing group by ID
   */
  async loadGroup(id: string): Promise<GroupSession> {
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
  async sendMessage(
    session: ChatSession | GroupSession,
    plaintext: string
  ): Promise<Message> {
    if (!this.currentUser) {
      throw new Error("No current user set. Call setCurrentUser() first.");
    }

    let message: Message;
    if (session instanceof ChatSession) {
      message = await session.encrypt(plaintext, this.currentUser.id);
    } else {
      message = await session.encrypt(plaintext, this.currentUser.id);
    }

    // Store the message
    await this.config.messageStore.create(message);

    // Send via transport if available
    if (this.config.transport) {
      await this.config.transport.send(message);
    }

    return message;
  }

  /**
   * Decrypt a message
   */
  async decryptMessage(message: Message, user: User): Promise<string> {
    if (message.groupId) {
      // Group message
      const group = await this.config.groupStore.findById(message.groupId);
      if (!group) {
        throw new Error(`Group not found: ${message.groupId}`);
      }
      const session = new GroupSession(group);
      await session.initialize();
      return await session.decrypt(message);
    } else {
      // 1:1 message - need to find the session
      const otherUserId =
        message.senderId === user.id ? message.receiverId : message.senderId;
      if (!otherUserId) {
        throw new Error("Invalid message: missing receiver/sender");
      }

      const otherUser = await this.config.userStore.findById(otherUserId);
      if (!otherUser) {
        throw new Error(`User not found: ${otherUserId}`);
      }

      // Create consistent session ID
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
  async getMessagesForUser(userId: string): Promise<Message[]> {
    return await this.config.messageStore.listByUser(userId);
  }

  /**
   * Get messages for a group
   */
  async getMessagesForGroup(groupId: string): Promise<Message[]> {
    return await this.config.messageStore.listByGroup(groupId);
  }
}

// Export adapters and implementations
export * from "./stores/adapters.js";
export * from "./stores/memory/userStore.js";
export * from "./stores/memory/messageStore.js";
export * from "./stores/memory/groupStore.js";
export * from "./transport/adapters.js";
export * from "./transport/memoryTransport.js";
export * from "./models/user.js";
export * from "./models/message.js";
export * from "./models/group.js";
export * from "./chat/ChatSession.js";
export * from "./chat/GroupSession.js";
