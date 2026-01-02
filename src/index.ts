import { EventEmitter } from 'events';
import type { User, StoredUser } from "./models/user.js";
import type { Message } from "./models/message.js";
import type { Group } from "./models/group.js";
import type { MediaAttachment } from "./models/mediaTypes.js";
import type {
  UserStoreAdapter,
  MessageStoreAdapter,
  GroupStoreAdapter,
} from "./stores/adapters.js";
import type { TransportAdapter } from "./transport/adapters.js";
import type { StorageProvider } from "./storage/adapters.js";
import { ChatSession } from "./chat/ChatSession.js";
import { GroupSession } from "./chat/GroupSession.js";
import { generateIdentityKeyPair } from "./crypto/keys.js";
import { generateUUID } from "./crypto/uuid.js";
import { logger, LogLevel } from "./utils/logger.js";
import { validateUsername, validateMessage, validateGroupName, validateGroupMembers } from "./utils/validation.js";
import { SessionError, StorageError, TransportError } from "./utils/errors.js";
import { MessageQueue } from "./utils/messageQueue.js";
import { EVENTS, ConnectionState } from "./constants.js";

export interface ChatSDKConfig {
  userStore: UserStoreAdapter;
  messageStore: MessageStoreAdapter;
  groupStore: GroupStoreAdapter;
  storageProvider?: StorageProvider;
  transport?: TransportAdapter;
  logLevel?: LogLevel;
}

/**
 * Main ChatSDK class - production-ready WhatsApp-style chat SDK
 * Extends EventEmitter to provide event-driven architecture
 * 
 * Events:
 * - message:sent - Emitted when a message is sent
 * - message:received - Emitted when a message is received
 * - message:failed - Emitted when a message fails to send
 * - connection:state - Emitted when connection state changes
 * - session:created - Emitted when a session is created
 * - group:created - Emitted when a group is created
 * - user:created - Emitted when a user is created
 * - error - Emitted when an error occurs
 */
export class ChatSDK extends EventEmitter {
  private config: ChatSDKConfig;
  private currentUser: User | null = null;
  private messageQueue: MessageQueue;

  constructor(config: ChatSDKConfig) {
    super();
    this.config = config;
    this.messageQueue = new MessageQueue();

    // Set log level
    if (config.logLevel !== undefined) {
      logger.setLevel(config.logLevel);
    }

    // Set up transport event handlers if transport is provided
    if (this.config.transport) {
      this.setupTransportHandlers();
    }

    logger.info('ChatSDK initialized');
  }

  private setupTransportHandlers(): void {
    if (!this.config.transport) return;

    // Handle incoming messages
    this.config.transport.onMessage((message: Message) => {
      logger.debug('Message received via transport', { messageId: message.id });
      this.emit(EVENTS.MESSAGE_RECEIVED, message);
      
      // Store received message
      this.config.messageStore.create(message).catch((error) => {
        logger.error('Failed to store received message', error);
      });
    });

    // Handle connection state changes
    if (this.config.transport.onConnectionStateChange) {
      this.config.transport.onConnectionStateChange((state: ConnectionState) => {
        logger.info('Connection state changed', { state });
        this.emit(EVENTS.CONNECTION_STATE_CHANGED, state);

        // Process queued messages when reconnected
        if (state === ConnectionState.CONNECTED) {
          this.processMessageQueue();
        }
      });
    }

    // Handle transport errors
    if (this.config.transport.onError) {
      this.config.transport.onError((error: Error) => {
        logger.error('Transport error', error);
        this.emit(EVENTS.ERROR, error);
      });
    }
  }

  private async processMessageQueue(): Promise<void> {
    const pending = this.messageQueue.getPendingMessages();
    const retryable = this.messageQueue.getRetryableMessages();
    const toSend = [...pending, ...retryable];

    logger.info('Processing message queue', { count: toSend.length });

    for (const queued of toSend) {
      try {
        await this.config.transport!.send(queued.message);
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
  async createUser(username: string): Promise<User> {
    validateUsername(username);

    const keyPair = generateIdentityKeyPair();
    const user: User = {
      id: generateUUID(),
      username,
      identityKey: keyPair.publicKey,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };

    try {
      await this.config.userStore.create(user);
      logger.info('User created', { userId: user.id, username: user.username });
      this.emit(EVENTS.USER_CREATED, user);
      return user;
    } catch (error) {
      const storageError = new StorageError(
        'Failed to create user',
        true,
        { username, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('User creation failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  /**
   * Import an existing user from stored data
   */
  async importUser(userData: StoredUser): Promise<User> {
    try {
      await this.config.userStore.save(userData);
      logger.info('User imported', { userId: userData.id });
      return userData;
    } catch (error) {
      const storageError = new StorageError(
        'Failed to import user',
        true,
        { userId: userData.id, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('User import failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  /**
   * Set the current active user
   */
  async setCurrentUser(user: User): Promise<void> {
    this.currentUser = user;
    logger.info('Current user set', { userId: user.id, username: user.username });

    if (this.config.transport) {
      try {
        await this.config.transport.connect(user.id);
      } catch (error) {
        const transportError = new TransportError(
          'Failed to connect transport',
          true,
          { userId: user.id, error: error instanceof Error ? error.message : String(error) }
        );
        logger.error('Transport connection failed', transportError);
        this.emit(EVENTS.ERROR, transportError);
        throw transportError;
      }
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
    
    try {
      const session = new ChatSession(sessionId, userA, userB, this.config.storageProvider);
      await session.initialize();
      logger.info('Chat session created', { sessionId, users: [userA.id, userB.id] });
      this.emit(EVENTS.SESSION_CREATED, session);
      return session;
    } catch (error) {
      const sessionError = new SessionError(
        'Failed to create chat session',
        { sessionId, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('Session creation failed', sessionError);
      this.emit(EVENTS.ERROR, sessionError);
      throw sessionError;
    }
  }

  /**
   * Create a new group with members
   */
  async createGroup(name: string, members: User[]): Promise<GroupSession> {
    validateGroupName(name);
    validateGroupMembers(members.length);

    const group: Group = {
      id: generateUUID(),
      name,
      members,
      createdAt: Date.now(),
    };

    try {
      await this.config.groupStore.create(group);
      const session = new GroupSession(group, this.config.storageProvider);
      await session.initialize();
      logger.info('Group created', { groupId: group.id, name: group.name, memberCount: members.length });
      this.emit(EVENTS.GROUP_CREATED, session);
      return session;
    } catch (error) {
      const storageError = new StorageError(
        'Failed to create group',
        true,
        { groupName: name, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('Group creation failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  /**
   * Load an existing group by ID
   */
  async loadGroup(id: string): Promise<GroupSession> {
    try {
      const group = await this.config.groupStore.findById(id);
      if (!group) {
        throw new SessionError(`Group not found: ${id}`, { groupId: id });
      }

      const session = new GroupSession(group, this.config.storageProvider);
      await session.initialize();
      logger.debug('Group loaded', { groupId: id });
      return session;
    } catch (error) {
      if (error instanceof SessionError) {
        this.emit(EVENTS.ERROR, error);
        throw error;
      }
      const storageError = new StorageError(
        'Failed to load group',
        true,
        { groupId: id, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('Group load failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  /**
   * Send a message in a chat session (1:1 or group)
   */
  async sendMessage(
    session: ChatSession | GroupSession,
    plaintext: string
  ): Promise<Message> {
    if (!this.currentUser) {
      throw new SessionError("No current user set. Call setCurrentUser() first.");
    }

    validateMessage(plaintext);

    let message: Message;
    try {
      if (session instanceof ChatSession) {
        message = await session.encrypt(plaintext, this.currentUser.id);
      } else {
        message = await session.encrypt(plaintext, this.currentUser.id);
      }

      // Store the message
      await this.config.messageStore.create(message);
      logger.debug('Message stored', { messageId: message.id });

      // Send via transport if available
      if (this.config.transport) {
        if (this.config.transport.isConnected()) {
          try {
            await this.config.transport.send(message);
            logger.debug('Message sent via transport', { messageId: message.id });
            this.emit(EVENTS.MESSAGE_SENT, message);
          } catch (error) {
            // Queue message for retry
            this.messageQueue.enqueue(message);
            this.messageQueue.markFailed(
              message.id,
              error instanceof Error ? error : new Error(String(error))
            );
            logger.warn('Message send failed, queued for retry', { messageId: message.id });
            this.emit(EVENTS.MESSAGE_FAILED, message, error);
          }
        } else {
          // Queue message if offline
          this.messageQueue.enqueue(message);
          logger.info('Message queued (offline)', { messageId: message.id });
        }
      }

      return message;
    } catch (error) {
      const sendError = error instanceof Error ? error : new Error(String(error));
      logger.error('Failed to send message', sendError);
      this.emit(EVENTS.ERROR, sendError);
      throw sendError;
    }
  }

  /**
   * Send a media message in a chat session (1:1 or group)
   */
  async sendMediaMessage(
    session: ChatSession | GroupSession,
    caption: string,
    media: MediaAttachment
  ): Promise<Message> {
    if (!this.currentUser) {
      throw new SessionError("No current user set. Call setCurrentUser() first.");
    }

    let message: Message;
    try {
      if (session instanceof ChatSession) {
        message = await session.encryptMedia(caption, media, this.currentUser.id);
      } else {
        message = await session.encryptMedia(caption, media, this.currentUser.id);
      }

      // Store the message
      await this.config.messageStore.create(message);
      logger.debug('Media message stored', { messageId: message.id, mediaType: media.type });

      // Send via transport if available
      if (this.config.transport) {
        if (this.config.transport.isConnected()) {
          try {
            await this.config.transport.send(message);
            logger.debug('Media message sent via transport', { messageId: message.id });
            this.emit(EVENTS.MESSAGE_SENT, message);
          } catch (error) {
            // Queue message for retry
            this.messageQueue.enqueue(message);
            this.messageQueue.markFailed(
              message.id,
              error instanceof Error ? error : new Error(String(error))
            );
            logger.warn('Media message send failed, queued for retry', { messageId: message.id });
            this.emit(EVENTS.MESSAGE_FAILED, message, error);
          }
        } else {
          // Queue message if offline
          this.messageQueue.enqueue(message);
          logger.info('Media message queued (offline)', { messageId: message.id });
        }
      }

      return message;
    } catch (error) {
      const sendError = error instanceof Error ? error : new Error(String(error));
      logger.error('Failed to send media message', sendError);
      this.emit(EVENTS.ERROR, sendError);
      throw sendError;
    }
  }

  /**
   * Decrypt a message
   */
  async decryptMessage(message: Message, user: User): Promise<string> {
    try {
      if (message.groupId) {
        // Group message
        const group = await this.config.groupStore.findById(message.groupId);
        if (!group) {
          throw new SessionError(`Group not found: ${message.groupId}`, { groupId: message.groupId });
        }
        const session = new GroupSession(group);
        await session.initialize();
        return await session.decrypt(message);
      } else {
        // 1:1 message - need to find the session
        const otherUserId =
          message.senderId === user.id ? message.receiverId : message.senderId;
        if (!otherUserId) {
          throw new SessionError("Invalid message: missing receiver/sender");
        }

        const otherUser = await this.config.userStore.findById(otherUserId);
        if (!otherUser) {
          throw new SessionError(`User not found: ${otherUserId}`, { userId: otherUserId });
        }

        // Create consistent session ID
        const ids = [user.id, otherUser.id].sort();
        const sessionId = `${ids[0]}-${ids[1]}`;
        const session = new ChatSession(sessionId, user, otherUser, this.config.storageProvider);
        await session.initializeForUser(user);
        return await session.decrypt(message, user);
      }
    } catch (error) {
      const decryptError = error instanceof Error ? error : new Error(String(error));
      logger.error('Failed to decrypt message', decryptError);
      this.emit(EVENTS.ERROR, decryptError);
      throw decryptError;
    }
  }

  /**
   * Decrypt a media message
   */
  async decryptMediaMessage(
    message: Message,
    user: User
  ): Promise<{ text: string; media: MediaAttachment }> {
    if (!message.media) {
      throw new SessionError("Message does not contain media");
    }

    try {
      if (message.groupId) {
        // Group media message
        const group = await this.config.groupStore.findById(message.groupId);
        if (!group) {
          throw new SessionError(`Group not found: ${message.groupId}`, { groupId: message.groupId });
        }
        const session = new GroupSession(group, this.config.storageProvider);
        await session.initialize();
        return await session.decryptMedia(message);
      } else {
        // 1:1 media message
        const otherUserId =
          message.senderId === user.id ? message.receiverId : message.senderId;
        if (!otherUserId) {
          throw new SessionError("Invalid message: missing receiver/sender");
        }

        const otherUser = await this.config.userStore.findById(otherUserId);
        if (!otherUser) {
          throw new SessionError(`User not found: ${otherUserId}`, { userId: otherUserId });
        }

        // Create consistent session ID
        const ids = [user.id, otherUser.id].sort();
        const sessionId = `${ids[0]}-${ids[1]}`;
        const session = new ChatSession(sessionId, user, otherUser, this.config.storageProvider);
        await session.initializeForUser(user);
        return await session.decryptMedia(message, user);
      }
    } catch (error) {
      const decryptError = error instanceof Error ? error : new Error(String(error));
      logger.error('Failed to decrypt media message', decryptError);
      this.emit(EVENTS.ERROR, decryptError);
      throw decryptError;
    }
  }

  /**
   * Get messages for a user
   */
  async getMessagesForUser(userId: string): Promise<Message[]> {
    try {
      return await this.config.messageStore.listByUser(userId);
    } catch (error) {
      const storageError = new StorageError(
        'Failed to get messages for user',
        true,
        { userId, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('Get messages failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  /**
   * Get messages for a group
   */
  async getMessagesForGroup(groupId: string): Promise<Message[]> {
    try {
      return await this.config.messageStore.listByGroup(groupId);
    } catch (error) {
      const storageError = new StorageError(
        'Failed to get messages for group',
        true,
        { groupId, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('Get messages failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  // ========== Public Accessor Methods ==========

  /**
   * Get the transport adapter
   */
  getTransport(): TransportAdapter | undefined {
    return this.config.transport;
  }

  /**
   * Get all users
   */
  async listUsers(): Promise<User[]> {
    try {
      return await this.config.userStore.list();
    } catch (error) {
      const storageError = new StorageError(
        'Failed to list users',
        true,
        { error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('List users failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  /**
   * Get user by ID
   */
  async getUserById(userId: string): Promise<User | undefined> {
    try {
      return await this.config.userStore.findById(userId);
    } catch (error) {
      const storageError = new StorageError(
        'Failed to get user',
        true,
        { userId, error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('Get user failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  /**
   * Get all groups
   */
  async listGroups(): Promise<Group[]> {
    try {
      return await this.config.groupStore.list();
    } catch (error) {
      const storageError = new StorageError(
        'Failed to list groups',
        true,
        { error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('List groups failed', storageError);
      this.emit(EVENTS.ERROR, storageError);
      throw storageError;
    }
  }

  /**
   * Get connection state
   */
  getConnectionState(): ConnectionState {
    if (!this.config.transport) {
      return ConnectionState.DISCONNECTED;
    }
    return this.config.transport.getConnectionState();
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    if (!this.config.transport) {
      return false;
    }
    return this.config.transport.isConnected();
  }

  /**
   * Disconnect transport
   */
  async disconnect(): Promise<void> {
    if (this.config.transport) {
      await this.config.transport.disconnect();
      logger.info('Transport disconnected');
    }
  }

  /**
   * Reconnect transport
   */
  async reconnect(): Promise<void> {
    if (this.config.transport) {
      await this.config.transport.reconnect();
      logger.info('Transport reconnected');
    }
  }

  /**
   * Get message queue status
   */
  getQueueStatus(): {
    size: number;
    pending: number;
    retryable: number;
  } {
    return {
      size: this.messageQueue.size(),
      pending: this.messageQueue.getPendingMessages().length,
      retryable: this.messageQueue.getRetryableMessages().length,
    };
  }
}

// Export adapters and implementations
export * from "./stores/adapters.js";
export * from "./stores/memory/userStore.js";
export * from "./stores/memory/messageStore.js";
export * from "./stores/memory/groupStore.js";
export * from "./transport/adapters.js";
export * from "./transport/memoryTransport.js";
export * from "./transport/websocketClient.js";
export * from "./models/user.js";
export * from "./models/message.js";
export * from "./models/group.js";
export * from "./models/mediaTypes.js";
export * from "./chat/ChatSession.js";
export * from "./chat/GroupSession.js";
export * from "./utils/errors.js";
export * from "./utils/logger.js";
export * from "./utils/validation.js";
export * from "./utils/mediaUtils.js";
export * from "./storage/adapters.js";
export * from "./storage/localStorage.js";
export * from "./storage/s3Storage.js";
export * from "./constants.js";
