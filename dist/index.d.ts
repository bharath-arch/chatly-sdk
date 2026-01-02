import { EventEmitter } from 'events';

interface User {
    id: string;
    username: string;
    identityKey: string;
    publicKey: string;
    privateKey: string;
}
interface StoredUser extends User {
    createdAt: number;
}

/**
 * Media types supported by the SDK
 */
declare enum MediaType {
    IMAGE = "image",
    AUDIO = "audio",
    VIDEO = "video",
    DOCUMENT = "document"
}
/**
 * Media metadata
 */
interface MediaMetadata {
    filename: string;
    mimeType: string;
    size: number;
    width?: number;
    height?: number;
    duration?: number;
    thumbnail?: string;
}
/**
 * Media attachment
 */
interface MediaAttachment {
    type: MediaType;
    data?: string | undefined;
    iv?: string | undefined;
    metadata: MediaMetadata;
    storage?: 'local' | 's3' | undefined;
    storageKey?: string | undefined;
    url?: string | undefined;
}
/**
 * Supported MIME types
 */
declare const SUPPORTED_MIME_TYPES: {
    image: string[];
    audio: string[];
    video: string[];
    document: string[];
};
/**
 * File size limits (in bytes)
 */
declare const FILE_SIZE_LIMITS: {
    image: number;
    audio: number;
    video: number;
    document: number;
};

type MessageType = "text" | "media" | "system";
interface Message {
    id: string;
    senderId: string;
    receiverId?: string;
    groupId?: string;
    ciphertext: string;
    iv: string;
    timestamp: number;
    type: MessageType;
    media?: MediaAttachment;
}

interface Group {
    id: string;
    name: string;
    members: User[];
    createdAt: number;
}

interface UserStoreAdapter {
    create(user: User): Promise<User>;
    findById(id: string): Promise<User | undefined>;
    save(user: StoredUser): Promise<void>;
    list(): Promise<User[]>;
}
interface MessageStoreAdapter {
    create(message: Message): Promise<Message>;
    findById(id: string): Promise<Message | undefined>;
    listByUser(userId: string): Promise<Message[]>;
    listByGroup(groupId: string): Promise<Message[]>;
    delete(id: string): Promise<void>;
}
interface GroupStoreAdapter {
    create(group: Group): Promise<Group>;
    findById(id: string): Promise<Group | undefined>;
    list(): Promise<Group[]>;
}

/**
 * SDK Configuration Constants
 */
declare const SUPPORTED_CURVE = "prime256v1";
declare const ALGORITHM = "aes-256-gcm";
declare const IV_LENGTH = 12;
declare const SALT_LENGTH = 16;
declare const KEY_LENGTH = 32;
declare const TAG_LENGTH = 16;
declare const PBKDF2_ITERATIONS = 100000;
declare const USERNAME_MIN_LENGTH = 3;
declare const USERNAME_MAX_LENGTH = 20;
declare const MESSAGE_MAX_LENGTH = 10000;
declare const GROUP_NAME_MAX_LENGTH = 100;
declare const GROUP_MIN_MEMBERS = 2;
declare const GROUP_MAX_MEMBERS = 256;
declare const RECONNECT_MAX_ATTEMPTS = 5;
declare const RECONNECT_BASE_DELAY = 1000;
declare const RECONNECT_MAX_DELAY = 30000;
declare const HEARTBEAT_INTERVAL = 30000;
declare const CONNECTION_TIMEOUT = 10000;
declare const MAX_QUEUE_SIZE = 1000;
declare const MESSAGE_RETRY_ATTEMPTS = 3;
declare const MESSAGE_RETRY_DELAY = 2000;
declare const EVENTS: {
    readonly MESSAGE_SENT: "message:sent";
    readonly MESSAGE_RECEIVED: "message:received";
    readonly MESSAGE_FAILED: "message:failed";
    readonly CONNECTION_STATE_CHANGED: "connection:state";
    readonly SESSION_CREATED: "session:created";
    readonly GROUP_CREATED: "group:created";
    readonly ERROR: "error";
    readonly USER_CREATED: "user:created";
};
declare enum ConnectionState {
    DISCONNECTED = "disconnected",
    CONNECTING = "connecting",
    CONNECTED = "connected",
    RECONNECTING = "reconnecting",
    FAILED = "failed"
}
declare enum MessageStatus {
    PENDING = "pending",
    SENT = "sent",
    DELIVERED = "delivered",
    FAILED = "failed"
}

/**
 * Transport adapter interface for network communication
 */
interface TransportAdapter {
    /**
     * Connect to the transport
     * @param userId - User ID to connect as
     */
    connect(userId: string): Promise<void>;
    /**
     * Disconnect from the transport
     */
    disconnect(): Promise<void>;
    /**
     * Reconnect to the transport
     */
    reconnect(): Promise<void>;
    /**
     * Send a message
     * @param message - Message to send
     */
    send(message: Message): Promise<void>;
    /**
     * Register a message handler
     * @param handler - Function to call when a message is received
     */
    onMessage(handler: (message: Message) => void): void;
    /**
     * Register a connection state change handler
     * @param handler - Function to call when connection state changes
     */
    onConnectionStateChange?(handler: (state: ConnectionState) => void): void;
    /**
     * Register an error handler
     * @param handler - Function to call when an error occurs
     */
    onError?(handler: (error: Error) => void): void;
    /**
     * Get the current connection state
     */
    getConnectionState(): ConnectionState;
    /**
     * Check if transport is connected
     */
    isConnected(): boolean;
}

interface StorageUploadResult {
    storageKey: string;
    url?: string;
}
interface StorageProvider {
    /**
     * Name of the storage provider (e.g., 'local', 's3')
     */
    readonly name: string;
    /**
     * Upload data to storage
     * @param data Base64 encoded data or Buffer
     * @param filename Desired filename or path
     * @param mimeType MIME type of the file
     */
    upload(data: string | Buffer, filename: string, mimeType: string): Promise<StorageUploadResult>;
    /**
     * Download data from storage
     * @param storageKey Key/path of the file in storage
     * @returns Base64 encoded data
     */
    download(storageKey: string): Promise<string>;
    /**
     * Delete data from storage
     * @param storageKey Key/path of the file in storage
     */
    delete(storageKey: string): Promise<void>;
}

declare class ChatSession {
    readonly id: string;
    readonly userA: User;
    readonly userB: User;
    private storageProvider?;
    private sharedSecret;
    private ephemeralKeyPair;
    constructor(id: string, userA: User, userB: User, storageProvider?: StorageProvider | undefined);
    /**
     * Initialize the session by deriving the shared secret
     * ECDH is commutative, so we can use either user's keys
     */
    initialize(): Promise<void>;
    /**
     * Initialize from a specific user's perspective (useful when decrypting)
     */
    initializeForUser(user: User): Promise<void>;
    /**
     * Encrypt a message for this session
     */
    encrypt(plaintext: string, senderId: string): Promise<Message>;
    /**
     * Encrypt a media message for this session
     */
    encryptMedia(plaintext: string, media: MediaAttachment, senderId: string): Promise<Message>;
    /**
     * Decrypt a message in this session
     */
    decrypt(message: Message, user: User): Promise<string>;
    private deriveLegacySecret;
    /**
     * Decrypt a media message in this session
     */
    decryptMedia(message: Message, user: User): Promise<{
        text: string;
        media: MediaAttachment;
    }>;
}

declare class GroupSession {
    readonly group: Group;
    private storageProvider?;
    private groupKey;
    constructor(group: Group, storageProvider?: StorageProvider | undefined);
    /**
     * Initialize the session by deriving the group key
     */
    initialize(): Promise<void>;
    /**
     * Encrypt a message for this group
     */
    encrypt(plaintext: string, senderId: string): Promise<Message>;
    /**
     * Encrypt a media message for this group
     */
    encryptMedia(plaintext: string, media: MediaAttachment, senderId: string): Promise<Message>;
    /**
     * Decrypt a message in this group
     */
    decrypt(message: Message): Promise<string>;
    /**
     * Decrypt a media message in this group
     */
    decryptMedia(message: Message): Promise<{
        text: string;
        media: MediaAttachment;
    }>;
}

/**
 * Log levels
 */
declare enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    NONE = 4
}
/**
 * Logger configuration
 */
interface LoggerConfig {
    level: LogLevel;
    prefix?: string;
    timestamp?: boolean;
}
/**
 * Simple structured logger
 */
declare class Logger {
    private config;
    constructor(config?: Partial<LoggerConfig>);
    private shouldLog;
    private formatMessage;
    debug(message: string, data?: unknown): void;
    info(message: string, data?: unknown): void;
    warn(message: string, data?: unknown): void;
    error(message: string, error?: Error | unknown): void;
    setLevel(level: LogLevel): void;
    getLevel(): LogLevel;
}
declare const logger: Logger;

declare class InMemoryUserStore implements UserStoreAdapter {
    private users;
    create(user: User): Promise<User>;
    findById(id: string): Promise<User | undefined>;
    save(user: StoredUser): Promise<void>;
    list(): Promise<User[]>;
}

declare class InMemoryMessageStore implements MessageStoreAdapter {
    private messages;
    create(message: Message): Promise<Message>;
    findById(id: string): Promise<Message | undefined>;
    listByUser(userId: string): Promise<Message[]>;
    listByGroup(groupId: string): Promise<Message[]>;
    delete(id: string): Promise<void>;
}

declare class InMemoryGroupStore implements GroupStoreAdapter {
    private groups;
    create(group: Group): Promise<Group>;
    findById(id: string): Promise<Group | undefined>;
    list(): Promise<Group[]>;
}

/**
 * In-memory transport for testing (no actual network communication)
 */
declare class InMemoryTransport implements TransportAdapter {
    private messageHandler;
    private connectionState;
    private stateHandler;
    private errorHandler;
    connect(userId: string): Promise<void>;
    disconnect(): Promise<void>;
    reconnect(): Promise<void>;
    send(message: Message): Promise<void>;
    onMessage(handler: (message: Message) => void): void;
    onConnectionStateChange(handler: (state: ConnectionState) => void): void;
    onError(handler: (error: Error) => void): void;
    getConnectionState(): ConnectionState;
    isConnected(): boolean;
    simulateReceive(message: Message): void;
    simulateError(error: Error): void;
}

declare class WebSocketClient implements TransportAdapter {
    private ws;
    private url;
    private messageHandler;
    private stateHandler;
    private errorHandler;
    private connectionState;
    private reconnectAttempts;
    private reconnectTimer;
    private heartbeatTimer;
    private currentUserId;
    private shouldReconnect;
    constructor(url: string);
    connect(userId: string): Promise<void>;
    private doConnect;
    disconnect(): Promise<void>;
    reconnect(): Promise<void>;
    private scheduleReconnect;
    private clearReconnectTimer;
    private startHeartbeat;
    private stopHeartbeat;
    send(message: Message): Promise<void>;
    onMessage(handler: (message: Message) => void): void;
    onConnectionStateChange(handler: (state: ConnectionState) => void): void;
    onError(handler: (error: Error) => void): void;
    getConnectionState(): ConnectionState;
    isConnected(): boolean;
    private updateState;
    private handleError;
}

/**
 * Base SDK Error class
 */
declare class SDKError extends Error {
    readonly code: string;
    readonly retryable: boolean;
    readonly details?: Record<string, unknown> | undefined;
    constructor(message: string, code: string, retryable?: boolean, details?: Record<string, unknown> | undefined);
    toJSON(): {
        name: string;
        message: string;
        code: string;
        retryable: boolean;
        details: Record<string, unknown> | undefined;
    };
}
/**
 * Network-related errors (connection, timeout, etc.)
 */
declare class NetworkError extends SDKError {
    constructor(message: string, details?: Record<string, unknown>);
}
/**
 * Encryption/Decryption errors
 */
declare class EncryptionError extends SDKError {
    constructor(message: string, details?: Record<string, unknown>);
}
/**
 * Authentication/Authorization errors
 */
declare class AuthError extends SDKError {
    constructor(message: string, details?: Record<string, unknown>);
}
/**
 * Validation errors (invalid input)
 */
declare class ValidationError extends SDKError {
    constructor(message: string, details?: Record<string, unknown>);
}
/**
 * Storage-related errors
 */
declare class StorageError extends SDKError {
    constructor(message: string, retryable?: boolean, details?: Record<string, unknown>);
}
/**
 * Session-related errors
 */
declare class SessionError extends SDKError {
    constructor(message: string, details?: Record<string, unknown>);
}
/**
 * Transport-related errors
 */
declare class TransportError extends SDKError {
    constructor(message: string, retryable?: boolean, details?: Record<string, unknown>);
}
/**
 * Configuration errors
 */
declare class ConfigError extends SDKError {
    constructor(message: string, details?: Record<string, unknown>);
}

/**
 * Validate username format
 */
declare function validateUsername(username: string): void;
/**
 * Validate message content
 */
declare function validateMessage(message: string): void;
/**
 * Validate group name
 */
declare function validateGroupName(name: string): void;
/**
 * Validate group members count
 */
declare function validateGroupMembers(memberCount: number): void;
/**
 * Validate user ID format
 */
declare function validateUserId(userId: string): void;

/**
 * Convert File or Blob to base64 string
 */
declare function encodeFileToBase64(file: File | Blob): Promise<string>;
/**
 * Convert base64 string to Blob
 */
declare function decodeBase64ToBlob(base64: string, mimeType: string): Blob;
/**
 * Detect media type from MIME type
 */
declare function getMediaType(mimeType: string): MediaType;
/**
 * Validate media file
 */
declare function validateMediaFile(file: File | Blob, filename?: string): void;
/**
 * Create media metadata from file
 */
declare function createMediaMetadata(file: File | Blob, filename?: string): Promise<MediaMetadata>;
/**
 * Create media attachment from file
 */
declare function createMediaAttachment(file: File | Blob, filename?: string): Promise<MediaAttachment>;
/**
 * Format file size for display
 */
declare function formatFileSize(bytes: number): string;

declare class LocalStorageProvider implements StorageProvider {
    readonly name = "local";
    private storageDir;
    constructor(storageDir?: string);
    upload(data: string | Buffer, filename: string, mimeType: string): Promise<StorageUploadResult>;
    download(storageKey: string): Promise<string>;
    delete(storageKey: string): Promise<void>;
}

interface S3Config {
    region: string;
    bucket: string;
    credentials?: {
        accessKeyId: string;
        secretAccessKey: string;
    };
    endpoint?: string;
    forcePathStyle?: boolean;
}
declare class S3StorageProvider implements StorageProvider {
    readonly name = "s3";
    private client;
    private bucket;
    constructor(config: S3Config);
    upload(data: string | Buffer, filename: string, mimeType: string): Promise<StorageUploadResult>;
    download(storageKey: string): Promise<string>;
    delete(storageKey: string): Promise<void>;
}

interface ChatSDKConfig {
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
declare class ChatSDK extends EventEmitter {
    private config;
    private currentUser;
    private messageQueue;
    constructor(config: ChatSDKConfig);
    private setupTransportHandlers;
    private processMessageQueue;
    /**
     * Create a new user with generated identity keys
     */
    createUser(username: string): Promise<User>;
    /**
     * Import an existing user from stored data
     */
    importUser(userData: StoredUser): Promise<User>;
    /**
     * Set the current active user
     */
    setCurrentUser(user: User): Promise<void>;
    /**
     * Get the current active user
     */
    getCurrentUser(): User | null;
    /**
     * Start a 1:1 chat session between two users
     */
    startSession(userA: User, userB: User): Promise<ChatSession>;
    /**
     * Create a new group with members
     */
    createGroup(name: string, members: User[]): Promise<GroupSession>;
    /**
     * Load an existing group by ID
     */
    loadGroup(id: string): Promise<GroupSession>;
    /**
     * Send a message in a chat session (1:1 or group)
     */
    sendMessage(session: ChatSession | GroupSession, plaintext: string): Promise<Message>;
    /**
     * Send a media message in a chat session (1:1 or group)
     */
    sendMediaMessage(session: ChatSession | GroupSession, caption: string, media: MediaAttachment): Promise<Message>;
    /**
     * Decrypt a message
     */
    decryptMessage(message: Message, user: User): Promise<string>;
    /**
     * Decrypt a media message
     */
    decryptMediaMessage(message: Message, user: User): Promise<{
        text: string;
        media: MediaAttachment;
    }>;
    /**
     * Get messages for a user
     */
    getMessagesForUser(userId: string): Promise<Message[]>;
    /**
     * Get messages for a group
     */
    getMessagesForGroup(groupId: string): Promise<Message[]>;
    /**
     * Get the transport adapter
     */
    getTransport(): TransportAdapter | undefined;
    /**
     * Get all users
     */
    listUsers(): Promise<User[]>;
    /**
     * Get user by ID
     */
    getUserById(userId: string): Promise<User | undefined>;
    /**
     * Get all groups
     */
    listGroups(): Promise<Group[]>;
    /**
     * Get connection state
     */
    getConnectionState(): ConnectionState;
    /**
     * Check if connected
     */
    isConnected(): boolean;
    /**
     * Disconnect transport
     */
    disconnect(): Promise<void>;
    /**
     * Reconnect transport
     */
    reconnect(): Promise<void>;
    /**
     * Get message queue status
     */
    getQueueStatus(): {
        size: number;
        pending: number;
        retryable: number;
    };
}

export { ALGORITHM, AuthError, CONNECTION_TIMEOUT, ChatSDK, type ChatSDKConfig, ChatSession, ConfigError, ConnectionState, EVENTS, EncryptionError, FILE_SIZE_LIMITS, GROUP_MAX_MEMBERS, GROUP_MIN_MEMBERS, GROUP_NAME_MAX_LENGTH, type Group, GroupSession, type GroupStoreAdapter, HEARTBEAT_INTERVAL, IV_LENGTH, InMemoryGroupStore, InMemoryMessageStore, InMemoryTransport, InMemoryUserStore, KEY_LENGTH, LocalStorageProvider, LogLevel, Logger, type LoggerConfig, MAX_QUEUE_SIZE, MESSAGE_MAX_LENGTH, MESSAGE_RETRY_ATTEMPTS, MESSAGE_RETRY_DELAY, type MediaAttachment, type MediaMetadata, MediaType, type Message, MessageStatus, type MessageStoreAdapter, type MessageType, NetworkError, PBKDF2_ITERATIONS, RECONNECT_BASE_DELAY, RECONNECT_MAX_ATTEMPTS, RECONNECT_MAX_DELAY, type S3Config, S3StorageProvider, SALT_LENGTH, SDKError, SUPPORTED_CURVE, SUPPORTED_MIME_TYPES, SessionError, StorageError, type StorageProvider, type StorageUploadResult, type StoredUser, TAG_LENGTH, type TransportAdapter, TransportError, USERNAME_MAX_LENGTH, USERNAME_MIN_LENGTH, type User, type UserStoreAdapter, ValidationError, WebSocketClient, createMediaAttachment, createMediaMetadata, decodeBase64ToBlob, encodeFileToBase64, formatFileSize, getMediaType, logger, validateGroupMembers, validateGroupName, validateMediaFile, validateMessage, validateUserId, validateUsername };
