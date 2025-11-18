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

type MessageType = "text" | "system";
interface Message {
    id: string;
    senderId: string;
    receiverId?: string;
    groupId?: string;
    ciphertext: string;
    iv: string;
    timestamp: number;
    type: MessageType;
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
    listByUser(userId: string): Promise<Message[]>;
    listByGroup(groupId: string): Promise<Message[]>;
}
interface GroupStoreAdapter {
    create(group: Group): Promise<Group>;
    findById(id: string): Promise<Group | undefined>;
    list(): Promise<Group[]>;
}

interface TransportAdapter {
    connect(userId: string): Promise<void>;
    send(message: Message): Promise<void>;
    onMessage(handler: (message: Message) => void): void;
}

declare class ChatSession {
    readonly id: string;
    readonly userA: User;
    readonly userB: User;
    private sharedSecret;
    private ephemeralKeyPair;
    constructor(id: string, userA: User, userB: User);
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
     * Decrypt a message in this session
     */
    decrypt(message: Message, user: User): Promise<string>;
}

declare class GroupSession {
    readonly group: Group;
    private groupKey;
    constructor(group: Group);
    /**
     * Initialize the session by deriving the group key
     */
    initialize(): Promise<void>;
    /**
     * Encrypt a message for this group
     */
    encrypt(plaintext: string, senderId: string): Promise<Message>;
    /**
     * Decrypt a message in this group
     */
    decrypt(message: Message): Promise<string>;
}

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
    listByUser(userId: string): Promise<Message[]>;
    listByGroup(groupId: string): Promise<Message[]>;
}

declare class InMemoryGroupStore implements GroupStoreAdapter {
    private groups;
    create(group: Group): Promise<Group>;
    findById(id: string): Promise<Group | undefined>;
    list(): Promise<Group[]>;
}

type MessageHandler = (message: Message) => void;
declare class InMemoryTransport implements TransportAdapter {
    private handler?;
    private connected;
    connect(_userId: string): Promise<void>;
    send(message: Message): Promise<void>;
    onMessage(handler: MessageHandler): void;
}

interface ChatSDKConfig {
    userStore: UserStoreAdapter;
    messageStore: MessageStoreAdapter;
    groupStore: GroupStoreAdapter;
    transport?: TransportAdapter;
}
/**
 * Main ChatSDK class - production-ready WhatsApp-style chat SDK
 */
declare class ChatSDK {
    private config;
    private currentUser;
    constructor(config: ChatSDKConfig);
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
    setCurrentUser(user: User): void;
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
     * Decrypt a message
     */
    decryptMessage(message: Message, user: User): Promise<string>;
    /**
     * Get messages for a user
     */
    getMessagesForUser(userId: string): Promise<Message[]>;
    /**
     * Get messages for a group
     */
    getMessagesForGroup(groupId: string): Promise<Message[]>;
}

export { ChatSDK, type ChatSDKConfig, ChatSession, type Group, GroupSession, type GroupStoreAdapter, InMemoryGroupStore, InMemoryMessageStore, InMemoryTransport, InMemoryUserStore, type Message, type MessageStoreAdapter, type MessageType, type StoredUser, type TransportAdapter, type User, type UserStoreAdapter };
