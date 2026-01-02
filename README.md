# chatly-sdk

You can find the sample project repository here: [Chatly SDK Sample Project](https://github.com/bharath-arch/chatly-sdk-demo.git)

Work In progress end-to-end encrypted chat SDK with WhatsApp-style features.

## Features

- 🔐 **End-to-End Encryption**
  - ECDH key exchange (P-256 curve)
  - AES-GCM message encryption
  - Per-user identity keys
  - Per-session ephemeral keys
  - Group shared keys

- 💬 **1:1 Messaging**
  - Secure key exchange
  - Encrypt/decrypt functions
  - Message payload schemas

- 👥 **Group Messaging**
  - Create groups
  - Add/remove members
  - Per-group shared key
  - Group message encryption
  - Message ordering & timestamps

- 🗄️ **Database Integration**
  - Adapter pattern for flexible storage
  - In-memory implementations included
  - UserStoreAdapter, MessageStoreAdapter, GroupStoreAdapter

- 🌐 **Networking Layer**
  - Transport adapter interface
  - In-memory transport for testing
  - Easy integration with your own WebSocket server

## Installation

```bash
npm install chatly-sdk
```

## Quick Start

### Basic Setup

```typescript
import { ChatSDK, InMemoryUserStore, InMemoryMessageStore, InMemoryGroupStore } from 'chatly-sdk';

const sdk = new ChatSDK({
  userStore: new InMemoryUserStore(),
  messageStore: new InMemoryMessageStore(),
  groupStore: new InMemoryGroupStore(),
});

// Create a user
const user = await sdk.createUser('alice');
sdk.setCurrentUser(user);
```

### 1:1 Chat Example

```typescript
import { ChatSDK, InMemoryUserStore, InMemoryMessageStore, InMemoryGroupStore } from 'chatly-sdk';

const sdk = new ChatSDK({
  userStore: new InMemoryUserStore(),
  messageStore: new InMemoryMessageStore(),
  groupStore: new InMemoryGroupStore(),
});

// Create two users
const alice = await sdk.createUser('alice');
const bob = await sdk.createUser('bob');

// Start a chat session
sdk.setCurrentUser(alice);
const session = await sdk.startSession(alice, bob);

// Send a message
const message = await sdk.sendMessage(session, 'Hello Bob!');

// Bob receives and decrypts
sdk.setCurrentUser(bob);
const messages = await sdk.getMessagesForUser(bob.id);
for (const msg of messages) {
  const decrypted = await sdk.decryptMessage(msg, bob);
  console.log(decrypted); // "Hello Bob!"
}
```

### Group Chat Example

```typescript
// Create users
const alice = await sdk.createUser('alice');
const bob = await sdk.createUser('bob');
const charlie = await sdk.createUser('charlie');

// Create a group
const group = await sdk.createGroup('Project Team', [alice, bob, charlie]);

// Send a group message
sdk.setCurrentUser(alice);
const message = await sdk.sendMessage(group, 'Hello team!');

// Members can read the message
sdk.setCurrentUser(bob);
const groupMessages = await sdk.getMessagesForGroup(group.group.id);
for (const msg of groupMessages) {
  const decrypted = await sdk.decryptMessage(msg, bob);
  console.log(decrypted);
}
```

### Save and Load User

```typescript
// Create and save user
const user = await sdk.createUser('john_doe');
const storedUser = {
  ...user,
  createdAt: Date.now(),
};
await sdk.config.userStore.save(storedUser);

// Later, load user
const loadedUser = await sdk.importUser(storedUser);
sdk.setCurrentUser(loadedUser);
```

## API Reference

### ChatSDK

Main SDK class for managing chat functionality.

#### Constructor

```typescript
new ChatSDK(config: {
  userStore: UserStoreAdapter;
  messageStore: MessageStoreAdapter;
  groupStore: GroupStoreAdapter;
  transport?: TransportAdapter;
})
```

#### Methods

- `createUser(username: string): Promise<User>` - Create a new user with generated keys
- `importUser(userData: StoredUser): Promise<User>` - Import an existing user
- `setCurrentUser(user: User): void` - Set the active user
- `getCurrentUser(): User | null` - Get the current user
- `startSession(userA: User, userB: User): Promise<ChatSession>` - Start a 1:1 chat
- `createGroup(name: string, members: User[]): Promise<GroupSession>` - Create a group
- `loadGroup(id: string): Promise<GroupSession>` - Load an existing group
- `sendMessage(session: ChatSession | GroupSession, plaintext: string): Promise<Message>` - Send a message
- `decryptMessage(message: Message, user: User): Promise<string>` - Decrypt a message
- `getMessagesForUser(userId: string): Promise<Message[]>` - Get user's messages
- `getMessagesForGroup(groupId: string): Promise<Message[]>` - Get group messages

### Adapters

#### UserStoreAdapter

```typescript
interface UserStoreAdapter {
  create(user: User): Promise<User>;
  findById(id: string): Promise<User | undefined>;
  save(user: StoredUser): Promise<void>;
  list(): Promise<User[]>;
}
```

#### MessageStoreAdapter

```typescript
interface MessageStoreAdapter {
  create(message: Message): Promise<Message>;
  listByUser(userId: string): Promise<Message[]>;
  listByGroup(groupId: string): Promise<Message[]>;
}
```

#### GroupStoreAdapter

```typescript
interface GroupStoreAdapter {
  create(group: Group): Promise<Group>;
  findById(id: string): Promise<Group | undefined>;
  list(): Promise<Group[]>;
}
```

#### TransportAdapter

```typescript
interface TransportAdapter {
  connect(userId: string): Promise<void>;
  send(message: Message): Promise<void>;
  onMessage(handler: (message: Message) => void): void;
}
```

## Extending the SDK

### Custom Store Adapters

Implement the adapter interfaces to use your own database:

```typescript
import { UserStoreAdapter, User } from 'chatly-sdk';

class PostgreSQLUserStore implements UserStoreAdapter {
  async create(user: User): Promise<User> {
    // Save to PostgreSQL
    const result = await db.query('INSERT INTO users ...');
    return result.rows[0];
  }
  
  async findById(id: string): Promise<User | undefined> {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0];
  }
  
  // ... implement other methods
}
```

### Custom Transport

Implement `TransportAdapter` to use your own WebSocket server:

```typescript
import { TransportAdapter, Message } from 'chatly-sdk';

class WebSocketTransport implements TransportAdapter {
  private ws: WebSocket;
  
  async connect(userId: string): Promise<void> {
    this.ws = new WebSocket(`wss://your-server.com/ws?userId=${userId}`);
  }
  
  async send(message: Message): Promise<void> {
    this.ws.send(JSON.stringify(message));
  }
  
  onMessage(handler: (message: Message) => void): void {
    this.ws.on('message', (data) => {
      handler(JSON.parse(data.toString()));
    });
  }
}
```

## Cryptography

The SDK uses Node.js built-in `crypto` module:

- **Key Exchange**: ECDH with P-256 (prime256v1) curve
- **Encryption**: AES-256-GCM
- **Key Derivation**: PBKDF2 with SHA-256
- **Key Storage**: Base64-encoded strings

### Security Notes

- Identity keys are long-term keys for user authentication
- Ephemeral keys are generated per-session (future: Double Ratchet support)
- Group keys are derived deterministically from group ID
- All messages use unique IVs for encryption

## Examples

See the `examples/` directory for complete examples:

- `oneToOne.ts` - 1:1 chat between two users
- `groupChat.ts` - Group chat with multiple members
- `saveLoadUser.ts` - Save and load user data

Run examples:

```bash
npm run build
node dist/examples/oneToOne.js
```

## Building

```bash
npm run build
```

This generates:
- `dist/index.js` - ES module bundle
- `dist/index.d.ts` - TypeScript definitions

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

## License

MIT
