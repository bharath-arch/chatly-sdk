# 🔐 Chatly SDK

Beta end-to-end encrypted chat SDK with WhatsApp-style features, event-driven architecture, and automatic reconnection.

You can find the sample project repository here: [Chatly SDK Sample Project](https://github.com/bharath-arch/chatly-sdk-demo.git)


[![npm version](https://img.shields.io/npm/v/chatly-sdk.svg)](https://www.npmjs.com/package/chatly-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

### 🔐 Security
- **End-to-End Encryption** - ECDH (P-256) + AES-256-GCM
- **Per-User Identity Keys** - Unique cryptographic identity
- **Session-Based Encryption** - Secure 1:1 and group messaging
- **Input Validation** - Protection against injection attacks

### 💬 Messaging
- **1:1 Chat** - Secure direct messaging
- **Group Chat** - Multi-user encrypted groups (2-256 members)
- **Message Queue** - Offline support with automatic retry
- **Delivery Tracking** - Message status (pending, sent, failed)

### 🌐 Connectivity
- **Auto-Reconnection** - Exponential backoff (up to 5 attempts)
- **Heartbeat Monitoring** - Connection health checks
- **Connection States** - Disconnected, connecting, connected, reconnecting, failed
- **Event-Driven** - Real-time events for all state changes

### 🛠️ Developer Experience
- **TypeScript First** - Full type safety
- **Event Emitter** - React to SDK events
- **Adapter Pattern** - Flexible storage and transport
- **Comprehensive Tests** - 40+ test cases
- **Structured Logging** - Configurable log levels

---

## 🎯 What Makes This SDK Production-Ready?

### 1. **Message Queue with Automatic Retry**
- Offline message support with persistent queue
- Configurable retry attempts (default: 3)
- Exponential backoff for failed messages
- Queue size management (default: 1000 messages)
- Message status tracking (pending, sent, failed)

### 2. **Event-Driven Architecture**
- Real-time event emissions for all state changes
- Extends Node.js `EventEmitter` for familiar API
- Events for messages, connections, users, groups, and errors
- Easy integration with React, Vue, or any framework

### 3. **Robust Connection Management**
- WebSocket support with automatic reconnection
- Exponential backoff strategy (up to 5 attempts)
- Heartbeat/ping-pong for connection health monitoring
- Connection state tracking (disconnected, connecting, connected, reconnecting, failed)
- Graceful degradation and error recovery

### 4. **Flexible Storage Adapters**
- Adapter pattern for any database (PostgreSQL, MySQL, MongoDB, Redis, etc.)
- In-memory stores for development and testing
- Easy migration from in-memory to production database
- Support for caching layers

### 5. **Enterprise-Grade Security**
- End-to-end encryption using ECDH (P-256) + AES-256-GCM
- Per-user cryptographic identity keys
- Session-based encryption for 1:1 and group chats
- Input validation to prevent injection attacks
- Secure key derivation and storage patterns

### 6. **Developer Experience**
- Full TypeScript support with comprehensive types
- Detailed error classes for better error handling
- Structured logging with configurable levels
- Extensive documentation and examples
- React hooks and context providers included


---

## 📦 Installation

```bash
npm install chatly-sdk
```

---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        ChatSDK                              │
│                   (EventEmitter)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ ChatSession  │  │ GroupSession │  │ Message Queue│     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Crypto (E2E) │  │  Validation  │  │    Logger    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
   ┌────▼────┐      ┌─────▼─────┐    ┌─────▼─────┐
   │  User   │      │  Message  │    │   Group   │
   │  Store  │      │   Store   │    │   Store   │
   └─────────┘      └───────────┘    └───────────┘
                          │
                    ┌─────▼─────┐
                    │ Transport │
                    │ (WebSocket│
                    │ /Memory)  │
                    └───────────┘
```

### Message Flow (1:1 Chat)

```
Alice                    SDK                     Bob
  │                       │                       │
  ├─ sendMessage() ──────▶│                       │
  │                       ├─ encrypt(ECDH+AES) ──▶│
  │                       ├─ store message ──────▶│
  │                       ├─ queue if offline ───▶│
  │                       ├─ send via transport ─▶│──────▶ WebSocket
  │                       │                       │
  │                       │◀──── receive ─────────┤◀────── WebSocket
  │                       ├─ emit MESSAGE_RECEIVED│
  │                       ├─ store message ──────▶│
  │                       │                       │
  │                       │                       ├─ decryptMessage()
  │                       │◀─ decrypt(ECDH+AES) ─┤
  │                       │                       │
  │                       ├─ "Hello Bob!" ───────▶│
```

### Connection Lifecycle

```
┌──────────────┐
│ DISCONNECTED │
└──────┬───────┘
       │ connect()
       ▼
┌──────────────┐     timeout/error     ┌──────────────┐
│  CONNECTING  │─────────────────────▶│    FAILED    │
└──────┬───────┘                       └──────────────┘
       │ onopen
       ▼
┌──────────────┐     onclose           ┌──────────────┐
│  CONNECTED   │─────────────────────▶│ RECONNECTING │
└──────┬───────┘                       └──────┬───────┘
       │                                      │
       │ heartbeat (30s)                     │ exponential
       │ ping/pong                           │ backoff
       │                                      │
       └──────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Basic Setup

```typescript
import { 
  ChatSDK, 
  InMemoryUserStore, 
  InMemoryMessageStore, 
  InMemoryGroupStore,
  LogLevel 
} from 'chatly-sdk';

// Initialize SDK
const sdk = new ChatSDK({
  userStore: new InMemoryUserStore(),
  messageStore: new InMemoryMessageStore(),
  groupStore: new InMemoryGroupStore(),
  logLevel: LogLevel.INFO, // Optional: DEBUG, INFO, WARN, ERROR, NONE
});

// Create a user
const alice = await sdk.createUser('alice');
sdk.setCurrentUser(alice);
```

### 1:1 Chat Example

```typescript
// Create users
const alice = await sdk.createUser('alice');
const bob = await sdk.createUser('bob');

// Start a chat session
sdk.setCurrentUser(alice);
const session = await sdk.startSession(alice, bob);

// Send a message
const message = await sdk.sendMessage(session, 'Hello Bob!');
console.log('Message sent:', message.id);

// Bob receives and decrypts
sdk.setCurrentUser(bob);
const messages = await sdk.getMessagesForUser(bob.id);
for (const msg of messages) {
  const plaintext = await sdk.decryptMessage(msg, bob);
  console.log('Received:', plaintext); // "Hello Bob!"
}
```

### Group Chat Example

```typescript
// Create users
const alice = await sdk.createUser('alice');
const bob = await sdk.createUser('bob');
const charlie = await sdk.createUser('charlie');

// Create a group
const group = await sdk.createGroup('Team Chat', [alice, bob, charlie]);

// Alice sends a message
sdk.setCurrentUser(alice);
await sdk.sendMessage(group, 'Hello team!');

// Bob and Charlie can decrypt
sdk.setCurrentUser(bob);
const messages = await sdk.getMessagesForGroup(group.group.id);
for (const msg of messages) {
  const plaintext = await sdk.decryptMessage(msg, bob);
  console.log('Bob received:', plaintext);
}
```

### Media Sharing Example

```typescript
import { createMediaAttachment } from 'chatly-sdk';

// Create users and session
const alice = await sdk.createUser('alice');
const bob = await sdk.createUser('bob');
const session = await sdk.startSession(alice, bob);

// Send an image
sdk.setCurrentUser(alice);
const imageFile = new File([imageBlob], 'photo.jpg', { type: 'image/jpeg' });
const imageMedia = await createMediaAttachment(imageFile);
await sdk.sendMediaMessage(session, 'Check out this photo!', imageMedia);

// Bob receives and decrypts
sdk.setCurrentUser(bob);
const messages = await sdk.getMessagesForUser(bob.id);
for (const msg of messages) {
  if (msg.type === 'media' && msg.media) {
    const { text, media } = await sdk.decryptMediaMessage(msg, bob);
    console.log('Caption:', text);
    console.log('Media type:', media.type);
    console.log('Filename:', media.metadata.filename);
    console.log('Size:', media.metadata.size);
    
    // Convert back to file
    const blob = decodeBase64ToBlob(media.data, media.metadata.mimeType);
    // Use blob as needed (display, download, etc.)
  }
}
```

---

## 📁 Media Sharing

Send encrypted images, audio, video, and documents with full end-to-end encryption.

### Supported Media Types

| Type | Formats | Max Size |
|------|---------|----------|
| **Images** | JPEG, PNG, GIF, WebP | 10 MB |
| **Audio** | MP3, MP4, OGG, WAV, WebM | 16 MB |
| **Video** | MP4, WebM, OGG | 100 MB |
| **Documents** | PDF, DOC, DOCX, XLS, XLSX, TXT | 100 MB |

### Sending Media

```typescript
import { createMediaAttachment, MediaType } from 'chatly-sdk';

// From a File object
const file = new File([blob], 'document.pdf', { type: 'application/pdf' });
const media = await createMediaAttachment(file);

// Send in 1:1 chat
await sdk.sendMediaMessage(session, 'Here is the document', media);

// Send in group chat
await sdk.sendMediaMessage(groupSession, 'Team photo!', media);
```

### Receiving Media

```typescript
// Get messages
const messages = await sdk.getMessagesForUser(userId);

// Check for media messages
for (const msg of messages) {
  if (msg.type === 'media' && msg.media) {
    // Decrypt media message
    const { text, media } = await sdk.decryptMediaMessage(msg, currentUser);
    
    // Access media data
    console.log('Caption:', text);
    console.log('Type:', media.type); // 'image', 'audio', 'video', 'document'
    console.log('Filename:', media.metadata.filename);
    console.log('Size:', media.metadata.size);
    console.log('MIME type:', media.metadata.mimeType);
    
    // For images/videos
    if (media.metadata.width) {
      console.log('Dimensions:', media.metadata.width, 'x', media.metadata.height);
    }
    
    // Thumbnail (for images/videos)
    if (media.metadata.thumbnail) {
      const thumbnailBlob = decodeBase64ToBlob(
        media.metadata.thumbnail,
        'image/jpeg'
      );
    }
    
    // Convert to Blob for use
    const blob = decodeBase64ToBlob(media.data, media.metadata.mimeType);
    const url = URL.createObjectURL(blob);
    // Use URL for display, download, etc.
  }
}
```

### Media Utilities

```typescript
import {
  createMediaAttachment,
  encodeFileToBase64,
  decodeBase64ToBlob,
  validateMediaFile,
  formatFileSize,
  MediaType,
  SUPPORTED_MIME_TYPES,
  FILE_SIZE_LIMITS
} from 'chatly-sdk';

// Validate before sending
try {
  validateMediaFile(file);
  console.log('File is valid');
} catch (error) {
  console.error('Invalid file:', error.message);
}

// Manual encoding/decoding
const base64 = await encodeFileToBase64(file);
const blob = decodeBase64ToBlob(base64, 'image/jpeg');

// Format file size
const sizeStr = formatFileSize(1024 * 1024); // "1.0 MB"

// Check supported types
console.log('Supported image types:', SUPPORTED_MIME_TYPES.image);
console.log('Max video size:', FILE_SIZE_LIMITS.video); // 100 MB
```

### Media Encryption

All media files are **fully encrypted end-to-end**:

1. **File data** is encrypted with the session/group key
2. **Metadata** (filename, size, etc.) is stored in plaintext for efficiency
3. **Thumbnails** (for images/videos) are encrypted
4. **No URL-based approach** - all files sent directly through SDK

```typescript
// Media encryption happens automatically
const media = await createMediaAttachment(file);
const message = await sdk.sendMediaMessage(session, caption, media);

// Message contains:
// - Encrypted caption (ciphertext)
// - Encrypted media data (media.data)
// - Plaintext metadata (media.metadata)
```

### Example: Sending an Image

```typescript
// Browser environment
const input = document.querySelector('input[type="file"]');
const file = input.files[0];

// Create media attachment (validates, encodes, generates thumbnail)
const media = await createMediaAttachment(file);

// Send with caption
await sdk.sendMediaMessage(session, 'Check this out!', media);
```

### Example: Displaying Received Images

```typescript
// Get and decrypt media message
const { text, media } = await sdk.decryptMediaMessage(message, currentUser);

// Create blob and display
const blob = decodeBase64ToBlob(media.data, media.metadata.mimeType);
const url = URL.createObjectURL(blob);

// Show image
const img = document.createElement('img');
img.src = url;
document.body.appendChild(img);

// Show thumbnail first (faster)
if (media.metadata.thumbnail) {
  const thumbBlob = decodeBase64ToBlob(media.metadata.thumbnail, 'image/jpeg');
  const thumbUrl = URL.createObjectURL(thumbBlob);
  img.src = thumbUrl; // Show thumbnail
  
  // Load full image
  img.onload = () => {
    URL.revokeObjectURL(thumbUrl);
    img.src = url; // Replace with full image
  };
}
```

---

## 🎯 Event-Driven Architecture


The SDK extends `EventEmitter` and emits events for all state changes:

```typescript
import { EVENTS, ConnectionState } from 'chatly-sdk';

// Message events
sdk.on(EVENTS.MESSAGE_SENT, (message) => {
  console.log('✅ Message sent:', message.id);
  updateUI('sent', message);
});

sdk.on(EVENTS.MESSAGE_RECEIVED, (message) => {
  console.log('📨 Message received:', message.id);
  notifyUser(message);
});

sdk.on(EVENTS.MESSAGE_FAILED, (message, error) => {
  console.error('❌ Message failed:', message.id, error);
  showRetryButton(message);
});

// Connection events
sdk.on(EVENTS.CONNECTION_STATE_CHANGED, (state) => {
  switch (state) {
    case ConnectionState.CONNECTED:
      console.log('🟢 Connected');
      break;
    case ConnectionState.RECONNECTING:
      console.log('🟡 Reconnecting...');
      break;
    case ConnectionState.DISCONNECTED:
      console.log('🔴 Disconnected');
      break;
    case ConnectionState.FAILED:
      console.log('💥 Connection failed');
      break;
  }
});

// User and group events
sdk.on(EVENTS.USER_CREATED, (user) => {
  console.log('👤 User created:', user.username);
});

sdk.on(EVENTS.SESSION_CREATED, (session) => {
  console.log('💬 Session created:', session.id);
});

sdk.on(EVENTS.GROUP_CREATED, (group) => {
  console.log('👥 Group created:', group.group.name);
});

// Error handling
sdk.on(EVENTS.ERROR, (error) => {
  console.error('⚠️ SDK error:', error);
  if (error.retryable) {
    // Retry the operation
  }
});
```

---

## 🔌 WebSocket Integration

### Client-Side Setup

```typescript
import { ChatSDK, WebSocketClient } from 'chatly-sdk';

// Create WebSocket transport
const transport = new WebSocketClient('wss://your-server.com/ws');

const sdk = new ChatSDK({
  userStore: new InMemoryUserStore(),
  messageStore: new InMemoryMessageStore(),
  groupStore: new InMemoryGroupStore(),
  transport, // Add transport
});

// Set current user (automatically connects WebSocket)
await sdk.setCurrentUser(user);

// Listen for connection state
sdk.on(EVENTS.CONNECTION_STATE_CHANGED, (state) => {
  console.log('Connection:', state);
});

// Receive messages in real-time
sdk.on(EVENTS.MESSAGE_RECEIVED, async (message) => {
  const plaintext = await sdk.decryptMessage(message, currentUser);
  displayMessage(plaintext);
});
```

### Server-Side Setup (Node.js)

```javascript
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

const clients = new Map(); // userId -> WebSocket

wss.on('connection', (ws, req) => {
  const userId = new URL(req.url, 'ws://localhost').searchParams.get('userId');
  
  if (!userId) {
    ws.close(4001, 'Missing userId');
    return;
  }
  
  clients.set(userId, ws);
  console.log(`User ${userId} connected`);
  
  // Handle ping/pong
  ws.on('message', (data) => {
    const message = JSON.parse(data.toString());
    
    if (message.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong' }));
      return;
    }
    
    // Forward message to recipient
    const recipientId = message.receiverId || message.groupId;
    const recipientWs = clients.get(recipientId);
    
    if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
      recipientWs.send(JSON.stringify(message));
    }
  });
  
  ws.on('close', () => {
    clients.delete(userId);
    console.log(`User ${userId} disconnected`);
  });
});
```

---

## 🗄️ Database Integration

The SDK uses the **Adapter Pattern** to support any database. You can implement custom storage adapters for your preferred database.

### Storage Adapter Interfaces

The SDK defines three adapter interfaces:

```typescript
// User storage
interface UserStoreAdapter {
  create(user: User): Promise<User>;
  findById(id: string): Promise<User | undefined>;
  save(user: StoredUser): Promise<void>;
  list(): Promise<User[]>;
}

// Message storage
interface MessageStoreAdapter {
  create(message: Message): Promise<Message>;
  listByUser(userId: string): Promise<Message[]>;
  listByGroup(groupId: string): Promise<Message[]>;
}

// Group storage
interface GroupStoreAdapter {
  create(group: Group): Promise<Group>;
  findById(id: string): Promise<Group | undefined>;
  list(): Promise<Group[]>;
}
```

---

### PostgreSQL Implementation

#### Database Schema

```sql
-- Users table
CREATE TABLE users (
  id VARCHAR(255) PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages table
CREATE TABLE messages (
  id VARCHAR(255) PRIMARY KEY,
  sender_id VARCHAR(255) NOT NULL REFERENCES users(id),
  receiver_id VARCHAR(255) REFERENCES users(id),
  group_id VARCHAR(255),
  ciphertext TEXT NOT NULL,
  iv VARCHAR(255) NOT NULL,
  timestamp BIGINT NOT NULL,
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_receiver (receiver_id),
  INDEX idx_group (group_id),
  INDEX idx_timestamp (timestamp)
);

-- Groups table
CREATE TABLE groups (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  shared_secret TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Group members table
CREATE TABLE group_members (
  group_id VARCHAR(255) NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, user_id)
);
```

#### Adapter Implementation

```typescript
import { Pool } from 'pg';
import { UserStoreAdapter, MessageStoreAdapter, GroupStoreAdapter } from 'chatly-sdk';
import type { User, StoredUser, Message, Group } from 'chatly-sdk';

// PostgreSQL User Store
export class PostgreSQLUserStore implements UserStoreAdapter {
  constructor(private pool: Pool) {}

  async create(user: User): Promise<User> {
    await this.pool.query(
      `INSERT INTO users (id, username, public_key, private_key) 
       VALUES ($1, $2, $3, $4)`,
      [user.id, user.username, user.publicKey, user.privateKey]
    );
    return user;
  }

  async findById(id: string): Promise<User | undefined> {
    const result = await this.pool.query(
      'SELECT id, username, public_key as "publicKey", private_key as "privateKey" FROM users WHERE id = $1',
      [id]
    );
    return result.rows[0];
  }

  async save(user: StoredUser): Promise<void> {
    await this.pool.query(
      `UPDATE users 
       SET username = $1, public_key = $2, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $3`,
      [user.username, user.publicKey, user.id]
    );
  }

  async list(): Promise<User[]> {
    const result = await this.pool.query(
      'SELECT id, username, public_key as "publicKey", private_key as "privateKey" FROM users'
    );
    return result.rows;
  }
}

// PostgreSQL Message Store
export class PostgreSQLMessageStore implements MessageStoreAdapter {
  constructor(private pool: Pool) {}

  async create(message: Message): Promise<Message> {
    await this.pool.query(
      `INSERT INTO messages (id, sender_id, receiver_id, group_id, ciphertext, iv, timestamp, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        message.id,
        message.senderId,
        message.receiverId || null,
        message.groupId || null,
        message.ciphertext,
        message.iv,
        message.timestamp,
        message.status || 'pending'
      ]
    );
    return message;
  }

  async listByUser(userId: string): Promise<Message[]> {
    const result = await this.pool.query(
      `SELECT id, sender_id as "senderId", receiver_id as "receiverId", 
              group_id as "groupId", ciphertext, iv, timestamp, status
       FROM messages 
       WHERE receiver_id = $1 OR sender_id = $1 
       ORDER BY timestamp ASC`,
      [userId]
    );
    return result.rows;
  }

  async listByGroup(groupId: string): Promise<Message[]> {
    const result = await this.pool.query(
      `SELECT id, sender_id as "senderId", receiver_id as "receiverId", 
              group_id as "groupId", ciphertext, iv, timestamp, status
       FROM messages 
       WHERE group_id = $1 
       ORDER BY timestamp ASC`,
      [groupId]
    );
    return result.rows;
  }
}

// PostgreSQL Group Store
export class PostgreSQLGroupStore implements GroupStoreAdapter {
  constructor(private pool: Pool) {}

  async create(group: Group): Promise<Group> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      
      // Insert group
      await client.query(
        'INSERT INTO groups (id, name, shared_secret) VALUES ($1, $2, $3)',
        [group.id, group.name, group.sharedSecret]
      );
      
      // Insert members
      for (const userId of group.members) {
        await client.query(
          'INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)',
          [group.id, userId]
        );
      }
      
      await client.query('COMMIT');
      return group;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async findById(id: string): Promise<Group | undefined> {
    const groupResult = await this.pool.query(
      'SELECT id, name, shared_secret as "sharedSecret" FROM groups WHERE id = $1',
      [id]
    );
    
    if (groupResult.rows.length === 0) return undefined;
    
    const membersResult = await this.pool.query(
      'SELECT user_id FROM group_members WHERE group_id = $1',
      [id]
    );
    
    return {
      ...groupResult.rows[0],
      members: membersResult.rows.map(row => row.user_id)
    };
  }

  async list(): Promise<Group[]> {
    const groupsResult = await this.pool.query(
      'SELECT id, name, shared_secret as "sharedSecret" FROM groups'
    );
    
    const groups: Group[] = [];
    for (const group of groupsResult.rows) {
      const membersResult = await this.pool.query(
        'SELECT user_id FROM group_members WHERE group_id = $1',
        [group.id]
      );
      groups.push({
        ...group,
        members: membersResult.rows.map(row => row.user_id)
      });
    }
    
    return groups;
  }
}

// Usage
import { Pool } from 'pg';
import { ChatSDK } from 'chatly-sdk';

const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'chatly',
  user: 'your_user',
  password: 'your_password',
});

const sdk = new ChatSDK({
  userStore: new PostgreSQLUserStore(pool),
  messageStore: new PostgreSQLMessageStore(pool),
  groupStore: new PostgreSQLGroupStore(pool),
});
```

---

### MongoDB Implementation

#### Adapter Implementation

```typescript
import { Collection, MongoClient } from 'mongodb';
import { UserStoreAdapter, MessageStoreAdapter, GroupStoreAdapter } from 'chatly-sdk';
import type { User, StoredUser, Message, Group } from 'chatly-sdk';

// MongoDB User Store
export class MongoDBUserStore implements UserStoreAdapter {
  constructor(private collection: Collection) {}

  async create(user: User): Promise<User> {
    await this.collection.insertOne({
      _id: user.id,
      username: user.username,
      publicKey: user.publicKey,
      privateKey: user.privateKey,
      createdAt: new Date(),
    });
    return user;
  }

  async findById(id: string): Promise<User | undefined> {
    const doc = await this.collection.findOne({ _id: id });
    if (!doc) return undefined;
    
    return {
      id: doc._id,
      username: doc.username,
      publicKey: doc.publicKey,
      privateKey: doc.privateKey,
    };
  }

  async save(user: StoredUser): Promise<void> {
    await this.collection.updateOne(
      { _id: user.id },
      { 
        $set: { 
          username: user.username, 
          publicKey: user.publicKey,
          updatedAt: new Date()
        } 
      }
    );
  }

  async list(): Promise<User[]> {
    const docs = await this.collection.find({}).toArray();
    return docs.map(doc => ({
      id: doc._id,
      username: doc.username,
      publicKey: doc.publicKey,
      privateKey: doc.privateKey,
    }));
  }
}

// MongoDB Message Store
export class MongoDBMessageStore implements MessageStoreAdapter {
  constructor(private collection: Collection) {}

  async create(message: Message): Promise<Message> {
    await this.collection.insertOne({
      _id: message.id,
      senderId: message.senderId,
      receiverId: message.receiverId,
      groupId: message.groupId,
      ciphertext: message.ciphertext,
      iv: message.iv,
      timestamp: message.timestamp,
      status: message.status || 'pending',
      createdAt: new Date(),
    });
    return message;
  }

  async listByUser(userId: string): Promise<Message[]> {
    const docs = await this.collection
      .find({ 
        $or: [{ receiverId: userId }, { senderId: userId }] 
      })
      .sort({ timestamp: 1 })
      .toArray();
    
    return docs.map(doc => ({
      id: doc._id,
      senderId: doc.senderId,
      receiverId: doc.receiverId,
      groupId: doc.groupId,
      ciphertext: doc.ciphertext,
      iv: doc.iv,
      timestamp: doc.timestamp,
      status: doc.status,
    }));
  }

  async listByGroup(groupId: string): Promise<Message[]> {
    const docs = await this.collection
      .find({ groupId })
      .sort({ timestamp: 1 })
      .toArray();
    
    return docs.map(doc => ({
      id: doc._id,
      senderId: doc.senderId,
      receiverId: doc.receiverId,
      groupId: doc.groupId,
      ciphertext: doc.ciphertext,
      iv: doc.iv,
      timestamp: doc.timestamp,
      status: doc.status,
    }));
  }
}

// MongoDB Group Store
export class MongoDBGroupStore implements GroupStoreAdapter {
  constructor(private collection: Collection) {}

  async create(group: Group): Promise<Group> {
    await this.collection.insertOne({
      _id: group.id,
      name: group.name,
      sharedSecret: group.sharedSecret,
      members: group.members,
      createdAt: new Date(),
    });
    return group;
  }

  async findById(id: string): Promise<Group | undefined> {
    const doc = await this.collection.findOne({ _id: id });
    if (!doc) return undefined;
    
    return {
      id: doc._id,
      name: doc.name,
      sharedSecret: doc.sharedSecret,
      members: doc.members,
    };
  }

  async list(): Promise<Group[]> {
    const docs = await this.collection.find({}).toArray();
    return docs.map(doc => ({
      id: doc._id,
      name: doc.name,
      sharedSecret: doc.sharedSecret,
      members: doc.members,
    }));
  }
}

// Usage
import { MongoClient } from 'mongodb';
import { ChatSDK } from 'chatly-sdk';

const client = new MongoClient('mongodb://localhost:27017');
await client.connect();
const db = client.db('chatly');

// Create indexes for better performance
await db.collection('messages').createIndex({ receiverId: 1, timestamp: 1 });
await db.collection('messages').createIndex({ groupId: 1, timestamp: 1 });
await db.collection('users').createIndex({ username: 1 }, { unique: true });

const sdk = new ChatSDK({
  userStore: new MongoDBUserStore(db.collection('users')),
  messageStore: new MongoDBMessageStore(db.collection('messages')),
  groupStore: new MongoDBGroupStore(db.collection('groups')),
});
```

---

### MySQL Implementation

#### Database Schema

```sql
CREATE DATABASE chatly CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE chatly;

CREATE TABLE users (
  id VARCHAR(255) PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_username (username)
) ENGINE=InnoDB;

CREATE TABLE messages (
  id VARCHAR(255) PRIMARY KEY,
  sender_id VARCHAR(255) NOT NULL,
  receiver_id VARCHAR(255),
  group_id VARCHAR(255),
  ciphertext MEDIUMTEXT NOT NULL,
  iv VARCHAR(255) NOT NULL,
  timestamp BIGINT NOT NULL,
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_receiver_time (receiver_id, timestamp),
  INDEX idx_group_time (group_id, timestamp),
  INDEX idx_sender (sender_id),
  FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE groups (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  shared_secret TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE group_members (
  group_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
```

#### Adapter Implementation

```typescript
import mysql from 'mysql2/promise';
import { UserStoreAdapter, MessageStoreAdapter, GroupStoreAdapter } from 'chatly-sdk';
import type { User, StoredUser, Message, Group } from 'chatly-sdk';

// MySQL User Store (similar to PostgreSQL, with minor syntax differences)
export class MySQLUserStore implements UserStoreAdapter {
  constructor(private pool: mysql.Pool) {}

  async create(user: User): Promise<User> {
    await this.pool.execute(
      'INSERT INTO users (id, username, public_key, private_key) VALUES (?, ?, ?, ?)',
      [user.id, user.username, user.publicKey, user.privateKey]
    );
    return user;
  }

  async findById(id: string): Promise<User | undefined> {
    const [rows] = await this.pool.execute(
      'SELECT id, username, public_key as publicKey, private_key as privateKey FROM users WHERE id = ?',
      [id]
    );
    return (rows as any[])[0];
  }

  async save(user: StoredUser): Promise<void> {
    await this.pool.execute(
      'UPDATE users SET username = ?, public_key = ? WHERE id = ?',
      [user.username, user.publicKey, user.id]
    );
  }

  async list(): Promise<User[]> {
    const [rows] = await this.pool.execute(
      'SELECT id, username, public_key as publicKey, private_key as privateKey FROM users'
    );
    return rows as User[];
  }
}

// Usage
import mysql from 'mysql2/promise';
import { ChatSDK } from 'chatly-sdk';

const pool = mysql.createPool({
  host: 'localhost',
  user: 'your_user',
  password: 'your_password',
  database: 'chatly',
  waitForConnections: true,
  connectionLimit: 10,
});

const sdk = new ChatSDK({
  userStore: new MySQLUserStore(pool),
  messageStore: new MySQLMessageStore(pool),
  groupStore: new MySQLGroupStore(pool),
});
```

---

### Redis (Caching Layer)

Use Redis as a caching layer on top of your primary database:

```typescript
import { createClient } from 'redis';
import { UserStoreAdapter } from 'chatly-sdk';
import type { User, StoredUser } from 'chatly-sdk';

export class CachedUserStore implements UserStoreAdapter {
  private redis: ReturnType<typeof createClient>;
  private primaryStore: UserStoreAdapter;
  private ttl: number = 3600; // 1 hour

  constructor(primaryStore: UserStoreAdapter, redisClient: ReturnType<typeof createClient>) {
    this.primaryStore = primaryStore;
    this.redis = redisClient;
  }

  async create(user: User): Promise<User> {
    const result = await this.primaryStore.create(user);
    // Cache the user
    await this.redis.setEx(
      `user:${user.id}`,
      this.ttl,
      JSON.stringify(result)
    );
    return result;
  }

  async findById(id: string): Promise<User | undefined> {
    // Try cache first
    const cached = await this.redis.get(`user:${id}`);
    if (cached) {
      return JSON.parse(cached);
    }

    // Fallback to primary store
    const user = await this.primaryStore.findById(id);
    if (user) {
      await this.redis.setEx(
        `user:${id}`,
        this.ttl,
        JSON.stringify(user)
      );
    }
    return user;
  }

  async save(user: StoredUser): Promise<void> {
    await this.primaryStore.save(user);
    // Invalidate cache
    await this.redis.del(`user:${user.id}`);
  }

  async list(): Promise<User[]> {
    return this.primaryStore.list();
  }
}

// Usage
import { createClient } from 'redis';

const redis = createClient({ url: 'redis://localhost:6379' });
await redis.connect();

const sdk = new ChatSDK({
  userStore: new CachedUserStore(new PostgreSQLUserStore(pool), redis),
  messageStore: new PostgreSQLMessageStore(pool),
  groupStore: new PostgreSQLGroupStore(pool),
});
```

---

### Best Practices

#### 1. Connection Pooling

```typescript
// ✅ DO: Use connection pooling
const pool = new Pool({ max: 20, min: 5 });

// ❌ DON'T: Create new connections for each query
const client = new Client();
await client.connect();
```

#### 2. Error Handling

```typescript
export class PostgreSQLUserStore implements UserStoreAdapter {
  async create(user: User): Promise<User> {
    try {
      await this.pool.query(/* ... */);
      return user;
    } catch (error) {
      if (error.code === '23505') { // Unique violation
        throw new Error(`User ${user.username} already exists`);
      }
      throw error;
    }
  }
}
```

#### 3. Transactions

```typescript
// Use transactions for multi-step operations
async create(group: Group): Promise<Group> {
  const client = await this.pool.connect();
  try {
    await client.query('BEGIN');
    // Multiple operations...
    await client.query('COMMIT');
    return group;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
```

#### 4. Indexing

```sql
-- Index frequently queried fields
CREATE INDEX idx_messages_receiver_time ON messages(receiver_id, timestamp);
CREATE INDEX idx_messages_group_time ON messages(group_id, timestamp);
CREATE INDEX idx_users_username ON users(username);
```

#### 5. Data Migration

When migrating from in-memory to database storage:

```typescript
// Export data from in-memory store
const users = await inMemoryStore.list();

// Import to database
for (const user of users) {
  await dbStore.create(user);
}
```

---

## ⚛️ React Integration

### Context Provider

```typescript
// contexts/SDKContext.tsx
import { createContext, useContext, useState, useEffect } from 'react';
import { ChatSDK, User, EVENTS, ConnectionState } from 'chatly-sdk';

interface SDKContextType {
  sdk: ChatSDK;
  currentUser: User | null;
  connectionState: ConnectionState;
  setCurrentUser: (user: User) => Promise<void>;
}

const SDKContext = createContext<SDKContextType | undefined>(undefined);

export function SDKProvider({ children }: { children: React.ReactNode }) {
  const [sdk] = useState(() => new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    transport: new WebSocketClient('wss://your-server.com/ws'),
  }));
  
  const [currentUser, setCurrentUserState] = useState<User | null>(null);
  const [connectionState, setConnectionState] = useState<ConnectionState>(
    ConnectionState.DISCONNECTED
  );
  
  useEffect(() => {
    // Listen for connection state changes
    sdk.on(EVENTS.CONNECTION_STATE_CHANGED, setConnectionState);
    
    return () => {
      sdk.off(EVENTS.CONNECTION_STATE_CHANGED, setConnectionState);
    };
  }, [sdk]);
  
  const setCurrentUser = async (user: User) => {
    setCurrentUserState(user);
    await sdk.setCurrentUser(user);
  };
  
  return (
    <SDKContext.Provider value={{ sdk, currentUser, connectionState, setCurrentUser }}>
      {children}
    </SDKContext.Provider>
  );
}

export function useSDK() {
  const context = useContext(SDKContext);
  if (!context) throw new Error('useSDK must be used within SDKProvider');
  return context;
}
```

### Custom Hooks

```typescript
// hooks/useMessages.ts
import { useState, useEffect } from 'react';
import { Message, ChatSession, EVENTS } from 'chatly-sdk';
import { useSDK } from '../contexts/SDKContext';

export function useMessages(session: ChatSession | null) {
  const { sdk, currentUser } = useSDK();
  const [messages, setMessages] = useState<Message[]>([]);
  const [decrypted, setDecrypted] = useState<Map<string, string>>(new Map());
  
  useEffect(() => {
    if (!session || !currentUser) return;
    
    // Load existing messages
    const loadMessages = async () => {
      const msgs = await sdk.getMessagesForUser(currentUser.id);
      setMessages(msgs);
      
      // Decrypt messages
      const decryptedMap = new Map();
      for (const msg of msgs) {
        const plaintext = await sdk.decryptMessage(msg, currentUser);
        decryptedMap.set(msg.id, plaintext);
      }
      setDecrypted(decryptedMap);
    };
    
    loadMessages();
    
    // Listen for new messages
    const handleNewMessage = async (message: Message) => {
      setMessages(prev => [...prev, message]);
      const plaintext = await sdk.decryptMessage(message, currentUser);
      setDecrypted(prev => new Map(prev).set(message.id, plaintext));
    };
    
    sdk.on(EVENTS.MESSAGE_RECEIVED, handleNewMessage);
    
    return () => {
      sdk.off(EVENTS.MESSAGE_RECEIVED, handleNewMessage);
    };
  }, [session, currentUser, sdk]);
  
  const sendMessage = async (text: string) => {
    if (!session) return;
    const message = await sdk.sendMessage(session, text);
    setMessages(prev => [...prev, message]);
  };
  
  return { messages, decrypted, sendMessage };
}
```

### Component Usage

```typescript
// components/ChatView.tsx
import { useSDK } from '../contexts/SDKContext';
import { useMessages } from '../hooks/useMessages';

function ChatView() {
  const { sdk, currentUser, connectionState } = useSDK();
  const [session, setSession] = useState<ChatSession | null>(null);
  const { messages, decrypted, sendMessage } = useMessages(session);
  const [input, setInput] = useState('');
  
  const handleSend = async () => {
    await sendMessage(input);
    setInput('');
  };
  
  return (
    <div>
      <div className="connection-status">
        {connectionState === ConnectionState.CONNECTED ? '🟢' : '🔴'} {connectionState}
      </div>
      
      <div className="messages">
        {messages.map(msg => (
          <div key={msg.id}>
            {decrypted.get(msg.id) || 'Decrypting...'}
          </div>
        ))}
      </div>
      
      <input 
        value={input} 
        onChange={(e) => setInput(e.target.value)}
        onKeyPress={(e) => e.key === 'Enter' && handleSend()}
      />
    </div>
  );
}
```

---

## 🛡️ Error Handling

The SDK uses typed errors for better error handling:

```typescript
import { 
  ValidationError, 
  NetworkError, 
  SessionError,
  EncryptionError,
  StorageError 
} from 'chatly-sdk';

try {
  await sdk.sendMessage(session, message);
} catch (error) {
  if (error instanceof ValidationError) {
    // Show validation error to user
    alert(`Invalid input: ${error.message}`);
  } else if (error instanceof NetworkError) {
    // Network error - check if retryable
    if (error.retryable) {
      console.log('Will retry automatically');
    } else {
      alert('Network error - please check your connection');
    }
  } else if (error instanceof SessionError) {
    // Session error - user not logged in
    redirectToLogin();
  } else if (error instanceof EncryptionError) {
    // Encryption failed - keys may be corrupted
    console.error('Encryption error:', error.details);
  } else if (error instanceof StorageError) {
    // Database error
    console.error('Storage error:', error.details);
  }
}
```

---

## 📊 API Reference

### ChatSDK

#### Constructor

```typescript
new ChatSDK(config: ChatSDKConfig)
```

**Config Options:**
- `userStore: UserStoreAdapter` - User storage adapter
- `messageStore: MessageStoreAdapter` - Message storage adapter
- `groupStore: GroupStoreAdapter` - Group storage adapter
- `transport?: TransportAdapter` - Optional transport layer
- `logLevel?: LogLevel` - Optional log level (DEBUG, INFO, WARN, ERROR, NONE)

#### Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `createUser(username)` | Create a new user | `Promise<User>` |
| `importUser(userData)` | Import existing user | `Promise<User>` |
| `setCurrentUser(user)` | Set active user | `Promise<void>` |
| `getCurrentUser()` | Get active user | `User \| null` |
| `startSession(userA, userB)` | Start 1:1 chat | `Promise<ChatSession>` |
| `createGroup(name, members)` | Create group | `Promise<GroupSession>` |
| `loadGroup(id)` | Load existing group | `Promise<GroupSession>` |
| `sendMessage(session, text)` | Send message | `Promise<Message>` |
| `decryptMessage(message, user)` | Decrypt message | `Promise<string>` |
| `getMessagesForUser(userId)` | Get user messages | `Promise<Message[]>` |
| `getMessagesForGroup(groupId)` | Get group messages | `Promise<Message[]>` |
| `listUsers()` | Get all users | `Promise<User[]>` |
| `getUserById(id)` | Get user by ID | `Promise<User \| undefined>` |
| `listGroups()` | Get all groups | `Promise<Group[]>` |
| `getConnectionState()` | Get connection state | `ConnectionState` |
| `isConnected()` | Check if connected | `boolean` |
| `disconnect()` | Disconnect transport | `Promise<void>` |
| `reconnect()` | Reconnect transport | `Promise<void>` |
| `getQueueStatus()` | Get message queue status | `QueueStatus` |

#### Events

| Event | Payload | Description |
|-------|---------|-------------|
| `message:sent` | `Message` | Message sent successfully |
| `message:received` | `Message` | Message received |
| `message:failed` | `Message, Error` | Message send failed |
| `connection:state` | `ConnectionState` | Connection state changed |
| `session:created` | `ChatSession` | Chat session created |
| `group:created` | `GroupSession` | Group created |
| `user:created` | `User` | User created |
| `error` | `Error` | SDK error occurred |

---

## 🔒 Security Best Practices

### 1. Secure Key Storage

```typescript
// ❌ DON'T: Store private keys in plaintext
localStorage.setItem('privateKey', user.privateKey);

// ✅ DO: Encrypt private keys with user password
import { encryptWithPassword } from './crypto';
const encrypted = await encryptWithPassword(user.privateKey, userPassword);
localStorage.setItem('encryptedKey', encrypted);
```

### 2. Use HTTPS/WSS

```typescript
// ❌ DON'T: Use unencrypted connections
const transport = new WebSocketClient('ws://server.com');

// ✅ DO: Use secure WebSocket
const transport = new WebSocketClient('wss://server.com');
```

### 3. Validate All Input

```typescript
// ✅ SDK automatically validates
await sdk.createUser('alice'); // ✅ Valid
await sdk.createUser('ab'); // ❌ Throws ValidationError
await sdk.sendMessage(session, ''); // ❌ Throws ValidationError
```

### 4. Handle Errors Properly

```typescript
// ✅ Use typed errors
sdk.on(EVENTS.ERROR, (error) => {
  if (error instanceof NetworkError && error.retryable) {
    // Will retry automatically
  } else {
    // Log to error tracking service
    Sentry.captureException(error);
  }
});
```

---

## 🧪 Testing

```bash
# Run tests
npm test

# Watch mode
npm run test:watch

# Coverage
npm run test:coverage
```

### Example Test

```typescript
import { ChatSDK, InMemoryUserStore } from 'chatly-sdk';

describe('ChatSDK', () => {
  it('should create and decrypt messages', async () => {
    const sdk = new ChatSDK({
      userStore: new InMemoryUserStore(),
      messageStore: new InMemoryMessageStore(),
      groupStore: new InMemoryGroupStore(),
    });
    
    const alice = await sdk.createUser('alice');
    const bob = await sdk.createUser('bob');
    const session = await sdk.startSession(alice, bob);
    
    sdk.setCurrentUser(alice);
    const message = await sdk.sendMessage(session, 'Hello!');
    
    const decrypted = await sdk.decryptMessage(message, bob);
    expect(decrypted).toBe('Hello!');
  });
});
```

---

## 📚 Examples

Check out the [examples](./examples) directory for complete implementations:

- **Basic Chat** - Simple 1:1 messaging
- **Group Chat** - Multi-user groups
- **React App** - Full React integration
- **WebSocket Server** - Node.js WebSocket server
- **MongoDB Integration** - Database persistence

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

---

## 📄 License

MIT © [Bharath](https://github.com/bharath-arch)

---

## 🔗 Links

- [NPM Package](https://www.npmjs.com/package/chatly-sdk)
- [GitHub Repository](https://github.com/bharath-arch/chatly-sdk)
- [Documentation](https://github.com/bharath-arch/chatly-sdk#readme)
- [Issue Tracker](https://github.com/bharath-arch/chatly-sdk/issues)

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/bharath-arch/chatly-sdk/issues)
- **Discussions**: [GitHub Discussions](https://github.com/bharath-arch/chatly-sdk/discussions)

---

**Built with ❤️ for secure, private messaging**
