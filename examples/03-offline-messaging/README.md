# Offline Messaging Example

Demonstrates asynchronous messaging without WebSocket (like email).

## What You'll Learn

- Messaging without real-time connection
- Message persistence in database
- Offline-first architecture
- Message retrieval and synchronization

## Running the Example

```bash
npm install
npm start
```

## How It Works

This example shows **asynchronous messaging** where:
- No WebSocket connection required
- Messages stored in database immediately
- Users retrieve messages when they check
- Works like email or traditional messaging

## Code Walkthrough

1. **No Transport Layer** - SDK initialized without WebSocket
2. **Messages Stored** - All messages go directly to database
3. **Pull-Based** - Users fetch messages when ready
4. **Offline-First** - Works without internet connection

## Output

```
📧 Chatly SDK - Offline Messaging Example
=========================================

Creating users...
✅ Alice created
✅ Bob created

Alice sends messages (offline mode)...
📤 Message queued: Hey Bob, check this out later!
📤 Message queued: No rush to reply
📤 Message queued: This works like email

Bob checks messages later...
📬 Bob has 3 new messages
📨 Message 1: Hey Bob, check this out later!
📨 Message 2: No rush to reply
📨 Message 3: This works like email

✅ Offline messaging works perfectly!
```

## Use Cases

- **Email-like systems**
- **Notification systems**
- **Asynchronous team communication**
- **IoT device messaging**
- **Store-and-forward systems**

## Key Difference from Live Chat

| Feature | Offline Messaging | Live Chat |
|---------|------------------|-----------|
| Transport | None | WebSocket |
| Delivery | Database | Real-time |
| Retrieval | Pull (fetch) | Push (events) |
| Use Case | Email-like | WhatsApp-like |
