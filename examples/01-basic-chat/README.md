# Basic Chat Example

A simple 1:1 chat example using in-memory storage.

## What You'll Learn

- Creating users
- Starting a chat session
- Sending and receiving encrypted messages
- Decrypting messages

## Running the Example

```bash
npm install
npm start
```

## Code Walkthrough

This example demonstrates the core SDK functionality:

1. **Initialize SDK** with in-memory stores
2. **Create two users** (Alice and Bob)
3. **Start a chat session** between them
4. **Send encrypted messages** from Alice to Bob
5. **Decrypt and read messages** as Bob

All messages are end-to-end encrypted using ECDH + AES-256-GCM.

## Output

```
🔐 Chatly SDK - Basic Chat Example
==================================

Creating users...
✅ Created user: alice (ID: xxx)
✅ Created user: bob (ID: xxx)

Starting chat session...
✅ Session created between alice and bob

Alice sends messages...
📤 Alice: Hello Bob!
📤 Alice: How are you today?
📤 Alice: This is end-to-end encrypted!

Bob receives and decrypts messages...
📨 Bob received: Hello Bob!
📨 Bob received: How are you today?
📨 Bob received: This is end-to-end encrypted!

✅ All messages encrypted and decrypted successfully!
```

## Key Concepts

- **In-Memory Storage**: No database required for testing
- **E2E Encryption**: Messages encrypted on sender, decrypted on receiver
- **Session Management**: Each conversation has a unique session
