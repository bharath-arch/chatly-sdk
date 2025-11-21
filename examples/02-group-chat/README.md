# Group Chat Example

Multi-user encrypted group messaging.

## What You'll Learn

- Creating groups
- Adding multiple members
- Sending messages to groups
- Group encryption
- Retrieving group messages

## Running the Example

```bash
npm install
npm start
```

## How It Works

This example demonstrates **group chat**:
- Create a group with multiple members
- All messages encrypted with group key
- All members can send and receive
- End-to-end encrypted group messaging

## Output

```
👥 Chatly SDK - Group Chat Example
==================================

Creating users...
✅ Alice created
✅ Bob created
✅ Charlie created

Creating group...
✅ Group created: Team Chat
✅ Members: 3

Alice sends to group...
📤 Alice: Hello team!
📤 Alice: Let's discuss the project

Bob sends to group...
📤 Bob: Sounds good!

Charlie sends to group...
📤 Charlie: I'm in!

All members receive messages...
📨 Bob received 4 messages
📨 Charlie received 4 messages

Decrypting messages...
💬 Alice: Hello team!
💬 Alice: Let's discuss the project
💬 Bob: Sounds good!
💬 Charlie: I'm in!

✅ Group chat works perfectly!
```

## Key Features

- **Multi-user**: 2-256 members per group
- **Encrypted**: End-to-end encryption for all messages
- **Scalable**: Same encryption performance regardless of group size
- **Persistent**: Messages stored in database

## Use Cases

- **Team Chat** (Slack, Microsoft Teams)
- **Family Groups** (WhatsApp groups)
- **Community Channels**
- **Project Collaboration**
