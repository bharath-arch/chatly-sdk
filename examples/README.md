# Chatly SDK - Examples

This directory contains practical examples demonstrating different use cases for the Chatly SDK.

## 📚 Examples

### 1. [Basic Chat](./01-basic-chat)
**Difficulty**: Beginner  
**Topics**: User creation, sessions, encryption, message sending

Simple 1:1 encrypted chat between two users.

---

### 2. [Group Chat](./02-group-chat)
**Difficulty**: Beginner  
**Topics**: Group creation, multi-user messaging, group encryption

Multi-user encrypted group messaging with 3+ participants.

---

### 3. [Offline Messaging](./03-offline-messaging)
Asynchronous messaging without WebSocket

### 2. **Real-time Examples**
- [`04-live-chat/`](./04-live-chat/) - Live chat with WebSocket (WhatsApp-style)
- [`05-hybrid-messaging/`](./05-hybrid-messaging/) - Hybrid online/offline messaging

### 3. **Database Integration**
- [`06-postgresql-integration/`](./06-postgresql-integration/) - PostgreSQL storage adapter
- [`07-mongodb-integration/`](./07-mongodb-integration/) - MongoDB storage adapter

### 4. **Real-world Applications**
- [`08-customer-support/`](./08-customer-support/) - Customer support chat system
- [`09-react-chat-app/`](./09-react-chat-app/) - Full React chat application
- [`10-websocket-server/`](./10-websocket-server/) - Node.js WebSocket server

## 🚀 Quick Start

Each example includes:
- ✅ Complete source code
- ✅ README with setup instructions
- ✅ package.json for dependencies
- ✅ Comments explaining key concepts

### Running an Example

```bash
# Navigate to an example
cd examples/01-basic-chat

# Install dependencies
npm install

# Run the example
npm start
```

## 📚 Learning Path

**Beginner**: Start here
1. `01-basic-chat` - Learn the basics
2. `02-group-chat` - Understand group messaging
3. `03-offline-messaging` - See how offline works

**Intermediate**: Real-time features
4. `04-live-chat` - Add WebSocket support
5. `05-hybrid-messaging` - Combine online/offline

**Advanced**: Production setup
6. `06-postgresql-integration` - Database persistence
7. `08-customer-support` - Real-world application
8. `09-react-chat-app` - Full frontend integration

## 🎯 Use Case Guide

| Use Case | Example | Description |
|----------|---------|-------------|
| **Messaging App** | `04-live-chat` | WhatsApp-style real-time chat |
| **Customer Support** | `08-customer-support` | Live support with offline fallback |
| **Team Collaboration** | `02-group-chat` + `04-live-chat` | Slack-style team chat |
| **Social Media DMs** | `05-hybrid-messaging` | Instagram-style direct messages |
| **Email-like System** | `03-offline-messaging` | Asynchronous messaging |

## 💡 Key Concepts Demonstrated

- ✅ **End-to-end encryption** - All examples use E2E encryption
- ✅ **Message queue** - Automatic retry and offline support
- ✅ **Event handling** - Real-time UI updates
- ✅ **Database integration** - PostgreSQL and MongoDB
- ✅ **WebSocket** - Real-time bidirectional communication
- ✅ **React integration** - Hooks and context providers

## 🔧 Prerequisites

- Node.js >= 16.x
- npm >= 8.x
- (Optional) PostgreSQL or MongoDB for database examples

## 📞 Need Help?

- Check the main [README](../README.md)
- Read [CONTRIBUTING.md](../CONTRIBUTING.md)
- Open an [issue](https://github.com/bharath-arch/chatly-sdk/issues)
