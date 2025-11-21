# Hybrid Messaging Example

Combines real-time and offline messaging (Slack/Instagram-style).

## What You'll Learn

- Hybrid online/offline messaging
- Message queue with automatic retry
- Graceful degradation
- Best of both worlds

## Running the Example

```bash
npm install
npm start
```

## How It Works

This example demonstrates **hybrid messaging**:
- Real-time delivery when online
- Automatic queueing when offline
- Messages sent when reconnected
- Seamless user experience

## Output

```
🔄 Chatly SDK - Hybrid Messaging Example
========================================

Initializing hybrid SDK...
✅ SDK ready (online + offline support)

Creating users...
✅ Alice and Bob created

Scenario 1: Online messaging (real-time)
🟢 Connected
📤 Alice: Hey! (delivered instantly)
📨 Bob received: Hey!

Scenario 2: Offline messaging (queued)
🔴 Simulating disconnect...
📤 Alice: Are you there? (queued)
📤 Alice: I'll wait for you (queued)
⏳ 2 messages in queue

Scenario 3: Reconnection (auto-send)
🟢 Reconnected!
✅ Sending queued messages...
📨 Bob received: Are you there?
📨 Bob received: I'll wait for you

✅ Hybrid messaging works perfectly!
```

## Key Features

- **Smart Delivery**: Real-time when online, queued when offline
- **Automatic Queue**: Messages queued during disconnection
- **Auto-Retry**: Failed messages retry automatically
- **Seamless UX**: Users don't need to worry about connection state

## Use Cases

- **Social Media DMs** (Instagram, Twitter)
- **Team Chat** (Slack, Microsoft Teams)
- **Mobile Apps** (intermittent connectivity)
- **Progressive Web Apps**
