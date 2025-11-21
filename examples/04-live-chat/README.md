# Live Chat Example

Real-time chat using WebSocket (WhatsApp-style).

## What You'll Learn

- Real-time messaging with WebSocket
- Event-driven architecture
- Connection state management
- Instant message delivery

## Prerequisites

You need a WebSocket server running. See [`../10-websocket-server/`](../10-websocket-server/) for a simple server implementation.

## Running the Example

```bash
# Terminal 1: Start WebSocket server
cd ../10-websocket-server
npm install
npm start

# Terminal 2: Run this example
cd ../04-live-chat
npm install
npm start
```

## How It Works

This example demonstrates **real-time messaging**:
- WebSocket connection for instant delivery
- Events for real-time UI updates
- Automatic reconnection on disconnect
- Message queue for offline scenarios

## Output

```
💬 Chatly SDK - Live Chat Example
=================================

Connecting to WebSocket server...
🟢 Connected to wss://localhost:8080

Creating users...
✅ Alice connected
✅ Bob connected

Setting up event listeners...
✅ Event listeners ready

Alice sends real-time messages...
📤 Alice: Hi Bob! (sent instantly)
📨 Bob received instantly: Hi Bob!

📤 Alice: How's it going?
📨 Bob received instantly: How's it going?

📤 Alice: This is real-time!
📨 Bob received instantly: This is real-time!

✅ All messages delivered in real-time!
```

## Key Features

- **Instant Delivery**: Messages delivered immediately via WebSocket
- **Event-Driven**: Real-time events for UI updates
- **Auto-Reconnect**: Automatically reconnects if connection drops
- **Message Queue**: Queues messages if offline, sends when reconnected

## Use Cases

- **Messaging Apps** (WhatsApp, Telegram)
- **Live Customer Support**
- **Team Collaboration** (Slack, Discord)
- **Gaming Chat**
- **Social Media DMs**
