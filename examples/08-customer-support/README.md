# Customer Support Chat Example

Real-world customer support system with live chat and offline fallback.

## What You'll Learn

- Building a customer support chat system
- Agent availability management
- Offline message handling
- Queue management for support tickets

## Running the Example

```bash
npm install
npm start
```

## How It Works

This example simulates a **customer support system**:
- Customers can send messages anytime
- Messages queued if no agents online
- Agents see messages when they come online
- Real-time chat when both are online

## Output

```
🎧 Chatly SDK - Customer Support Example
========================================

Setting up support system...
✅ Support agent created
✅ Customer created

Scenario 1: Customer sends message (agent offline)
📝 Customer: I need help with my order
⏳ Message queued (no agents available)

Scenario 2: Agent comes online
🟢 Agent online
📬 Agent has 1 pending message
📨 Agent sees: I need help with my order

Scenario 3: Live chat (both online)
💬 Real-time conversation started
📤 Agent: Hi! How can I help?
📨 Customer received: Hi! How can I help?
📤 Customer: My order #12345 is delayed
📨 Agent received: My order #12345 is delayed
📤 Agent: Let me check that for you
📨 Customer received: Let me check that for you

✅ Support system works perfectly!
```

## Features

- **24/7 Availability**: Customers can message anytime
- **Offline Queue**: Messages queued when agents offline
- **Real-time**: Live chat when agents available
- **Message History**: Full conversation history

## Use Cases

- **Customer Support** (Zendesk, Intercom-style)
- **Help Desk Systems**
- **Live Chat Widgets**
- **Support Ticketing**
