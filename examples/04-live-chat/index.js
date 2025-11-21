import { 
  ChatSDK, 
  InMemoryUserStore, 
  InMemoryMessageStore, 
  InMemoryGroupStore,
  WebSocketClient,
  EVENTS,
  ConnectionState,
  LogLevel 
} from 'chatly-sdk';

async function main() {
  console.log('💬 Chatly SDK - Live Chat Example');
  console.log('=================================\n');

  // Create WebSocket transport for real-time communication
  console.log('Connecting to WebSocket server...');
  const transport = new WebSocketClient('ws://localhost:8080');

  // Initialize SDK with WebSocket transport
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    transport, // Add WebSocket for real-time
    logLevel: LogLevel.NONE,
  });

  // Listen for connection state changes
  sdk.on(EVENTS.CONNECTION_STATE_CHANGED, (state) => {
    switch (state) {
      case ConnectionState.CONNECTED:
        console.log('🟢 Connected to WebSocket server');
        break;
      case ConnectionState.CONNECTING:
        console.log('🟡 Connecting...');
        break;
      case ConnectionState.DISCONNECTED:
        console.log('🔴 Disconnected');
        break;
      case ConnectionState.RECONNECTING:
        console.log('🟡 Reconnecting...');
        break;
    }
  });

  // Create users
  console.log('\nCreating users...');
  const alice = await sdk.createUser('alice');
  const bob = await sdk.createUser('bob');
  console.log('✅ Alice created');
  console.log('✅ Bob created\n');

  // Start session
  const session = await sdk.startSession(alice, bob);

  // Set up event listeners for real-time updates
  console.log('Setting up event listeners...');
  
  sdk.on(EVENTS.MESSAGE_SENT, (message) => {
    console.log(`✅ Message sent (ID: ${message.id.substring(0, 8)}...)`);
  });

  sdk.on(EVENTS.MESSAGE_RECEIVED, async (message) => {
    const currentUser = sdk.getCurrentUser();
    if (currentUser) {
      const plaintext = await sdk.decryptMessage(message, currentUser);
      console.log(`📨 ${currentUser.username} received instantly: ${plaintext}`);
    }
  });

  sdk.on(EVENTS.MESSAGE_FAILED, (message, error) => {
    console.error(`❌ Message failed: ${error.message}`);
  });

  console.log('✅ Event listeners ready\n');

  // Wait for connection
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Alice sends real-time messages
  console.log('Alice sends real-time messages...');
  sdk.setCurrentUser(alice);

  const messages = [
    'Hi Bob! (sent instantly)',
    'How\'s it going?',
    'This is real-time!',
  ];

  for (const text of messages) {
    await sdk.sendMessage(session, text);
    console.log(`📤 Alice: ${text}`);
    await new Promise(resolve => setTimeout(resolve, 500)); // Small delay for demo
  }

  console.log();

  // Wait a bit for all messages to be received
  await new Promise(resolve => setTimeout(resolve, 1000));

  console.log('✅ All messages delivered in real-time!');
  console.log('\n💡 Key Features:');
  console.log('   - Instant delivery via WebSocket');
  console.log('   - Real-time events for UI updates');
  console.log('   - Automatic reconnection');
  console.log('   - Message queue for offline scenarios');

  // Disconnect
  await sdk.disconnect();
  console.log('\n🔌 Disconnected from server');
}

main().catch(console.error);
