import { 
  ChatSDK, 
  InMemoryUserStore, 
  InMemoryMessageStore, 
  InMemoryGroupStore,
  MemoryTransport,
  EVENTS,
  ConnectionState,
  LogLevel 
} from 'chatly-sdk';

async function main() {
  console.log('🔄 Chatly SDK - Hybrid Messaging Example');
  console.log('========================================\n');

  // Use MemoryTransport for demo (simulates WebSocket)
  const transport = new MemoryTransport();

  console.log('Initializing hybrid SDK...');
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    transport, // Hybrid: works online AND offline
    logLevel: LogLevel.NONE,
  });

  // Track connection state
  let connectionState = ConnectionState.DISCONNECTED;
  sdk.on(EVENTS.CONNECTION_STATE_CHANGED, (state) => {
    connectionState = state;
    const emoji = state === ConnectionState.CONNECTED ? '🟢' : '🔴';
    console.log(`${emoji} Connection: ${state}`);
  });

  console.log('✅ SDK ready (online + offline support)\n');

  // Create users
  console.log('Creating users...');
  const alice = await sdk.createUser('alice');
  const bob = await sdk.createUser('bob');
  console.log('✅ Alice and Bob created\n');

  const session = await sdk.startSession(alice, bob);

  // Scenario 1: Online messaging (real-time)
  console.log('Scenario 1: Online messaging (real-time)');
  sdk.setCurrentUser(alice);
  await sdk.setCurrentUser(alice); // This connects the transport

  await new Promise(resolve => setTimeout(resolve, 500));

  await sdk.sendMessage(session, 'Hey!');
  console.log('📤 Alice: Hey! (delivered instantly)');

  sdk.setCurrentUser(bob);
  const messages1 = await sdk.getMessagesForUser(bob.id);
  const text1 = await sdk.decryptMessage(messages1[0], bob);
  console.log(`📨 Bob received: ${text1}\n`);

  // Scenario 2: Offline messaging (queued)
  console.log('Scenario 2: Offline messaging (queued)');
  console.log('🔴 Simulating disconnect...');
  await sdk.disconnect();

  sdk.setCurrentUser(alice);
  await sdk.sendMessage(session, 'Are you there?');
  console.log('📤 Alice: Are you there? (queued)');
  
  await sdk.sendMessage(session, 'I\'ll wait for you');
  console.log('📤 Alice: I\'ll wait for you (queued)');

  const queueStatus = sdk.getQueueStatus();
  console.log(`⏳ ${queueStatus.pending} messages in queue\n`);

  // Scenario 3: Reconnection (auto-send queued messages)
  console.log('Scenario 3: Reconnection (auto-send)');
  console.log('🟢 Reconnecting...');
  
  await sdk.reconnect();
  await new Promise(resolve => setTimeout(resolve, 500));

  console.log('✅ Sending queued messages...');

  sdk.setCurrentUser(bob);
  const messages2 = await sdk.getMessagesForUser(bob.id);
  
  // Get the last 2 messages
  const recentMessages = messages2.slice(-2);
  for (const msg of recentMessages) {
    const text = await sdk.decryptMessage(msg, bob);
    console.log(`📨 Bob received: ${text}`);
  }

  console.log();
  console.log('✅ Hybrid messaging works perfectly!');
  console.log('\n💡 Key Features:');
  console.log('   - Real-time when online');
  console.log('   - Queued when offline');
  console.log('   - Auto-send on reconnect');
  console.log('   - Seamless user experience');

  await sdk.disconnect();
}

main().catch(console.error);
