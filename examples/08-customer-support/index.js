import { 
  ChatSDK, 
  InMemoryUserStore, 
  InMemoryMessageStore, 
  InMemoryGroupStore,
  MemoryTransport,
  EVENTS,
  LogLevel 
} from 'chatly-sdk';

async function main() {
  console.log('🎧 Chatly SDK - Customer Support Example');
  console.log('========================================\n');

  // Initialize support system
  const transport = new MemoryTransport();
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    transport,
    logLevel: LogLevel.NONE,
  });

  console.log('Setting up support system...');
  
  // Create support agent and customer
  const agent = await sdk.createUser('support-agent');
  const customer = await sdk.createUser('customer-john');
  console.log('✅ Support agent created');
  console.log('✅ Customer created\n');

  // Create support session
  const session = await sdk.startSession(customer, agent);

  // Scenario 1: Customer sends message (agent offline)
  console.log('Scenario 1: Customer sends message (agent offline)');
  sdk.setCurrentUser(customer);
  
  await sdk.sendMessage(session, 'I need help with my order');
  console.log('📝 Customer: I need help with my order');
  console.log('⏳ Message queued (no agents available)\n');

  await new Promise(resolve => setTimeout(resolve, 1000));

  // Scenario 2: Agent comes online and sees pending messages
  console.log('Scenario 2: Agent comes online');
  sdk.setCurrentUser(agent);
  await sdk.setCurrentUser(agent); // Connect agent
  
  console.log('🟢 Agent online');
  
  const pendingMessages = await sdk.getMessagesForUser(agent.id);
  console.log(`📬 Agent has ${pendingMessages.length} pending message(s)`);
  
  for (const msg of pendingMessages) {
    const text = await sdk.decryptMessage(msg, agent);
    console.log(`📨 Agent sees: ${text}`);
  }
  console.log();

  // Scenario 3: Live chat (both online)
  console.log('Scenario 3: Live chat (both online)');
  console.log('💬 Real-time conversation started\n');

  // Set up real-time event listeners
  sdk.on(EVENTS.MESSAGE_RECEIVED, async (message) => {
    const currentUser = sdk.getCurrentUser();
    if (currentUser) {
      const plaintext = await sdk.decryptMessage(message, currentUser);
      console.log(`📨 ${currentUser.username} received: ${plaintext}`);
    }
  });

  // Agent responds
  sdk.setCurrentUser(agent);
  await sdk.sendMessage(session, 'Hi! How can I help?');
  console.log('📤 Agent: Hi! How can I help?');
  await new Promise(resolve => setTimeout(resolve, 300));

  // Customer replies
  sdk.setCurrentUser(customer);
  await sdk.sendMessage(session, 'My order #12345 is delayed');
  console.log('📤 Customer: My order #12345 is delayed');
  await new Promise(resolve => setTimeout(resolve, 300));

  // Agent helps
  sdk.setCurrentUser(agent);
  await sdk.sendMessage(session, 'Let me check that for you');
  console.log('📤 Agent: Let me check that for you');
  await new Promise(resolve => setTimeout(resolve, 300));

  console.log();
  console.log('✅ Support system works perfectly!');
  console.log('\n💡 Key Features:');
  console.log('   - 24/7 availability (customers message anytime)');
  console.log('   - Offline queue (messages saved for agents)');
  console.log('   - Real-time chat when both online');
  console.log('   - Full conversation history');

  await sdk.disconnect();
}

main().catch(console.error);
