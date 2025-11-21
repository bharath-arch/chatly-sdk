import { ChatSDK, InMemoryUserStore, InMemoryMessageStore, InMemoryGroupStore, LogLevel } from 'chatly-sdk';

async function main() {
  console.log('📧 Chatly SDK - Offline Messaging Example');
  console.log('=========================================\n');

  // Initialize SDK WITHOUT transport (offline mode)
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    // No transport = offline/asynchronous messaging
    logLevel: LogLevel.NONE,
  });

  // Create users
  console.log('Creating users...');
  const alice = await sdk.createUser('alice');
  const bob = await sdk.createUser('bob');
  console.log('✅ Alice created');
  console.log('✅ Bob created\n');

  // Start session
  const session = await sdk.startSession(alice, bob);

  // Alice sends messages (offline mode)
  console.log('Alice sends messages (offline mode)...');
  sdk.setCurrentUser(alice);

  const messages = [
    'Hey Bob, check this out later!',
    'No rush to reply',
    'This works like email',
  ];

  for (const text of messages) {
    await sdk.sendMessage(session, text);
    console.log(`📤 Message queued: ${text}`);
  }
  console.log();

  // Simulate time passing...
  console.log('⏰ Time passes... Bob checks messages later...\n');

  // Bob retrieves messages
  console.log('Bob checks messages later...');
  sdk.setCurrentUser(bob);
  
  const receivedMessages = await sdk.getMessagesForUser(bob.id);
  console.log(`📬 Bob has ${receivedMessages.length} new messages`);
  
  for (let i = 0; i < receivedMessages.length; i++) {
    const plaintext = await sdk.decryptMessage(receivedMessages[i], bob);
    console.log(`📨 Message ${i + 1}: ${plaintext}`);
  }
  console.log();

  // Bob replies (also offline)
  console.log('Bob replies (also offline)...');
  await sdk.sendMessage(session, 'Thanks Alice, got your messages!');
  console.log('📤 Bob: Thanks Alice, got your messages!\n');

  // Alice checks later
  console.log('Alice checks messages later...');
  sdk.setCurrentUser(alice);
  
  const aliceMessages = await sdk.getMessagesForUser(alice.id);
  const bobReply = aliceMessages[aliceMessages.length - 1];
  const replyText = await sdk.decryptMessage(bobReply, alice);
  console.log(`📨 Alice received: ${replyText}\n`);

  console.log('✅ Offline messaging works perfectly!');
  console.log('\n💡 Key Points:');
  console.log('   - No WebSocket connection needed');
  console.log('   - Messages stored in database');
  console.log('   - Users fetch messages when ready');
  console.log('   - Works like email or async messaging');
}

main().catch(console.error);
