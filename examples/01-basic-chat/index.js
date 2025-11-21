import { ChatSDK, InMemoryUserStore, InMemoryMessageStore, InMemoryGroupStore, LogLevel } from 'chatly-sdk';

async function main() {
  console.log('🔐 Chatly SDK - Basic Chat Example');
  console.log('==================================\n');

  // Initialize SDK with in-memory storage
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    logLevel: LogLevel.NONE, // Disable logs for cleaner output
  });

  // Step 1: Create users
  console.log('Creating users...');
  const alice = await sdk.createUser('alice');
  const bob = await sdk.createUser('bob');
  console.log(`✅ Created user: ${alice.username} (ID: ${alice.id.substring(0, 8)}...)`);
  console.log(`✅ Created user: ${bob.username} (ID: ${bob.id.substring(0, 8)}...)\n`);

  // Step 2: Start a chat session
  console.log('Starting chat session...');
  const session = await sdk.startSession(alice, bob);
  console.log(`✅ Session created between ${alice.username} and ${bob.username}\n`);

  // Step 3: Alice sends messages
  console.log('Alice sends messages...');
  sdk.setCurrentUser(alice);
  
  const messages = [
    'Hello Bob!',
    'How are you today?',
    'This is end-to-end encrypted!',
  ];

  for (const text of messages) {
    await sdk.sendMessage(session, text);
    console.log(`📤 Alice: ${text}`);
  }
  console.log();

  // Step 4: Bob receives and decrypts messages
  console.log('Bob receives and decrypts messages...');
  sdk.setCurrentUser(bob);
  
  const receivedMessages = await sdk.getMessagesForUser(bob.id);
  
  for (const msg of receivedMessages) {
    const plaintext = await sdk.decryptMessage(msg, bob);
    console.log(`📨 Bob received: ${plaintext}`);
  }
  console.log();

  console.log('✅ All messages encrypted and decrypted successfully!');
}

main().catch(console.error);
