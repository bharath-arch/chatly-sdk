import { ChatSDK, InMemoryUserStore, InMemoryMessageStore, InMemoryGroupStore, LogLevel } from 'chatly-sdk';

async function main() {
  console.log('👥 Chatly SDK - Group Chat Example');
  console.log('==================================\n');

  // Initialize SDK
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    logLevel: LogLevel.NONE,
  });

  // Create users
  console.log('Creating users...');
  const alice = await sdk.createUser('alice');
  const bob = await sdk.createUser('bob');
  const charlie = await sdk.createUser('charlie');
  console.log('✅ Alice created');
  console.log('✅ Bob created');
  console.log('✅ Charlie created\n');

  // Create group
  console.log('Creating group...');
  const group = await sdk.createGroup('Team Chat', [alice, bob, charlie]);
  console.log(`✅ Group created: ${group.group.name}`);
  console.log(`✅ Members: ${group.group.members.length}\n`);

  // Alice sends messages to group
  console.log('Alice sends to group...');
  sdk.setCurrentUser(alice);
  await sdk.sendMessage(group, 'Hello team!');
  console.log('📤 Alice: Hello team!');
  
  await sdk.sendMessage(group, 'Let\'s discuss the project');
  console.log('📤 Alice: Let\'s discuss the project\n');

  // Bob sends to group
  console.log('Bob sends to group...');
  sdk.setCurrentUser(bob);
  await sdk.sendMessage(group, 'Sounds good!');
  console.log('📤 Bob: Sounds good!\n');

  // Charlie sends to group
  console.log('Charlie sends to group...');
  sdk.setCurrentUser(charlie);
  await sdk.sendMessage(group, 'I\'m in!');
  console.log('📤 Charlie: I\'m in!\n');

  // All members receive messages
  console.log('All members receive messages...');
  const bobMessages = await sdk.getMessagesForGroup(group.group.id);
  const charlieMessages = await sdk.getMessagesForGroup(group.group.id);
  console.log(`📨 Bob received ${bobMessages.length} messages`);
  console.log(`📨 Charlie received ${charlieMessages.length} messages\n`);

  // Decrypt and display messages
  console.log('Decrypting messages...');
  for (const msg of bobMessages) {
    const plaintext = await sdk.decryptMessage(msg, bob);
    const sender = msg.senderId === alice.id ? 'Alice' : 
                   msg.senderId === bob.id ? 'Bob' : 'Charlie';
    console.log(`💬 ${sender}: ${plaintext}`);
  }
  console.log();

  console.log('✅ Group chat works perfectly!');
  console.log('\n💡 Key Features:');
  console.log('   - Multi-user (2-256 members)');
  console.log('   - End-to-end encrypted');
  console.log('   - All members can send/receive');
  console.log('   - Messages stored in database');
}

main().catch(console.error);
