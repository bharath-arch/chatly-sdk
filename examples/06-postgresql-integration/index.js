import pkg from 'pg';
const { Pool } = pkg;
import { ChatSDK, LogLevel } from 'chatly-sdk';
import { PostgreSQLUserStore } from './adapters/userStore.js';
import { PostgreSQLMessageStore } from './adapters/messageStore.js';
import { PostgreSQLGroupStore } from './adapters/groupStore.js';

async function main() {
  console.log('🗄️  Chatly SDK - PostgreSQL Integration');
  console.log('======================================\n');

  // Create PostgreSQL connection pool
  console.log('Connecting to PostgreSQL...');
  const pool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'chatly',
    user: 'postgres',      // Update with your credentials
    password: 'password',  // Update with your credentials
    max: 20,
    min: 5,
  });

  // Test connection
  try {
    await pool.query('SELECT NOW()');
    console.log('✅ Connected to database: chatly\n');
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    console.log('\n💡 Make sure PostgreSQL is running and database exists:');
    console.log('   createdb chatly');
    console.log('   psql chatly < schema.sql');
    process.exit(1);
  }

  // Initialize SDK with PostgreSQL adapters
  const sdk = new ChatSDK({
    userStore: new PostgreSQLUserStore(pool),
    messageStore: new PostgreSQLMessageStore(pool),
    groupStore: new PostgreSQLGroupStore(pool),
    logLevel: LogLevel.NONE,
  });

  // Create users
  console.log('Creating users in database...');
  const alice = await sdk.createUser('alice-pg');
  const bob = await sdk.createUser('bob-pg');
  console.log('✅ Alice saved to PostgreSQL');
  console.log('✅ Bob saved to PostgreSQL\n');

  // Start session
  const session = await sdk.startSession(alice, bob);

  // Send messages
  console.log('Sending encrypted messages...');
  sdk.setCurrentUser(alice);
  
  await sdk.sendMessage(session, 'Hello from PostgreSQL!');
  console.log('📤 Message 1 saved to database');
  
  await sdk.sendMessage(session, 'Messages are persisted');
  console.log('📤 Message 2 saved to database');
  
  await sdk.sendMessage(session, 'Even after restart!');
  console.log('📤 Message 3 saved to database\n');

  // Retrieve messages
  console.log('Retrieving messages from database...');
  sdk.setCurrentUser(bob);
  
  const messages = await sdk.getMessagesForUser(bob.id);
  console.log(`📨 Retrieved ${messages.length} messages from PostgreSQL`);
  
  for (const msg of messages) {
    const plaintext = await sdk.decryptMessage(msg, bob);
    console.log(`📨 Decrypted: ${plaintext}`);
  }
  console.log();

  console.log('✅ PostgreSQL integration works!');
  console.log('\n💡 Key Features:');
  console.log('   - Messages persisted in PostgreSQL');
  console.log('   - Connection pooling for performance');
  console.log('   - Transactions for data integrity');
  console.log('   - Indexes for fast queries');

  // Cleanup
  await pool.end();
  console.log('\n🔌 Database connection closed');
}

main().catch(console.error);
