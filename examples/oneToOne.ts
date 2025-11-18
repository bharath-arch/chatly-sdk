import { ChatSDK } from "../src/index.js";
import {
  InMemoryUserStore,
  InMemoryMessageStore,
  InMemoryGroupStore,
} from "../src/index.js";
import { InMemoryTransport } from "../src/index.js";

/**
 * Example: 1:1 Chat between two users
 */
async function main() {
  // Initialize SDK with in-memory stores
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    transport: new InMemoryTransport(),
  });

  // Create two users
  console.log("Creating users...");
  const alice = await sdk.createUser("alice");
  const bob = await sdk.createUser("bob");

  console.log(`Alice ID: ${alice.id}`);
  console.log(`Bob ID: ${bob.id}`);

  // Set Alice as current user
  sdk.setCurrentUser(alice);

  // Start a chat session between Alice and Bob
  console.log("\nStarting chat session...");
  const session = await sdk.startSession(alice, bob);

  // Alice sends a message to Bob
  console.log("\nAlice sending message...");
  const message1 = await sdk.sendMessage(session, "Hello Bob! This is encrypted.");
  console.log(`Message sent: ${message1.id}`);

  // Switch to Bob's perspective
  sdk.setCurrentUser(bob);

  // Bob receives and decrypts the message
  console.log("\nBob receiving messages...");
  const messages = await sdk.getMessagesForUser(bob.id);
  console.log(`Bob has ${messages.length} message(s)`);

  for (const msg of messages) {
    const decrypted = await sdk.decryptMessage(msg, bob);
    console.log(`Decrypted: "${decrypted}"`);
  }

  // Bob replies
  console.log("\nBob replying...");
  const replySession = await sdk.startSession(bob, alice);
  const message2 = await sdk.sendMessage(replySession, "Hi Alice! Got your message.");
  console.log(`Reply sent: ${message2.id}`);

  // Switch back to Alice
  sdk.setCurrentUser(alice);
  const aliceMessages = await sdk.getMessagesForUser(alice.id);
  console.log(`\nAlice has ${aliceMessages.length} message(s)`);

  for (const msg of aliceMessages) {
    const decrypted = await sdk.decryptMessage(msg, alice);
    console.log(`Decrypted: "${decrypted}"`);
  }
}

main().catch(console.error);

