import { ChatSDK } from "../src/index.js";
import {
  InMemoryUserStore,
  InMemoryMessageStore,
  InMemoryGroupStore,
} from "../src/index.js";
import { InMemoryTransport } from "../src/index.js";

/**
 * Example: Group Chat with multiple members
 */
async function main() {
  // Initialize SDK
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
    transport: new InMemoryTransport(),
  });

  // Create users
  console.log("Creating users...");
  const alice = await sdk.createUser("alice");
  const bob = await sdk.createUser("bob");
  const charlie = await sdk.createUser("charlie");

  console.log(`Alice: ${alice.id}`);
  console.log(`Bob: ${bob.id}`);
  console.log(`Charlie: ${charlie.id}`);

  // Create a group
  console.log("\nCreating group...");
  const group = await sdk.createGroup("Project Team", [alice, bob, charlie]);
  console.log(`Group created: ${group.group.id} - ${group.group.name}`);
  console.log(`Members: ${group.group.members.map((m) => m.username).join(", ")}`);

  // Alice sends a message to the group
  console.log("\nAlice sending group message...");
  sdk.setCurrentUser(alice);
  const message1 = await sdk.sendMessage(group, "Hello team! Let's start the project.");
  console.log(`Message sent: ${message1.id}`);

  // Bob reads the group message
  console.log("\nBob reading group messages...");
  sdk.setCurrentUser(bob);
  const bobMessages = await sdk.getMessagesForGroup(group.group.id);
  for (const msg of bobMessages) {
    const decrypted = await sdk.decryptMessage(msg, bob);
    console.log(`Bob sees: "${decrypted}" from ${msg.senderId}`);
  }

  // Charlie replies
  console.log("\nCharlie replying...");
  sdk.setCurrentUser(charlie);
  const message2 = await sdk.sendMessage(group, "Sounds good! I'm ready.");
  console.log(`Message sent: ${message2.id}`);

  // Alice reads all messages
  console.log("\nAlice reading all group messages...");
  sdk.setCurrentUser(alice);
  const allMessages = await sdk.getMessagesForGroup(group.group.id);
  console.log(`Total messages: ${allMessages.length}`);
  for (const msg of allMessages) {
    const decrypted = await sdk.decryptMessage(msg, alice);
    const sender = group.group.members.find((m) => m.id === msg.senderId);
    console.log(`${sender?.username || "Unknown"}: "${decrypted}"`);
  }
}

main().catch(console.error);

