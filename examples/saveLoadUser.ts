import { ChatSDK } from "../src/index.js";
import {
  InMemoryUserStore,
  InMemoryMessageStore,
  InMemoryGroupStore,
} from "../src/index.js";
import type { StoredUser } from "../src/index.js";

/**
 * Example: Save and load user data
 */
async function main() {
  // Initialize SDK
  const sdk = new ChatSDK({
    userStore: new InMemoryUserStore(),
    messageStore: new InMemoryMessageStore(),
    groupStore: new InMemoryGroupStore(),
  });

  // Create a user
  console.log("Creating user...");
  const user = await sdk.createUser("john_doe");
  console.log(`User created: ${user.username} (${user.id})`);
  console.log(`Public key: ${user.publicKey.substring(0, 20)}...`);

  // Simulate saving user data (in real app, this would be to a database)
  const userStore = new InMemoryUserStore();
  const storedUser: StoredUser = {
    ...user,
    createdAt: Date.now(),
  };

  // Save user
  await userStore.save(storedUser);
  console.log("\nUser saved to store");

  // Simulate loading user from storage
  console.log("\nLoading user from store...");
  const loadedUser = await userStore.findById(user.id);
  if (loadedUser) {
    console.log(`User loaded: ${loadedUser.username} (${loadedUser.id})`);
    console.log(`Keys match: ${loadedUser.publicKey === user.publicKey}`);

    // Import the user into a new SDK instance
    const sdk2 = new ChatSDK({
      userStore: new InMemoryUserStore(),
      messageStore: new InMemoryMessageStore(),
      groupStore: new InMemoryGroupStore(),
    });

    const importedUser = await sdk2.importUser(loadedUser as StoredUser);
    console.log(`\nUser imported into new SDK instance: ${importedUser.username}`);
    sdk2.setCurrentUser(importedUser);
    console.log("User is now active in SDK2");
  } else {
    console.error("Failed to load user");
  }
}

main().catch(console.error);

