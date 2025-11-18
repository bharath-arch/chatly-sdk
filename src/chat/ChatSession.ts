import type { User } from "../models/user.js";
import type { Message } from "../models/message.js";
import { deriveSharedSecret, encryptMessage, decryptMessage } from "../crypto/e2e.js";
import type { KeyPair } from "../crypto/keys.js";
import { generateUUID } from "../crypto/uuid.js";

export class ChatSession {
  private sharedSecret: Buffer | null = null;
  private ephemeralKeyPair: KeyPair | null = null;

  constructor(
    public readonly id: string,
    public readonly userA: User,
    public readonly userB: User
  ) {}

  /**
   * Initialize the session by deriving the shared secret
   * ECDH is commutative, so we can use either user's keys
   */
  async initialize(): Promise<void> {
    // For 1:1 chat, derive shared secret from identity keys
    // Use userA's private key and userB's public key
    // (ECDH is commutative, so userB could also use their private key and userA's public key)
    const localKeyPair: KeyPair = {
      publicKey: this.userA.publicKey,
      privateKey: this.userA.privateKey,
    };
    
    this.sharedSecret = deriveSharedSecret(localKeyPair, this.userB.publicKey);
  }

  /**
   * Initialize from a specific user's perspective (useful when decrypting)
   */
  async initializeForUser(user: User): Promise<void> {
    const otherUser = user.id === this.userA.id ? this.userB : this.userA;
    const localKeyPair: KeyPair = {
      publicKey: user.publicKey,
      privateKey: user.privateKey,
    };
    
    this.sharedSecret = deriveSharedSecret(localKeyPair, otherUser.publicKey);
  }

  /**
   * Encrypt a message for this session
   */
  async encrypt(plaintext: string, senderId: string): Promise<Message> {
    if (!this.sharedSecret) {
      await this.initialize();
    }

    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }

    const { ciphertext, iv } = encryptMessage(plaintext, this.sharedSecret);

    return {
      id: generateUUID(),
      senderId,
      receiverId: senderId === this.userA.id ? this.userB.id : this.userA.id,
      ciphertext,
      iv,
      timestamp: Date.now(),
      type: "text",
    };
  }

  /**
   * Decrypt a message in this session
   */
  async decrypt(message: Message, user: User): Promise<string> {
    // Re-initialize from the decrypting user's perspective if needed
    // (though ECDH is commutative, this ensures we're using the right keys)
    if (!this.sharedSecret || 
        (user.id !== this.userA.id && user.id !== this.userB.id)) {
      await this.initializeForUser(user);
    }

    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }

    return decryptMessage(message.ciphertext, message.iv, this.sharedSecret);
  }
}
