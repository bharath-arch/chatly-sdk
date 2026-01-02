import type { User } from "../models/user.js";
import type { Message } from "../models/message.js";
import type { MediaAttachment } from "../models/mediaTypes.js";
import { deriveSharedSecret, deriveLegacySharedSecret, encryptMessage, decryptMessage } from "../crypto/e2e.js";
import type { KeyPair } from "../crypto/keys.js";
import { generateUUID } from "../crypto/uuid.js";
import type { StorageProvider } from "../storage/adapters.js";
import { logger } from "../utils/logger.js";

export class ChatSession {
  private sharedSecret: Buffer | null = null;
  private ephemeralKeyPair: KeyPair | null = null;

  constructor(
    public readonly id: string,
    public readonly userA: User,
    public readonly userB: User,
    private storageProvider?: StorageProvider
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
    
    logger.debug(`[ChatSession] Initializing for user ${user.id}`, {
      hasLocalPriv: !!user.privateKey,
      privType: typeof user.privateKey,
      hasRemotePub: !!otherUser.publicKey,
      pubType: typeof otherUser.publicKey
    });
    
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
   * Encrypt a media message for this session
   */
  async encryptMedia(
    plaintext: string,
    media: MediaAttachment,
    senderId: string
  ): Promise<Message> {
    if (!this.sharedSecret) {
      await this.initialize();
    }

    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }

    // Encrypt the message text (could be caption)
    const { ciphertext, iv } = encryptMessage(plaintext, this.sharedSecret);

    // Encrypt the media data with its own IV
    const { ciphertext: encryptedMediaData, iv: mediaIv } = encryptMessage(
      media.data || "",
      this.sharedSecret
    );

    // Create encrypted media attachment
    const encryptedMedia: MediaAttachment = {
      ...media,
      data: encryptedMediaData,
      iv: mediaIv,
    };

    // If storage provider is available, upload the encrypted data
    if (this.storageProvider) {
      const filename = `${this.id}/${generateUUID()}-${media.metadata.filename}`;
      const uploadResult = await this.storageProvider.upload(
        encryptedMediaData,
        filename,
        media.metadata.mimeType
      );
      
      encryptedMedia.storage = this.storageProvider.name as 'local' | 's3';
      encryptedMedia.storageKey = uploadResult.storageKey;
      encryptedMedia.url = uploadResult.url;
      encryptedMedia.data = undefined; // Remove data from attachment if stored remotely
    }

    return {
      id: generateUUID(),
      senderId,
      receiverId: senderId === this.userA.id ? this.userB.id : this.userA.id,
      ciphertext,
      iv,
      timestamp: Date.now(),
      type: "media",
      media: encryptedMedia,
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

    try {
      return decryptMessage(message.ciphertext, message.iv, this.sharedSecret);
    } catch (error) {
      // Fallback for legacy messages (before salt logic)
      const legacySecret = this.deriveLegacySecret(user);
      try {
        return decryptMessage(message.ciphertext, message.iv, legacySecret);
      } catch (innerError) {
        throw error; // Throw original error if fallback also fails
      }
    }
  }

  private deriveLegacySecret(user: User): Buffer {
    const otherUser = user.id === this.userA.id ? this.userB : this.userA;
    logger.debug(`[ChatSession] Deriving legacy secret for user ${user.id}`, {
      hasPriv: !!user.privateKey,
      privType: typeof user.privateKey,
      remotePubType: typeof otherUser.publicKey
    });
    const localKeyPair: KeyPair = {
      publicKey: user.publicKey,
      privateKey: user.privateKey,
    };
    return deriveLegacySharedSecret(localKeyPair, otherUser.publicKey);
  }

  /**
   * Decrypt a media message in this session
   */
  async decryptMedia(message: Message, user: User): Promise<{ text: string; media: MediaAttachment }> {
    if (!message.media) {
      throw new Error("Message does not contain media");
    }

    // Re-initialize if needed
    if (!this.sharedSecret || 
        (user.id !== this.userA.id && user.id !== this.userB.id)) {
      await this.initializeForUser(user);
    }

    if (!this.sharedSecret) {
      throw new Error("Failed to initialize session");
    }

    // Decrypt the message text
    const text = decryptMessage(message.ciphertext, message.iv, this.sharedSecret);

    let encryptedMediaData = message.media.data;

    // If data is missing but storageKey is present, download it
    if (!encryptedMediaData && message.media.storageKey && this.storageProvider) {
      encryptedMediaData = await this.storageProvider.download(message.media.storageKey);
    }

    // Decrypt the media data using its own IV
    if (!message.media.iv && !encryptedMediaData) {
        throw new Error("Media data or IV missing");
    }

    let decryptedMediaData: string;
    try {
      decryptedMediaData = decryptMessage(
        encryptedMediaData || "",
        message.media.iv || message.iv,
        this.sharedSecret
      );
    } catch (error) {
      // Fallback for legacy media
      const legacySecret = this.deriveLegacySecret(user);
      try {
        decryptedMediaData = decryptMessage(
          encryptedMediaData || "",
          message.media.iv || message.iv,
          legacySecret
        );
      } catch (innerError) {
        throw error;
      }
    }

    // Create decrypted media attachment
    const decryptedMedia: MediaAttachment = {
      ...message.media,
      data: decryptedMediaData,
    };

    return { text, media: decryptedMedia };
  }
}
