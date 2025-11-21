import type { Group } from "../models/group.js";
import type { Message } from "../models/message.js";
import type { MediaAttachment } from "../models/mediaTypes.js";
import { deriveGroupKey } from "../crypto/group.js";
import { encryptMessage, decryptMessage } from "../crypto/e2e.js";
import { base64ToBuffer } from "../crypto/utils.js";
import { generateUUID } from "../crypto/uuid.js";

export class GroupSession {
  private groupKey: Buffer | null = null;

  constructor(public readonly group: Group) {}

  /**
   * Initialize the session by deriving the group key
   */
  async initialize(): Promise<void> {
    const groupKeyData = deriveGroupKey(this.group.id);
    this.groupKey = base64ToBuffer(groupKeyData.key);
  }

  /**
   * Encrypt a message for this group
   */
  async encrypt(plaintext: string, senderId: string): Promise<Message> {
    if (!this.groupKey) {
      await this.initialize();
    }

    if (!this.groupKey) {
      throw new Error("Failed to initialize group session");
    }

    const { ciphertext, iv } = encryptMessage(plaintext, this.groupKey);

    return {
      id: generateUUID(),
      senderId,
      groupId: this.group.id,
      ciphertext,
      iv,
      timestamp: Date.now(),
      type: "text",
    };
  }

  /**
   * Encrypt a media message for this group
   */
  async encryptMedia(
    plaintext: string,
    media: MediaAttachment,
    senderId: string
  ): Promise<Message> {
    if (!this.groupKey) {
      await this.initialize();
    }

    if (!this.groupKey) {
      throw new Error("Failed to initialize group session");
    }

    // Encrypt the message text (could be caption)
    const { ciphertext, iv } = encryptMessage(plaintext, this.groupKey);

    // Encrypt the media data
    const { ciphertext: encryptedMediaData } = encryptMessage(
      media.data,
      this.groupKey
    );

    // Create encrypted media attachment
    const encryptedMedia: MediaAttachment = {
      ...media,
      data: encryptedMediaData,
    };

    return {
      id: generateUUID(),
      senderId,
      groupId: this.group.id,
      ciphertext,
      iv,
      timestamp: Date.now(),
      type: "media",
      media: encryptedMedia,
    };
  }

  /**
   * Decrypt a message in this group
   */
  async decrypt(message: Message): Promise<string> {
    if (!this.groupKey) {
      await this.initialize();
    }

    if (!this.groupKey) {
      throw new Error("Failed to initialize group session");
    }

    return decryptMessage(message.ciphertext, message.iv, this.groupKey);
  }

  /**
   * Decrypt a media message in this group
   */
  async decryptMedia(message: Message): Promise<{ text: string; media: MediaAttachment }> {
    if (!message.media) {
      throw new Error("Message does not contain media");
    }

    if (!this.groupKey) {
      await this.initialize();
    }

    if (!this.groupKey) {
      throw new Error("Failed to initialize group session");
    }

    // Decrypt the message text
    const text = decryptMessage(message.ciphertext, message.iv, this.groupKey);

    // Decrypt the media data
    const decryptedMediaData = decryptMessage(
      message.media.data,
      message.iv,
      this.groupKey
    );

    // Create decrypted media attachment
    const decryptedMedia: MediaAttachment = {
      ...message.media,
      data: decryptedMediaData,
    };

    return { text, media: decryptedMedia };
  }
}
