import type { Group } from "../models/group.js";
import type { Message } from "../models/message.js";
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
}
