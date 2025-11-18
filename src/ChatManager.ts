
import { KeyManager, KeyPair } from './crypto/keyManager';
import { encrypt } from './crypto/encrypt';
import { decrypt } from './crypto/decrypt';
import { ChatClient } from './transport/websocketClient';
import { Message } from './models/Message';

export class ChatManager {
  private keyManager: KeyManager;
  private chatClient: ChatClient;
  private contacts: { [id: string]: Uint8Array } = {}; // Maps user ID to public key

  constructor(websocketUrl: string) {
    this.keyManager = new KeyManager();
    this.chatClient = new ChatClient(websocketUrl);
  }

  async initialize(): Promise<void> {
    await this.keyManager.generateKeys();
    this.chatClient.connect();
    this.chatClient.onMessage(this.handleIncomingMessage.bind(this));
  }

  addContact(userId: string, publicKey: Uint8Array): void {
    this.contacts[userId] = publicKey;
  }

  async sendMessage(recipientId: string, content: string): Promise<void> {
    const recipientPublicKey = this.contacts[recipientId];
    if (!recipientPublicKey) {
      throw new Error(`Contact not found: ${recipientId}`);
    }

    const senderPrivateKey = this.keyManager.getPrivateKey();
    if (!senderPrivateKey) {
      throw new Error('Sender keys not generated.');
    }

    const message: Message = {
      id: Date.now().toString(),
      senderId: this.getOwnUserId(),
      recipientId,
      content,
      timestamp: Date.now(),
    };

    const encryptedMessage = await encrypt(
      JSON.stringify(message),
      recipientPublicKey,
      senderPrivateKey
    );

    this.chatClient.sendMessage(Buffer.from(encryptedMessage));
  }

  private async handleIncomingMessage(encryptedMessage: Buffer): Promise<void> {
    // In a real application, you would need a way to identify the sender
    // and get their public key. For this example, we'll assume the sender
    // is the only other contact.
    const senderId = Object.keys(this.contacts)[0];
    if (!senderId) {
      console.error('Received message but no contacts are known.');
      return;
    }
    const senderPublicKey = this.contacts[senderId];

    if (!senderPublicKey) {
      console.error('Received message from unknown sender.');
      return;
    }

    const recipientPrivateKey = this.keyManager.getPrivateKey();
    if (!recipientPrivateKey) {
      throw new Error('Recipient keys not generated.');
    }

    try {
      const decryptedMessageJson = await decrypt(
        encryptedMessage,
        senderPublicKey,
        recipientPrivateKey
      );
      const message: Message = JSON.parse(decryptedMessageJson);
      console.log('Decrypted message:', message);
    } catch (error) {
      console.error('Failed to decrypt message:', error);
    }
  }

  getOwnUserId(): string {
    // In a real app, this would be a unique user ID.
    // For this example, we'll use a hash of the public key.
    const publicKey = this.keyManager.getPublicKey();
    if (!publicKey) {
      throw new Error('Keys not generated.');
    }
    return Buffer.from(publicKey).toString('hex');
  }

  getOwnPublicKey(): Uint8Array | null {
    return this.keyManager.getPublicKey();
  }
}
