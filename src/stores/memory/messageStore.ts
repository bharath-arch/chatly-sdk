import type { Message } from "../../models/message.js";
import type { MessageStoreAdapter } from "../adapters.js";

export class InMemoryMessageStore implements MessageStoreAdapter {
  private messages: Message[] = [];

  async create(message: Message): Promise<Message> {
    this.messages.push(message);
    return message;
  }

  async listByUser(userId: string): Promise<Message[]> {
    return this.messages.filter(
      (msg) => msg.senderId === userId || msg.receiverId === userId
    );
  }

  async listByGroup(groupId: string): Promise<Message[]> {
    return this.messages.filter((msg) => msg.groupId === groupId);
  }
}
