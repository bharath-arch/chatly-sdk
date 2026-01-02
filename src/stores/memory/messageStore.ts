import type { Message } from "../../models/message.js";
import type { MessageStoreAdapter } from "../adapters.js";

export class InMemoryMessageStore implements MessageStoreAdapter {
  private messages: Message[] = [];

  async create(message: Message): Promise<Message> {
    this.messages.push(message);
    return message;
  }

  async findById(id: string): Promise<Message | undefined> {
    return this.messages.find((msg) => msg.id === id);
  }

  async listByUser(userId: string): Promise<Message[]> {
    return this.messages.filter(
      (msg) => msg.senderId === userId || msg.receiverId === userId
    );
  }

  async listByGroup(groupId: string): Promise<Message[]> {
    return this.messages.filter((msg) => msg.groupId === groupId);
  }

  async delete(id: string): Promise<void> {
    this.messages = this.messages.filter((msg) => msg.id !== id);
  }
}
