import type { Message } from "../models/message.js";
import type { TransportAdapter } from "./adapters.js";

type MessageHandler = (message: Message) => void;

export class InMemoryTransport implements TransportAdapter {
  private handler?: MessageHandler;
  private connected = false;

  async connect(_userId: string): Promise<void> {
    this.connected = true;
  }

  async send(message: Message): Promise<void> {
    if (!this.connected) {
      throw new Error("Transport not connected");
    }
    this.handler?.(message);
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }
}
