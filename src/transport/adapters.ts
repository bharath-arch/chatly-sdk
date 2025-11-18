import type { Message } from "../models/message.js";

export interface TransportAdapter {
  connect(userId: string): Promise<void>;
  send(message: Message): Promise<void>;
  onMessage(handler: (message: Message) => void): void;
}
