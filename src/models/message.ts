import type { MediaAttachment } from './mediaTypes.js';

export type MessageType = "text" | "media" | "system";

export interface Message {
  id: string;
  senderId: string;
  receiverId?: string;
  groupId?: string;
  ciphertext: string;
  iv: string;
  timestamp: number;
  type: MessageType;
  media?: MediaAttachment; // Optional media attachment
}

