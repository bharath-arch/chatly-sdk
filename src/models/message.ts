export type MessageType = "text" | "system";

export interface Message {
  id: string;
  senderId: string;
  receiverId?: string;
  groupId?: string;
  ciphertext: string;
  iv: string;
  timestamp: number;
  type: MessageType;
}

