import type { User, StoredUser } from "../models/user.js";
import type { Message } from "../models/message.js";
import type { Group } from "../models/group.js";

export interface UserStoreAdapter {
  create(user: User): Promise<User>;
  findById(id: string): Promise<User | undefined>;
  save(user: StoredUser): Promise<void>;
  list(): Promise<User[]>;
}

export interface MessageStoreAdapter {
  create(message: Message): Promise<Message>;
  listByUser(userId: string): Promise<Message[]>;
  listByGroup(groupId: string): Promise<Message[]>;
}

export interface GroupStoreAdapter {
  create(group: Group): Promise<Group>;
  findById(id: string): Promise<Group | undefined>;
  list(): Promise<Group[]>;
}
