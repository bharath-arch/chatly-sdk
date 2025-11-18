import type { User, StoredUser } from "../../models/user.js";
import type { UserStoreAdapter } from "../adapters.js";

export class InMemoryUserStore implements UserStoreAdapter {
  private users = new Map<string, StoredUser>();

  async create(user: User): Promise<User> {
    const stored: StoredUser = { ...user, createdAt: Date.now() };
    this.users.set(stored.id, stored);
    return stored;
  }

  async findById(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async save(user: StoredUser): Promise<void> {
    this.users.set(user.id, user);
  }

  async list(): Promise<User[]> {
    return Array.from(this.users.values());
  }
}
