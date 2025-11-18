import type { Group } from "../../models/group.js";
import type { GroupStoreAdapter } from "../adapters.js";

export class InMemoryGroupStore implements GroupStoreAdapter {
  private groups = new Map<string, Group>();

  async create(group: Group): Promise<Group> {
    this.groups.set(group.id, group);
    return group;
  }

  async findById(id: string): Promise<Group | undefined> {
    return this.groups.get(id);
  }

  async list(): Promise<Group[]> {
    return Array.from(this.groups.values());
  }
}
