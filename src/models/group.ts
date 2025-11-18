import type { User } from "./user.js";

export interface Group {
  id: string;
  name: string;
  members: User[];
  createdAt: number;
}
