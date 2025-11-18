import { randomBytes, pbkdf2Sync } from "crypto";
import { bufferToBase64 } from "./utils.js";

export interface GroupKey {
  groupId: string;
  key: string;
}

const KEY_LENGTH = 32; // 256 bits
const PBKDF2_ITERATIONS = 100000;

/**
 * Derive a group shared key from the group ID
 */
export function deriveGroupKey(groupId: string): GroupKey {
  // Use PBKDF2 to derive a deterministic key from the group ID
  const salt = Buffer.from(groupId, "utf8");
  const key = pbkdf2Sync(groupId, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
  
  return {
    groupId,
    key: bufferToBase64(key),
  };
}
