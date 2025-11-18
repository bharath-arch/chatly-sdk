import { createECDH, randomBytes } from "crypto";
import { bufferToBase64, base64ToBuffer } from "./utils.js";

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface StoredKeyPair extends KeyPair {
  createdAt: number;
}

export const SUPPORTED_CURVE = "prime256v1";

/**
 * Generate a long-term identity key pair for a user
 */
export function generateIdentityKeyPair(): KeyPair {
  const ecdh = createECDH(SUPPORTED_CURVE);
  ecdh.generateKeys();
  
  return {
    publicKey: bufferToBase64(ecdh.getPublicKey()),
    privateKey: bufferToBase64(ecdh.getPrivateKey()),
  };
}

/**
 * Generate an ephemeral key pair for a session
 */
export function generateEphemeralKeyPair(): KeyPair {
  // Ephemeral keys use the same curve, but are meant to be temporary
  return generateIdentityKeyPair();
}
