  import { createECDH, createCipheriv, createDecipheriv, randomBytes, pbkdf2Sync } from "crypto";
  import type { KeyPair } from "./keys.js";
  import { base64ToBuffer, bufferToBase64 } from "./utils.js";
  import { SUPPORTED_CURVE } from "./keys.js";
  import { createHash } from "crypto";

  const ALGORITHM = "aes-256-gcm";
  const IV_LENGTH = 12; // 96 bits for GCM
  const SALT_LENGTH = 16;
  const KEY_LENGTH = 32; // 256 bits
  const TAG_LENGTH = 16;
  const PBKDF2_ITERATIONS = 100000;


  export function deriveSharedSecret(local: KeyPair, remotePublicKey: string): Buffer {
    const ecdh = createECDH(SUPPORTED_CURVE);
    ecdh.setPrivateKey(base64ToBuffer(local.privateKey));
  
    const remotePublicKeyBuffer = base64ToBuffer(remotePublicKey);
    const sharedSecret = ecdh.computeSecret(remotePublicKeyBuffer);
  
    // Deterministic salt: sort the two public-key buffers lexically,
    // then hash and take first SALT_LENGTH bytes.
    const a = base64ToBuffer(local.publicKey);
    const b = base64ToBuffer(remotePublicKey);
    const [first, second] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  
    const hash = createHash("sha256").update(first).update(second).digest();
    const salt = hash.slice(0, SALT_LENGTH);
  
    const derivedKey = pbkdf2Sync(sharedSecret, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
  
    return derivedKey;
  }

  /**
   * Legacy secret derivation without salt (for backward compatibility)
   */
  export function deriveLegacySharedSecret(local: KeyPair, remotePublicKey: string): Buffer {
    const ecdh = createECDH(SUPPORTED_CURVE);
    ecdh.setPrivateKey(base64ToBuffer(local.privateKey));
    return ecdh.computeSecret(base64ToBuffer(remotePublicKey));
  }

  /**
   * Encrypt a message using AES-GCM
   */
  export function encryptMessage(plaintext: string, secret: Buffer): { ciphertext: string; iv: string } {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, secret, iv);
    
    let ciphertext = cipher.update(plaintext, "utf8");
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    
    const tag = cipher.getAuthTag();
    
    // Combine ciphertext + tag
    const encrypted = Buffer.concat([ciphertext, tag]);
    
    return {
      ciphertext: bufferToBase64(encrypted),
      iv: bufferToBase64(iv),
    };
  }

  /**
   * Decrypt a message using AES-GCM
   */
  export function decryptMessage(ciphertext: string, iv: string, secret: Buffer): string {
    const encryptedBuffer = base64ToBuffer(ciphertext);
    const ivBuffer = base64ToBuffer(iv);
    
    // Extract tag from the end
    const tag = encryptedBuffer.slice(-TAG_LENGTH);
    const actualCiphertext = encryptedBuffer.slice(0, -TAG_LENGTH);
    
    const decipher = createDecipheriv(ALGORITHM, secret, ivBuffer);
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(actualCiphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted.toString("utf8");
  }
