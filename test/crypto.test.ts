import { encryptMessage, decryptMessage, deriveSharedSecret } from '../src/crypto/e2e';
import { generateIdentityKeyPair } from '../src/crypto/keys';

describe('End-to-End Encryption', () => {
  describe('Key Generation', () => {
    it('should generate a valid key pair', () => {
      const keyPair = generateIdentityKeyPair();
      
      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(typeof keyPair.publicKey).toBe('string');
      expect(typeof keyPair.privateKey).toBe('string');
      expect(keyPair.publicKey.length).toBeGreaterThan(0);
      expect(keyPair.privateKey.length).toBeGreaterThan(0);
    });

    it('should generate unique key pairs', () => {
      const keyPair1 = generateIdentityKeyPair();
      const keyPair2 = generateIdentityKeyPair();
      
      expect(keyPair1.publicKey).not.toBe(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toBe(keyPair2.privateKey);
    });
  });

  describe('Shared Secret Derivation', () => {
    it('should derive the same shared secret for both parties', async () => {
      const aliceKeys = generateIdentityKeyPair();
      const bobKeys = generateIdentityKeyPair();
      
      const aliceShared = await deriveSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
      const bobShared = await deriveSharedSecret(bobKeys.privateKey, aliceKeys.publicKey);
      
      expect(aliceShared).toBe(bobShared);
    });

    it('should derive different secrets for different key pairs', async () => {
      const aliceKeys = generateIdentityKeyPair();
      const bobKeys = generateIdentityKeyPair();
      const charlieKeys = generateIdentityKeyPair();
      
      const aliceBobSecret = await deriveSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
      const aliceCharlieSecret = await deriveSharedSecret(aliceKeys.privateKey, charlieKeys.publicKey);
      
      expect(aliceBobSecret).not.toBe(aliceCharlieSecret);
    });
  });

  describe('Message Encryption and Decryption', () => {
    it('should encrypt and decrypt a message correctly', async () => {
      const aliceKeys = generateIdentityKeyPair();
      const bobKeys = generateIdentityKeyPair();
      const sharedSecret = await deriveSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
      
      const plaintext = 'Hello, Bob!';
      const encrypted = await encryptMessage(plaintext, sharedSecret);
      
      expect(encrypted).toHaveProperty('ciphertext');
      expect(encrypted).toHaveProperty('iv');
      expect(typeof encrypted.ciphertext).toBe('string');
      expect(typeof encrypted.iv).toBe('string');
      
      const decrypted = await decryptMessage(encrypted.ciphertext, encrypted.iv, sharedSecret);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertexts for the same plaintext', async () => {
      const aliceKeys = generateIdentityKeyPair();
      const bobKeys = generateIdentityKeyPair();
      const sharedSecret = await deriveSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
      
      const plaintext = 'Hello, Bob!';
      const encrypted1 = await encryptMessage(plaintext, sharedSecret);
      const encrypted2 = await encryptMessage(plaintext, sharedSecret);
      
      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
    });

    it('should fail to decrypt with wrong shared secret', async () => {
      const aliceKeys = generateIdentityKeyPair();
      const bobKeys = generateIdentityKeyPair();
      const charlieKeys = generateIdentityKeyPair();
      
      const aliceBobSecret = await deriveSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
      const aliceCharlieSecret = await deriveSharedSecret(aliceKeys.privateKey, charlieKeys.publicKey);
      
      const plaintext = 'Secret message';
      const encrypted = await encryptMessage(plaintext, aliceBobSecret);
      
      await expect(
        decryptMessage(encrypted.ciphertext, encrypted.iv, aliceCharlieSecret)
      ).rejects.toThrow();
    });

    it('should handle empty messages', async () => {
      const aliceKeys = generateIdentityKeyPair();
      const bobKeys = generateIdentityKeyPair();
      const sharedSecret = await deriveSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
      
      const plaintext = '';
      const encrypted = await encryptMessage(plaintext, sharedSecret);
      const decrypted = await decryptMessage(encrypted.ciphertext, encrypted.iv, sharedSecret);
      
      expect(decrypted).toBe(plaintext);
    });

    it('should handle long messages', async () => {
      const aliceKeys = generateIdentityKeyPair();
      const bobKeys = generateIdentityKeyPair();
      const sharedSecret = await deriveSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
      
      const plaintext = 'A'.repeat(10000);
      const encrypted = await encryptMessage(plaintext, sharedSecret);
      const decrypted = await decryptMessage(encrypted.ciphertext, encrypted.iv, sharedSecret);
      
      expect(decrypted).toBe(plaintext);
    });

    it('should handle special characters and emojis', async () => {
      const aliceKeys = generateIdentityKeyPair();
      const bobKeys = generateIdentityKeyPair();
      const sharedSecret = await deriveSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
      
      const plaintext = 'Hello 👋 World! 🌍 Special chars: @#$%^&*()';
      const encrypted = await encryptMessage(plaintext, sharedSecret);
      const decrypted = await decryptMessage(encrypted.ciphertext, encrypted.iv, sharedSecret);
      
      expect(decrypted).toBe(plaintext);
    });
  });
});
