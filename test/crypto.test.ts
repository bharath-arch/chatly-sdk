
import assert from 'assert';
import { KeyManager } from '../src/crypto/keyManager';
import { encrypt } from '../src/crypto/encrypt';
import { decrypt } from '../src/crypto/decrypt';

async function testCrypto() {
  console.log('Running crypto tests...');

  // Test KeyManager
  const keyManager1 = new KeyManager();
  const keyManager2 = new KeyManager();

  await keyManager1.generateKeys();
  await keyManager2.generateKeys();

  const publicKey1 = keyManager1.getPublicKey();
  const privateKey1 = keyManager1.getPrivateKey();
  const publicKey2 = keyManager2.getPublicKey();
  const privateKey2 = keyManager2.getPrivateKey();

  assert(publicKey1, 'publicKey1 should not be null');
  assert(privateKey1, 'privateKey1 should not be null');
  assert(publicKey2, 'publicKey2 should not be null');
  assert(privateKey2, 'privateKey2 should not be null');

  console.log('KeyManager test passed.');

  // Test encrypt and decrypt
  const message = 'This is a secret message.';
  if (publicKey1 && privateKey1 && publicKey2 && privateKey2) {
    const encryptedMessage = await encrypt(message, publicKey2, privateKey1);
    const decryptedMessage = await decrypt(encryptedMessage, publicKey1, privateKey2);

    assert.strictEqual(decryptedMessage, message, 'Decrypted message should match original message.');
  } else {
    assert.fail('Keys should not be null');
  }

  console.log('Encrypt/decrypt test passed.');

  console.log('All crypto tests passed.');
}

testCrypto().catch(console.error);
