
import sodium from 'libsodium-wrappers';

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export class KeyManager {
  private keyPair: KeyPair | null = null;

  async generateKeys(): Promise<void> {
    await sodium.ready;
    const keys = sodium.crypto_box_keypair();
    this.keyPair = {
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
    };
  }

  getPublicKey(): Uint8Array | null {
    return this.keyPair ? this.keyPair.publicKey : null;
  }

  getPrivateKey(): Uint8Array | null {
    return this.keyPair ? this.keyPair.privateKey : null;
  }
}
