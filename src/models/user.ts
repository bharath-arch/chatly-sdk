export interface User {
  id: string;
  username: string;
  identityKey: string;
  publicKey: string;
  privateKey: string;
}

export interface StoredUser extends User {
  createdAt: number;
}
