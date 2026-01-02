import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { StorageProvider, StorageUploadResult } from './adapters.js';

export class LocalStorageProvider implements StorageProvider {
  public readonly name = 'local';
  private storageDir: string;

  constructor(storageDir: string = './storage') {
    this.storageDir = path.resolve(storageDir);
    // Ensure storage directory exists
    fs.mkdir(this.storageDir, { recursive: true }).catch(() => {});
  }

  async upload(
    data: string | Buffer,
    filename: string,
    mimeType: string
  ): Promise<StorageUploadResult> {
    const buffer = typeof data === 'string' ? Buffer.from(data, 'base64') : data;
    const filePath = path.join(this.storageDir, filename);
    
    // Ensure parent directories exist
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, buffer);

    return {
      storageKey: filename,
      url: `file://${filePath}`,
    };
  }

  async download(storageKey: string): Promise<string> {
    const filePath = path.join(this.storageDir, storageKey);
    const buffer = await fs.readFile(filePath);
    return buffer.toString('base64');
  }

  async delete(storageKey: string): Promise<void> {
    const filePath = path.join(this.storageDir, storageKey);
    try {
      await fs.unlink(filePath);
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }
}
