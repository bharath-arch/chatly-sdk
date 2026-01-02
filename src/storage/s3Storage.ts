import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { StorageProvider, StorageUploadResult } from './adapters.js';

export interface S3Config {
  region: string;
  bucket: string;
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
  };
  endpoint?: string;
  forcePathStyle?: boolean;
}

export class S3StorageProvider implements StorageProvider {
  public readonly name = 's3';
  private client: S3Client;
  private bucket: string;

  constructor(config: S3Config) {
    const s3Config: any = {
      region: config.region,
      forcePathStyle: config.forcePathStyle,
    };

    if (config.credentials) {
      s3Config.credentials = config.credentials;
    }

    if (config.endpoint) {
      s3Config.endpoint = config.endpoint;
    }

    this.client = new S3Client(s3Config);
    this.bucket = config.bucket;
  }

  async upload(
    data: string | Buffer,
    filename: string,
    mimeType: string
  ): Promise<StorageUploadResult> {
    const body = typeof data === 'string' ? Buffer.from(data, 'base64') : data;
    
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: filename,
        Body: body,
        ContentType: mimeType,
      })
    );

    return {
      storageKey: filename,
      url: `https://${this.bucket}.s3.amazonaws.com/${filename}`,
    };
  }

  async download(storageKey: string): Promise<string> {
    const response = await this.client.send(
      new GetObjectCommand({
        Bucket: this.bucket,
        Key: storageKey,
      })
    );

    if (!response.Body) {
      throw new Error('S3 download failed: empty body');
    }

    const bytes = await response.Body.transformToByteArray();
    return Buffer.from(bytes).toString('base64');
  }

  async delete(storageKey: string): Promise<void> {
    await this.client.send(
      new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: storageKey,
      })
    );
  }
}
