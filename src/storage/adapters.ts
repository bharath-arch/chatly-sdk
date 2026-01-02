export interface StorageUploadResult {
  storageKey: string;
  url?: string;
}

export interface StorageProvider {
  /**
   * Name of the storage provider (e.g., 'local', 's3')
   */
  readonly name: string;

  /**
   * Upload data to storage
   * @param data Base64 encoded data or Buffer
   * @param filename Desired filename or path
   * @param mimeType MIME type of the file
   */
  upload(
    data: string | Buffer,
    filename: string,
    mimeType: string
  ): Promise<StorageUploadResult>;

  /**
   * Download data from storage
   * @param storageKey Key/path of the file in storage
   * @returns Base64 encoded data
   */
  download(storageKey: string): Promise<string>;

  /**
   * Delete data from storage
   * @param storageKey Key/path of the file in storage
   */
  delete(storageKey: string): Promise<void>;
}
