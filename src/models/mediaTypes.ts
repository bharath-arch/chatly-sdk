/**
 * Media types supported by the SDK
 */
export enum MediaType {
  IMAGE = 'image',
  AUDIO = 'audio',
  VIDEO = 'video',
  DOCUMENT = 'document',
}

/**
 * Media metadata
 */
export interface MediaMetadata {
  filename: string;
  mimeType: string;
  size: number;
  width?: number;  // For images/videos
  height?: number; // For images/videos
  duration?: number; // For audio/video (in seconds)
  thumbnail?: string; // Base64 thumbnail for images/videos
}

/**
 * Media attachment
 */
export interface MediaAttachment {
  type: MediaType;
  data: string; // Base64 encoded file data
  metadata: MediaMetadata;
}

/**
 * Supported MIME types
 */
export const SUPPORTED_MIME_TYPES = {
  image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
  audio: ['audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/webm'],
  video: ['video/mp4', 'video/webm', 'video/ogg'],
  document: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain',
  ],
};

/**
 * File size limits (in bytes)
 */
export const FILE_SIZE_LIMITS = {
  image: 10 * 1024 * 1024,    // 10 MB
  audio: 16 * 1024 * 1024,    // 16 MB
  video: 100 * 1024 * 1024,   // 100 MB
  document: 100 * 1024 * 1024, // 100 MB
};
