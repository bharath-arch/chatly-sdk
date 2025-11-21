import { MediaType, MediaMetadata, MediaAttachment, SUPPORTED_MIME_TYPES, FILE_SIZE_LIMITS } from '../models/mediaTypes.js';
import { ValidationError } from './errors.js';

/**
 * Convert File or Blob to base64 string
 */
export async function encodeFileToBase64(file: File | Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      if (!result) {
        reject(new Error('Failed to read file: result is null'));
        return;
      }
      const base64 = result.split(',')[1];
      if (!base64) {
        reject(new Error('Failed to extract base64 data'));
        return;
      }
      resolve(base64);
    };
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsDataURL(file);
  });
}

/**
 * Convert base64 string to Blob
 */
export function decodeBase64ToBlob(base64: string, mimeType: string): Blob {
  const byteCharacters = atob(base64);
  const byteNumbers = new Array(byteCharacters.length);
  
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  
  const byteArray = new Uint8Array(byteNumbers);
  return new Blob([byteArray], { type: mimeType });
}

/**
 * Detect media type from MIME type
 */
export function getMediaType(mimeType: string): MediaType {
  if (SUPPORTED_MIME_TYPES.image.includes(mimeType)) {
    return MediaType.IMAGE;
  }
  if (SUPPORTED_MIME_TYPES.audio.includes(mimeType)) {
    return MediaType.AUDIO;
  }
  if (SUPPORTED_MIME_TYPES.video.includes(mimeType)) {
    return MediaType.VIDEO;
  }
  if (SUPPORTED_MIME_TYPES.document.includes(mimeType)) {
    return MediaType.DOCUMENT;
  }
  throw new ValidationError(`Unsupported MIME type: ${mimeType}`);
}

/**
 * Validate media file
 */
export function validateMediaFile(file: File | Blob, filename?: string): void {
  const mimeType = file.type;
  
  // Check if MIME type is supported
  const mediaType = getMediaType(mimeType);
  
  // Check file size
  const maxSize = FILE_SIZE_LIMITS[mediaType];
  if (file.size > maxSize) {
    throw new ValidationError(
      `File size exceeds limit. Max size for ${mediaType}: ${maxSize / 1024 / 1024}MB`
    );
  }
  
  // Validate filename if provided
  if (filename && filename.length > 255) {
    throw new ValidationError('Filename too long (max 255 characters)');
  }
}

/**
 * Create media metadata from file
 */
export async function createMediaMetadata(
  file: File | Blob,
  filename?: string
): Promise<MediaMetadata> {
  const actualFilename = filename || (file instanceof File ? file.name : 'file');
  
  const metadata: MediaMetadata = {
    filename: actualFilename,
    mimeType: file.type,
    size: file.size,
  };
  
  // For images, try to get dimensions
  if (file.type.startsWith('image/')) {
    try {
      const dimensions = await getImageDimensions(file);
      metadata.width = dimensions.width;
      metadata.height = dimensions.height;
      
      // Generate thumbnail for images
      metadata.thumbnail = await generateThumbnail(file);
    } catch (error) {
      // Dimensions optional, continue without them
    }
  }
  
  // For audio/video, duration would need to be provided by the caller
  // as we can't reliably get it in Node.js without external libraries
  
  return metadata;
}

/**
 * Get image dimensions
 */
function getImageDimensions(file: Blob): Promise<{ width: number; height: number }> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve({ width: img.width, height: img.height });
    };
    
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('Failed to load image'));
    };
    
    img.src = url;
  });
}

/**
 * Generate thumbnail for image (max 200x200)
 */
async function generateThumbnail(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    
    img.onload = () => {
      URL.revokeObjectURL(url);
      
      // Calculate thumbnail size (max 200x200, maintain aspect ratio)
      const maxSize = 200;
      let width = img.width;
      let height = img.height;
      
      if (width > height) {
        if (width > maxSize) {
          height = (height * maxSize) / width;
          width = maxSize;
        }
      } else {
        if (height > maxSize) {
          width = (width * maxSize) / height;
          height = maxSize;
        }
      }
      
      // Create canvas and draw thumbnail
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      
      if (!ctx) {
        reject(new Error('Failed to get canvas context'));
        return;
      }
      
      ctx.drawImage(img, 0, 0, width, height);
      
      // Convert to base64
      const dataUrl = canvas.toDataURL('image/jpeg', 0.7);
      const thumbnail = dataUrl.split(',')[1];
      if (!thumbnail) {
        reject(new Error('Failed to generate thumbnail'));
        return;
      }
      resolve(thumbnail);
    };
    
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('Failed to load image for thumbnail'));
    };
    
    img.src = url;
  });
}

/**
 * Create media attachment from file
 */
export async function createMediaAttachment(
  file: File | Blob,
  filename?: string
): Promise<MediaAttachment> {
  // Validate file
  validateMediaFile(file, filename);
  
  // Get media type
  const mediaType = getMediaType(file.type);
  
  // Encode file to base64
  const data = await encodeFileToBase64(file);
  
  // Create metadata
  const metadata = await createMediaMetadata(file, filename);
  
  return {
    type: mediaType,
    data,
    metadata,
  };
}

/**
 * Format file size for display
 */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
