export function bufferToBase64(buffer: Buffer): string {
  return buffer.toString("base64");
}

export function base64ToBuffer(data: string | Buffer): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (!data) return Buffer.alloc(0);
  return Buffer.from(data, "base64");
}
