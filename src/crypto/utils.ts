export function bufferToBase64(buffer: Buffer): string {
  return buffer.toString("base64");
}

export function base64ToBuffer(data: string): Buffer {
  return Buffer.from(data, "base64");
}
