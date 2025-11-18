
import WebSocket from 'ws';

export class ChatClient {
  private ws: WebSocket | null = null;
  private messageHandlers: ((message: Buffer) => void)[] = [];

  constructor(private url: string) {}

  connect(): void {
    this.ws = new WebSocket(this.url);

    this.ws.on('open', () => {
      console.log('Connected to WebSocket server');
    });

    this.ws.on('message', (message: Buffer) => {
      this.messageHandlers.forEach(handler => handler(message));
    });

    this.ws.on('close', () => {
      console.log('Disconnected from WebSocket server');
    });
  }

  sendMessage(message: string | Buffer): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(message);
    } else {
      console.error('WebSocket is not connected.');
    }
  }

  onMessage(handler: (message: Buffer) => void): void {
    this.messageHandlers.push(handler);
  }
}
