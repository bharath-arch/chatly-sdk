import { Message } from "../models/message.js";
import { TransportAdapter } from "./adapters.js";
import { ConnectionState } from "../constants.js";

/**
 * In-memory transport for testing (no actual network communication)
 */
export class InMemoryTransport implements TransportAdapter {
  private messageHandler: ((message: Message) => void) | null = null;
  private connectionState: ConnectionState = ConnectionState.DISCONNECTED;
  private stateHandler: ((state: ConnectionState) => void) | null = null;
  private errorHandler: ((error: Error) => void) | null = null;

  async connect(userId: string): Promise<void> {
    this.connectionState = ConnectionState.CONNECTED;
    if (this.stateHandler) {
      this.stateHandler(this.connectionState);
    }
  }

  async disconnect(): Promise<void> {
    this.connectionState = ConnectionState.DISCONNECTED;
    if (this.stateHandler) {
      this.stateHandler(this.connectionState);
    }
  }

  async reconnect(): Promise<void> {
    this.connectionState = ConnectionState.CONNECTING;
    if (this.stateHandler) {
      this.stateHandler(this.connectionState);
    }
    
    // Simulate reconnection delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    this.connectionState = ConnectionState.CONNECTED;
    if (this.stateHandler) {
      this.stateHandler(this.connectionState);
    }
  }

  async send(message: Message): Promise<void> {
    // In-memory transport just echoes back the message
    if (this.messageHandler) {
      // Simulate async delivery
      setTimeout(() => {
        this.messageHandler!(message);
      }, 10);
    }
  }

  onMessage(handler: (message: Message) => void): void {
    this.messageHandler = handler;
  }

  onConnectionStateChange(handler: (state: ConnectionState) => void): void {
    this.stateHandler = handler;
  }

  onError(handler: (error: Error) => void): void {
    this.errorHandler = handler;
  }

  getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  isConnected(): boolean {
    return this.connectionState === ConnectionState.CONNECTED;
  }

  // Test helper to simulate receiving a message
  simulateReceive(message: Message): void {
    if (this.messageHandler) {
      this.messageHandler(message);
    }
  }

  // Test helper to simulate an error
  simulateError(error: Error): void {
    if (this.errorHandler) {
      this.errorHandler(error);
    }
  }
}
