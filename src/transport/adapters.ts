import { Message } from "../models/message.js";
import { ConnectionState } from "../constants.js";

/**
 * Transport adapter interface for network communication
 */
export interface TransportAdapter {
  /**
   * Connect to the transport
   * @param userId - User ID to connect as
   */
  connect(userId: string): Promise<void>;

  /**
   * Disconnect from the transport
   */
  disconnect(): Promise<void>;

  /**
   * Reconnect to the transport
   */
  reconnect(): Promise<void>;

  /**
   * Send a message
   * @param message - Message to send
   */
  send(message: Message): Promise<void>;

  /**
   * Register a message handler
   * @param handler - Function to call when a message is received
   */
  onMessage(handler: (message: Message) => void): void;

  /**
   * Register a connection state change handler
   * @param handler - Function to call when connection state changes
   */
  onConnectionStateChange?(handler: (state: ConnectionState) => void): void;

  /**
   * Register an error handler
   * @param handler - Function to call when an error occurs
   */
  onError?(handler: (error: Error) => void): void;

  /**
   * Get the current connection state
   */
  getConnectionState(): ConnectionState;

  /**
   * Check if transport is connected
   */
  isConnected(): boolean;
}
