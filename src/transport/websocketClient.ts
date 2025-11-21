import { Message } from "../models/message.js";
import { TransportAdapter } from "./adapters.js";
import {
  ConnectionState,
  RECONNECT_MAX_ATTEMPTS,
  RECONNECT_BASE_DELAY,
  RECONNECT_MAX_DELAY,
  HEARTBEAT_INTERVAL,
  CONNECTION_TIMEOUT,
} from "../constants.js";
import { NetworkError, TransportError } from "../utils/errors.js";
import { logger } from "../utils/logger.js";

export class WebSocketClient implements TransportAdapter {
  private ws: WebSocket | null = null;
  private url: string;
  private messageHandler: ((message: Message) => void) | null = null;
  private stateHandler: ((state: ConnectionState) => void) | null = null;
  private errorHandler: ((error: Error) => void) | null = null;
  private connectionState: ConnectionState = ConnectionState.DISCONNECTED;
  private reconnectAttempts: number = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private currentUserId: string | null = null;
  private shouldReconnect: boolean = true;

  constructor(url: string) {
    this.url = url;
  }

  async connect(userId: string): Promise<void> {
    this.currentUserId = userId;
    this.shouldReconnect = true;
    return this.doConnect();
  }

  private async doConnect(): Promise<void> {
    if (this.connectionState === ConnectionState.CONNECTING) {
      logger.warn('Already connecting, skipping duplicate connect attempt');
      return;
    }

    this.updateState(ConnectionState.CONNECTING);
    logger.info('Connecting to WebSocket', { url: this.url, userId: this.currentUserId });

    return new Promise((resolve, reject) => {
      try {
        const wsUrl = this.currentUserId 
          ? `${this.url}?userId=${this.currentUserId}`
          : this.url;
        
        this.ws = new WebSocket(wsUrl);

        const connectionTimeout = setTimeout(() => {
          if (this.connectionState === ConnectionState.CONNECTING) {
            this.ws?.close();
            const error = new NetworkError('Connection timeout');
            this.handleError(error);
            reject(error);
          }
        }, CONNECTION_TIMEOUT);

        this.ws.onopen = () => {
          clearTimeout(connectionTimeout);
          this.reconnectAttempts = 0;
          this.updateState(ConnectionState.CONNECTED);
          logger.info('WebSocket connected');
          this.startHeartbeat();
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            
            // Handle pong response
            if (message.type === 'pong') {
              logger.debug('Received pong');
              return;
            }

            if (this.messageHandler) {
              this.messageHandler(message);
            }
          } catch (error) {
            const parseError = new TransportError(
              'Failed to parse message',
              false,
              { error: error instanceof Error ? error.message : String(error) }
            );
            logger.error('Message parse error', parseError);
            this.handleError(parseError);
          }
        };

        this.ws.onerror = (event) => {
          clearTimeout(connectionTimeout);
          const error = new NetworkError('WebSocket error', {
            event: event.type,
          });
          logger.error('WebSocket error', error);
          this.handleError(error);
          reject(error);
        };

        this.ws.onclose = (event) => {
          clearTimeout(connectionTimeout);
          this.stopHeartbeat();
          logger.info('WebSocket closed', {
            code: event.code,
            reason: event.reason,
            wasClean: event.wasClean,
          });

          if (this.connectionState !== ConnectionState.DISCONNECTED) {
            this.updateState(ConnectionState.DISCONNECTED);
            
            // Attempt reconnection if not manually disconnected
            if (this.shouldReconnect && this.reconnectAttempts < RECONNECT_MAX_ATTEMPTS) {
              this.scheduleReconnect();
            } else if (this.reconnectAttempts >= RECONNECT_MAX_ATTEMPTS) {
              this.updateState(ConnectionState.FAILED);
              const error = new NetworkError('Max reconnection attempts exceeded');
              this.handleError(error);
            }
          }
        };
      } catch (error) {
        const connectError = new NetworkError(
          'Failed to create WebSocket connection',
          { error: error instanceof Error ? error.message : String(error) }
        );
        logger.error('Connection error', connectError);
        this.handleError(connectError);
        reject(connectError);
      }
    });
  }

  async disconnect(): Promise<void> {
    logger.info('Disconnecting WebSocket');
    this.shouldReconnect = false;
    this.clearReconnectTimer();
    this.stopHeartbeat();

    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }

    this.updateState(ConnectionState.DISCONNECTED);
  }

  async reconnect(): Promise<void> {
    logger.info('Manual reconnect requested');
    this.reconnectAttempts = 0;
    this.shouldReconnect = true;
    await this.disconnect();
    
    if (this.currentUserId) {
      await this.doConnect();
    } else {
      throw new TransportError('Cannot reconnect: no user ID set');
    }
  }

  private scheduleReconnect(): void {
    this.clearReconnectTimer();
    this.reconnectAttempts++;
    
    // Exponential backoff with jitter
    const delay = Math.min(
      RECONNECT_BASE_DELAY * Math.pow(2, this.reconnectAttempts - 1),
      RECONNECT_MAX_DELAY
    );
    const jitter = Math.random() * 1000;
    const totalDelay = delay + jitter;

    logger.info('Scheduling reconnect', {
      attempt: this.reconnectAttempts,
      delay: totalDelay,
    });

    this.updateState(ConnectionState.RECONNECTING);

    this.reconnectTimer = setTimeout(async () => {
      try {
        await this.doConnect();
      } catch (error) {
        logger.error('Reconnect failed', error);
      }
    }, totalDelay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    
    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected()) {
        try {
          this.ws?.send(JSON.stringify({ type: 'ping' }));
          logger.debug('Sent ping');
        } catch (error) {
          logger.error('Failed to send heartbeat', error);
        }
      }
    }, HEARTBEAT_INTERVAL);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  async send(message: Message): Promise<void> {
    if (!this.isConnected() || !this.ws) {
      throw new NetworkError('WebSocket not connected');
    }

    try {
      this.ws.send(JSON.stringify(message));
      logger.debug('Message sent', { messageId: message.id });
    } catch (error) {
      const sendError = new NetworkError(
        'Failed to send message',
        { error: error instanceof Error ? error.message : String(error) }
      );
      logger.error('Send error', sendError);
      throw sendError;
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
    return (
      this.connectionState === ConnectionState.CONNECTED &&
      this.ws?.readyState === WebSocket.OPEN
    );
  }

  private updateState(newState: ConnectionState): void {
    if (this.connectionState !== newState) {
      const oldState = this.connectionState;
      this.connectionState = newState;
      logger.info('Connection state changed', {
        from: oldState,
        to: newState,
      });
      
      if (this.stateHandler) {
        this.stateHandler(newState);
      }
    }
  }

  private handleError(error: Error): void {
    if (this.errorHandler) {
      this.errorHandler(error);
    }
  }
}
