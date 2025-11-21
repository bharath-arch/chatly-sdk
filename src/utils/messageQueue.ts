import { Message } from '../models/message.js';
import { logger } from './logger.js';
import { MAX_QUEUE_SIZE, MESSAGE_RETRY_ATTEMPTS, MESSAGE_RETRY_DELAY, MessageStatus } from '../constants.js';

/**
 * Queued message with retry metadata
 */
export interface QueuedMessage {
  message: Message;
  status: MessageStatus;
  attempts: number;
  lastAttempt?: number;
  error?: Error;
}

/**
 * Message queue for offline support and retry logic
 */
export class MessageQueue {
  private queue: Map<string, QueuedMessage> = new Map();
  private maxSize: number;
  private maxRetries: number;
  private retryDelay: number;

  constructor(
    maxSize: number = MAX_QUEUE_SIZE,
    maxRetries: number = MESSAGE_RETRY_ATTEMPTS,
    retryDelay: number = MESSAGE_RETRY_DELAY
  ) {
    this.maxSize = maxSize;
    this.maxRetries = maxRetries;
    this.retryDelay = retryDelay;
  }

  /**
   * Add a message to the queue
   */
  enqueue(message: Message): void {
    if (this.queue.size >= this.maxSize) {
      logger.warn('Message queue is full, removing oldest message');
      const firstKey = this.queue.keys().next().value;
      if (firstKey) {
        this.queue.delete(firstKey);
      }
    }

    this.queue.set(message.id, {
      message,
      status: MessageStatus.PENDING,
      attempts: 0,
    });

    logger.debug('Message enqueued', { messageId: message.id });
  }

  /**
   * Mark a message as sent
   */
  markSent(messageId: string): void {
    const queued = this.queue.get(messageId);
    if (queued) {
      queued.status = MessageStatus.SENT;
      logger.debug('Message marked as sent', { messageId });
      // Remove from queue after successful send
      this.queue.delete(messageId);
    }
  }

  /**
   * Mark a message as failed
   */
  markFailed(messageId: string, error: Error): void {
    const queued = this.queue.get(messageId);
    if (queued) {
      queued.status = MessageStatus.FAILED;
      queued.error = error;
      queued.attempts++;
      queued.lastAttempt = Date.now();

      logger.warn('Message failed', {
        messageId,
        attempts: queued.attempts,
        error: error.message,
      });

      // Remove if max retries exceeded
      if (queued.attempts >= this.maxRetries) {
        logger.error('Message exceeded max retries, removing from queue', {
          messageId,
          attempts: queued.attempts,
        });
        this.queue.delete(messageId);
      }
    }
  }

  /**
   * Get messages that need to be retried
   */
  getRetryableMessages(): QueuedMessage[] {
    const now = Date.now();
    const retryable: QueuedMessage[] = [];

    for (const queued of this.queue.values()) {
      if (
        queued.status === MessageStatus.FAILED &&
        queued.attempts < this.maxRetries &&
        (!queued.lastAttempt || now - queued.lastAttempt >= this.retryDelay)
      ) {
        retryable.push(queued);
      }
    }

    return retryable;
  }

  /**
   * Get all pending messages
   */
  getPendingMessages(): QueuedMessage[] {
    return Array.from(this.queue.values()).filter(
      (q) => q.status === MessageStatus.PENDING
    );
  }

  /**
   * Get queue size
   */
  size(): number {
    return this.queue.size;
  }

  /**
   * Clear the queue
   */
  clear(): void {
    this.queue.clear();
    logger.debug('Message queue cleared');
  }

  /**
   * Get message by ID
   */
  get(messageId: string): QueuedMessage | undefined {
    return this.queue.get(messageId);
  }

  /**
   * Remove message from queue
   */
  remove(messageId: string): void {
    this.queue.delete(messageId);
    logger.debug('Message removed from queue', { messageId });
  }

  /**
   * Get all messages in queue
   */
  getAll(): QueuedMessage[] {
    return Array.from(this.queue.values());
  }
}
