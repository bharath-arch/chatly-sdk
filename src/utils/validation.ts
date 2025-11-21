import { ValidationError } from "./errors.js";

/**
 * Validation utilities
 */

const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/;
const MAX_MESSAGE_LENGTH = 10000;
const MIN_GROUP_MEMBERS = 2;
const MAX_GROUP_MEMBERS = 256;
const MAX_GROUP_NAME_LENGTH = 100;

/**
 * Validate username format
 */
export function validateUsername(username: string): void {
  if (!username || typeof username !== 'string') {
    throw new ValidationError('Username is required', { username });
  }

  if (!USERNAME_REGEX.test(username)) {
    throw new ValidationError(
      'Username must be 3-20 characters and contain only letters, numbers, underscores, and hyphens',
      { username }
    );
  }
}

/**
 * Validate message content
 */
export function validateMessage(message: string): void {
  if (!message || typeof message !== 'string') {
    throw new ValidationError('Message content is required');
  }

  if (message.length === 0) {
    throw new ValidationError('Message cannot be empty');
  }

  if (message.length > MAX_MESSAGE_LENGTH) {
    throw new ValidationError(
      `Message exceeds maximum length of ${MAX_MESSAGE_LENGTH} characters`,
      { length: message.length, max: MAX_MESSAGE_LENGTH }
    );
  }
}

/**
 * Validate group name
 */
export function validateGroupName(name: string): void {
  if (!name || typeof name !== 'string') {
    throw new ValidationError('Group name is required');
  }

  if (name.trim().length === 0) {
    throw new ValidationError('Group name cannot be empty');
  }

  if (name.length > MAX_GROUP_NAME_LENGTH) {
    throw new ValidationError(
      `Group name exceeds maximum length of ${MAX_GROUP_NAME_LENGTH} characters`,
      { length: name.length, max: MAX_GROUP_NAME_LENGTH }
    );
  }
}

/**
 * Validate group members count
 */
export function validateGroupMembers(memberCount: number): void {
  if (memberCount < MIN_GROUP_MEMBERS) {
    throw new ValidationError(
      `Group must have at least ${MIN_GROUP_MEMBERS} members`,
      { count: memberCount, min: MIN_GROUP_MEMBERS }
    );
  }

  if (memberCount > MAX_GROUP_MEMBERS) {
    throw new ValidationError(
      `Group cannot have more than ${MAX_GROUP_MEMBERS} members`,
      { count: memberCount, max: MAX_GROUP_MEMBERS }
    );
  }
}

/**
 * Validate user ID format
 */
export function validateUserId(userId: string): void {
  if (!userId || typeof userId !== 'string') {
    throw new ValidationError('User ID is required');
  }

  if (userId.trim().length === 0) {
    throw new ValidationError('User ID cannot be empty');
  }
}
