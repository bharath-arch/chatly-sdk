import { validateUsername, validateMessage, validateGroupName, validateGroupMembers } from '../src/utils/validation';
import { ValidationError } from '../src/utils/errors';

describe('Validation Utilities', () => {
  describe('validateUsername', () => {
    it('should accept valid usernames', () => {
      expect(() => validateUsername('alice')).not.toThrow();
      expect(() => validateUsername('bob123')).not.toThrow();
      expect(() => validateUsername('user_name')).not.toThrow();
      expect(() => validateUsername('user-name')).not.toThrow();
      expect(() => validateUsername('ABC')).not.toThrow();
    });

    it('should reject invalid usernames', () => {
      expect(() => validateUsername('')).toThrow(ValidationError);
      expect(() => validateUsername('ab')).toThrow(ValidationError); // Too short
      expect(() => validateUsername('a'.repeat(21))).toThrow(ValidationError); // Too long
      expect(() => validateUsername('user@name')).toThrow(ValidationError); // Invalid char
      expect(() => validateUsername('user name')).toThrow(ValidationError); // Space
      expect(() => validateUsername('user.name')).toThrow(ValidationError); // Dot
    });
  });

  describe('validateMessage', () => {
    it('should accept valid messages', () => {
      expect(() => validateMessage('Hello')).not.toThrow();
      expect(() => validateMessage('A'.repeat(10000))).not.toThrow();
      expect(() => validateMessage('Message with emojis 👋🌍')).not.toThrow();
    });

    it('should reject invalid messages', () => {
      expect(() => validateMessage('')).toThrow(ValidationError);
      expect(() => validateMessage('A'.repeat(10001))).toThrow(ValidationError); // Too long
    });
  });

  describe('validateGroupName', () => {
    it('should accept valid group names', () => {
      expect(() => validateGroupName('Team Chat')).not.toThrow();
      expect(() => validateGroupName('Project 2024')).not.toThrow();
      expect(() => validateGroupName('A'.repeat(100))).not.toThrow();
    });

    it('should reject invalid group names', () => {
      expect(() => validateGroupName('')).toThrow(ValidationError);
      expect(() => validateGroupName('   ')).toThrow(ValidationError);
      expect(() => validateGroupName('A'.repeat(101))).toThrow(ValidationError); // Too long
    });
  });

  describe('validateGroupMembers', () => {
    it('should accept valid member counts', () => {
      expect(() => validateGroupMembers(2)).not.toThrow();
      expect(() => validateGroupMembers(10)).not.toThrow();
      expect(() => validateGroupMembers(256)).not.toThrow();
    });

    it('should reject invalid member counts', () => {
      expect(() => validateGroupMembers(0)).toThrow(ValidationError);
      expect(() => validateGroupMembers(1)).toThrow(ValidationError); // Too few
      expect(() => validateGroupMembers(257)).toThrow(ValidationError); // Too many
    });
  });
});
