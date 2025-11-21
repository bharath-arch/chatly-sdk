import { ChatSDK } from '../src/index';
import { InMemoryUserStore } from '../src/stores/memory/userStore';
import { InMemoryMessageStore } from '../src/stores/memory/messageStore';
import { InMemoryGroupStore } from '../src/stores/memory/groupStore';
import { EVENTS } from '../src/constants';
import { ValidationError, SessionError } from '../src/utils/errors';

describe('ChatSDK', () => {
  let sdk: ChatSDK;

  beforeEach(() => {
    sdk = new ChatSDK({
      userStore: new InMemoryUserStore(),
      messageStore: new InMemoryMessageStore(),
      groupStore: new InMemoryGroupStore(),
    });
  });

  describe('User Management', () => {
    it('should create a user with valid username', async () => {
      const user = await sdk.createUser('alice');
      
      expect(user).toHaveProperty('id');
      expect(user).toHaveProperty('username', 'alice');
      expect(user).toHaveProperty('publicKey');
      expect(user).toHaveProperty('privateKey');
      expect(user).toHaveProperty('identityKey');
    });

    it('should reject invalid usernames', async () => {
      await expect(sdk.createUser('')).rejects.toThrow(ValidationError);
      await expect(sdk.createUser('ab')).rejects.toThrow(ValidationError); // Too short
      await expect(sdk.createUser('a'.repeat(21))).rejects.toThrow(ValidationError); // Too long
      await expect(sdk.createUser('user@name')).rejects.toThrow(ValidationError); // Invalid chars
    });

    it('should emit user:created event', async () => {
      const handler = jest.fn();
      sdk.on(EVENTS.USER_CREATED, handler);
      
      const user = await sdk.createUser('bob');
      
      expect(handler).toHaveBeenCalledWith(user);
    });

    it('should list all users', async () => {
      await sdk.createUser('alice');
      await sdk.createUser('bob');
      
      const users = await sdk.listUsers();
      
      expect(users).toHaveLength(2);
      expect(users.map(u => u.username)).toContain('alice');
      expect(users.map(u => u.username)).toContain('bob');
    });

    it('should get user by ID', async () => {
      const alice = await sdk.createUser('alice');
      
      const retrieved = await sdk.getUserById(alice.id);
      
      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(alice.id);
      expect(retrieved?.username).toBe('alice');
    });
  });

  describe('Session Management', () => {
    it('should create a 1:1 chat session', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      
      const session = await sdk.startSession(alice, bob);
      
      expect(session).toBeDefined();
      expect(session.id).toBeDefined();
    });

    it('should emit session:created event', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const handler = jest.fn();
      sdk.on(EVENTS.SESSION_CREATED, handler);
      
      const session = await sdk.startSession(alice, bob);
      
      expect(handler).toHaveBeenCalledWith(session);
    });

    it('should create consistent session IDs regardless of user order', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      
      const session1 = await sdk.startSession(alice, bob);
      const session2 = await sdk.startSession(bob, alice);
      
      expect(session1.id).toBe(session2.id);
    });
  });

  describe('Group Management', () => {
    it('should create a group with valid members', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      
      const group = await sdk.createGroup('Team Chat', [alice, bob]);
      
      expect(group).toBeDefined();
      expect(group.group.name).toBe('Team Chat');
      expect(group.group.members).toHaveLength(2);
    });

    it('should reject groups with less than 2 members', async () => {
      const alice = await sdk.createUser('alice');
      
      await expect(
        sdk.createGroup('Solo Chat', [alice])
      ).rejects.toThrow(ValidationError);
    });

    it('should reject invalid group names', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      
      await expect(
        sdk.createGroup('', [alice, bob])
      ).rejects.toThrow(ValidationError);
      
      await expect(
        sdk.createGroup('   ', [alice, bob])
      ).rejects.toThrow(ValidationError);
    });

    it('should emit group:created event', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const handler = jest.fn();
      sdk.on(EVENTS.GROUP_CREATED, handler);
      
      const group = await sdk.createGroup('Team', [alice, bob]);
      
      expect(handler).toHaveBeenCalledWith(group);
    });

    it('should list all groups', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      
      await sdk.createGroup('Group 1', [alice, bob]);
      await sdk.createGroup('Group 2', [alice, bob]);
      
      const groups = await sdk.listGroups();
      
      expect(groups).toHaveLength(2);
    });

    it('should load an existing group', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const created = await sdk.createGroup('Team', [alice, bob]);
      
      const loaded = await sdk.loadGroup(created.group.id);
      
      expect(loaded.group.id).toBe(created.group.id);
      expect(loaded.group.name).toBe('Team');
    });
  });

  describe('Messaging', () => {
    it('should send and decrypt a 1:1 message', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const session = await sdk.startSession(alice, bob);
      
      sdk.setCurrentUser(alice);
      const message = await sdk.sendMessage(session, 'Hello Bob!');
      
      expect(message).toBeDefined();
      expect(message.senderId).toBe(alice.id);
      expect(message.receiverId).toBe(bob.id);
      
      const decrypted = await sdk.decryptMessage(message, bob);
      expect(decrypted).toBe('Hello Bob!');
    });

    it('should reject messages without current user', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const session = await sdk.startSession(alice, bob);
      
      await expect(
        sdk.sendMessage(session, 'Hello')
      ).rejects.toThrow(SessionError);
    });

    it('should reject invalid messages', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const session = await sdk.startSession(alice, bob);
      
      sdk.setCurrentUser(alice);
      
      await expect(
        sdk.sendMessage(session, '')
      ).rejects.toThrow(ValidationError);
      
      await expect(
        sdk.sendMessage(session, 'A'.repeat(10001))
      ).rejects.toThrow(ValidationError);
    });

    it('should send and decrypt a group message', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const charlie = await sdk.createUser('charlie');
      const group = await sdk.createGroup('Team', [alice, bob, charlie]);
      
      sdk.setCurrentUser(alice);
      const message = await sdk.sendMessage(group, 'Hello team!');
      
      expect(message.groupId).toBe(group.group.id);
      
      const decryptedByBob = await sdk.decryptMessage(message, bob);
      const decryptedByCharlie = await sdk.decryptMessage(message, charlie);
      
      expect(decryptedByBob).toBe('Hello team!');
      expect(decryptedByCharlie).toBe('Hello team!');
    });

    it('should get messages for a user', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const session = await sdk.startSession(alice, bob);
      
      sdk.setCurrentUser(alice);
      await sdk.sendMessage(session, 'Message 1');
      await sdk.sendMessage(session, 'Message 2');
      
      const messages = await sdk.getMessagesForUser(bob.id);
      
      expect(messages).toHaveLength(2);
    });

    it('should get messages for a group', async () => {
      const alice = await sdk.createUser('alice');
      const bob = await sdk.createUser('bob');
      const group = await sdk.createGroup('Team', [alice, bob]);
      
      sdk.setCurrentUser(alice);
      await sdk.sendMessage(group, 'Message 1');
      await sdk.sendMessage(group, 'Message 2');
      
      const messages = await sdk.getMessagesForGroup(group.group.id);
      
      expect(messages).toHaveLength(2);
    });
  });

  describe('Connection State', () => {
    it('should return disconnected when no transport', () => {
      expect(sdk.isConnected()).toBe(false);
      expect(sdk.getConnectionState()).toBe('disconnected');
    });
  });

  describe('Queue Status', () => {
    it('should return queue status', () => {
      const status = sdk.getQueueStatus();
      
      expect(status).toHaveProperty('size');
      expect(status).toHaveProperty('pending');
      expect(status).toHaveProperty('retryable');
      expect(status.size).toBe(0);
    });
  });
});
