# Contributing to Chatly SDK

Thank you for your interest in contributing to Chatly SDK! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

---

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors. We expect all participants to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, trolling, or discriminatory comments
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

---

## 🚀 Getting Started

### Prerequisites

- **Node.js**: >= 16.x
- **npm**: >= 8.x
- **Git**: Latest version
- **TypeScript**: 5.x (installed as dev dependency)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/chatly-sdk.git
cd chatly-sdk
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/bharath-arch/chatly-sdk.git
```

---

## 💻 Development Setup

### Install Dependencies

```bash
npm install
```

### Build the Project

```bash
npm run build
```

### Run Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Development Commands

```bash
# Build the SDK
npm run build

# Run TypeScript compiler
npx tsc --noEmit

# Format code (if prettier is configured)
npm run format

# Lint code (if eslint is configured)
npm run lint
```

---

## 📁 Project Structure

```
e2e-chat-sdk/
├── src/
│   ├── chat/              # Chat session implementations
│   │   ├── chatSession.ts
│   │   └── groupSession.ts
│   ├── crypto/            # Cryptography implementations
│   │   ├── e2e.ts         # End-to-end encryption
│   │   └── keys.ts        # Key generation
│   ├── models/            # Data models
│   │   ├── user.ts
│   │   ├── message.ts
│   │   └── group.ts
│   ├── stores/            # Storage adapters
│   │   ├── adapters.ts    # Store interfaces
│   │   └── memory/        # In-memory implementations
│   ├── transport/         # Network layer
│   │   ├── adapters.ts    # Transport interface
│   │   ├── websocketClient.ts
│   │   └── memoryTransport.ts
│   ├── utils/             # Utility functions
│   │   ├── errors.ts      # Error classes
│   │   ├── logger.ts      # Logging system
│   │   ├── validation.ts  # Input validation
│   │   └── messageQueue.ts
│   ├── constants.ts       # Constants and enums
│   └── index.ts           # Main SDK export
├── test/                  # Test files
│   ├── crypto.test.ts
│   ├── sdk.test.ts
│   └── validation.test.ts
├── dist/                  # Build output (generated)
├── jest.config.js         # Jest configuration
├── tsconfig.json          # TypeScript configuration
└── package.json
```

---

## 🔄 Development Workflow

### 1. Create a Branch

Always create a new branch for your work:

```bash
# Update your local main branch
git checkout main
git pull upstream main

# Create a feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

### 2. Make Your Changes

- Write clean, readable code
- Follow the coding standards (see below)
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run tests
npm test

# Check test coverage
npm run test:coverage

# Build to ensure no errors
npm run build
```

### 4. Commit Your Changes

Follow the commit message guidelines (see below):

```bash
git add .
git commit -m "feat: add message queue retry logic"
```

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

---

## 📝 Coding Standards

### TypeScript Style Guide

#### 1. Use TypeScript Features

```typescript
// ✅ DO: Use interfaces for object shapes
interface User {
  id: string;
  username: string;
  publicKey: string;
}

// ✅ DO: Use type annotations
function createUser(username: string): Promise<User> {
  // ...
}

// ❌ DON'T: Use 'any' type
function processData(data: any) { // Bad
  // ...
}
```

#### 2. Naming Conventions

```typescript
// Classes: PascalCase
class ChatSDK { }
class WebSocketClient { }

// Interfaces: PascalCase
interface TransportAdapter { }
interface UserStoreAdapter { }

// Functions/Methods: camelCase
function sendMessage() { }
async function createUser() { }

// Constants: UPPER_SNAKE_CASE
const MAX_RETRY_ATTEMPTS = 5;
const HEARTBEAT_INTERVAL = 30000;

// Enums: PascalCase for enum, UPPER_CASE for values
enum ConnectionState {
  DISCONNECTED = 'disconnected',
  CONNECTED = 'connected',
}
```

#### 3. Error Handling

```typescript
// ✅ DO: Use custom error classes
throw new ValidationError('Username must be 3-20 characters');

// ✅ DO: Provide error context
throw new NetworkError('Connection failed', 'CONN_FAILED', true, {
  url: wsUrl,
  attempt: reconnectAttempts,
});

// ❌ DON'T: Throw generic errors
throw new Error('Something went wrong'); // Bad
```

#### 4. Async/Await

```typescript
// ✅ DO: Use async/await
async function sendMessage(text: string): Promise<Message> {
  const encrypted = await encryptMessage(text, sharedSecret);
  return await transport.send(encrypted);
}

// ❌ DON'T: Mix promises and callbacks
function sendMessage(text: string, callback: Function) { // Bad
  encryptMessage(text).then(encrypted => {
    callback(null, encrypted);
  });
}
```

#### 5. Documentation

```typescript
// ✅ DO: Add JSDoc comments for public APIs
/**
 * Sends an encrypted message through the specified session.
 * 
 * @param session - The chat or group session
 * @param text - The plaintext message to send
 * @returns Promise resolving to the sent message
 * @throws {ValidationError} If message is invalid
 * @throws {SessionError} If no current user is set
 * @throws {NetworkError} If send fails
 */
async function sendMessage(
  session: ChatSession | GroupSession,
  text: string
): Promise<Message> {
  // ...
}
```

### Code Organization

#### 1. Imports

```typescript
// Order: external, internal, types
import { EventEmitter } from 'events';
import { ChatSession } from './chat/chatSession.js';
import type { User } from './models/user.js';
```

#### 2. File Extensions

```typescript
// ✅ DO: Use .js extensions for imports (for ESM compatibility)
import { User } from './models/user.js';

// ❌ DON'T: Omit extensions
import { User } from './models/user'; // Bad
```

#### 3. Exports

```typescript
// ✅ DO: Use named exports
export class ChatSDK { }
export interface User { }

// ✅ DO: Group exports at the end
export { ChatSDK, User, Message };
```

---

## 🧪 Testing Guidelines

### Test Structure

```typescript
describe('ComponentName', () => {
  describe('methodName', () => {
    it('should do something specific', async () => {
      // Arrange
      const sdk = new ChatSDK({ /* config */ });
      
      // Act
      const result = await sdk.someMethod();
      
      // Assert
      expect(result).toBeDefined();
      expect(result.property).toBe(expectedValue);
    });
  });
});
```

### Test Coverage Requirements

- **Minimum Coverage**: 70% for all metrics (branches, functions, lines, statements)
- **New Features**: Must have 80%+ coverage
- **Bug Fixes**: Must include regression tests

### What to Test

#### 1. Happy Paths

```typescript
it('should create a user with valid username', async () => {
  const user = await sdk.createUser('alice');
  expect(user.username).toBe('alice');
});
```

#### 2. Error Cases

```typescript
it('should reject invalid usernames', async () => {
  await expect(sdk.createUser('')).rejects.toThrow(ValidationError);
  await expect(sdk.createUser('ab')).rejects.toThrow(ValidationError);
});
```

#### 3. Edge Cases

```typescript
it('should handle empty messages', async () => {
  const encrypted = await encryptMessage('', sharedSecret);
  const decrypted = await decryptMessage(encrypted.ciphertext, encrypted.iv, sharedSecret);
  expect(decrypted).toBe('');
});
```

#### 4. Integration Tests

```typescript
it('should send and decrypt messages end-to-end', async () => {
  const alice = await sdk.createUser('alice');
  const bob = await sdk.createUser('bob');
  const session = await sdk.startSession(alice, bob);
  
  sdk.setCurrentUser(alice);
  const message = await sdk.sendMessage(session, 'Hello!');
  
  const decrypted = await sdk.decryptMessage(message, bob);
  expect(decrypted).toBe('Hello!');
});
```

---

## 📝 Commit Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, semicolons, etc.)
- **refactor**: Code refactoring
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Build process or auxiliary tool changes

### Examples

```bash
# Feature
git commit -m "feat(transport): add automatic reconnection with exponential backoff"

# Bug fix
git commit -m "fix(crypto): handle empty messages in encryption"

# Documentation
git commit -m "docs(readme): add React integration examples"

# Breaking change
git commit -m "feat(sdk)!: change sendMessage to return Promise<Message>

BREAKING CHANGE: sendMessage now returns a Promise instead of void"
```

### Scope

Use the component/module name:
- `sdk` - Core SDK
- `crypto` - Cryptography
- `transport` - Network layer
- `stores` - Storage adapters
- `validation` - Input validation
- `errors` - Error handling
- `queue` - Message queue
- `tests` - Test files
- `docs` - Documentation

---

## 🔀 Pull Request Process

### Before Submitting

- [ ] Tests pass: `npm test`
- [ ] Build succeeds: `npm run build`
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] Commit messages follow conventions
- [ ] Branch is up to date with main

### PR Title

Follow the same format as commit messages:

```
feat(transport): add WebSocket reconnection logic
fix(crypto): handle edge case in key derivation
docs(readme): improve installation instructions
```

### PR Description Template

```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
Describe the tests you ran and how to reproduce them.

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have updated the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally
- [ ] Any dependent changes have been merged and published
```

### Review Process

1. **Automated Checks**: CI/CD runs tests and builds
2. **Code Review**: At least one maintainer reviews the code
3. **Feedback**: Address review comments
4. **Approval**: Maintainer approves the PR
5. **Merge**: Maintainer merges the PR

---

## 🚢 Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes (e.g., 1.0.0 → 2.0.0)
- **MINOR**: New features, backward compatible (e.g., 1.0.0 → 1.1.0)
- **PATCH**: Bug fixes, backward compatible (e.g., 1.0.0 → 1.0.1)

### Release Steps (Maintainers Only)

1. Update version in `package.json`
2. Update CHANGELOG.md
3. Create a git tag: `git tag v1.2.3`
4. Push tag: `git push origin v1.2.3`
5. Publish to npm: `npm publish`
6. Create GitHub release with notes

---

## 🐛 Reporting Bugs

### Before Reporting

- Check if the bug has already been reported
- Try to reproduce with the latest version
- Gather relevant information (OS, Node version, etc.)

### Bug Report Template

```markdown
**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Initialize SDK with '...'
2. Call method '...'
3. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Code Sample**
```typescript
// Minimal code to reproduce
const sdk = new ChatSDK({ /* ... */ });
await sdk.someMethod(); // Error occurs here
```

**Environment**
- OS: [e.g., macOS 13.0]
- Node.js version: [e.g., 18.12.0]
- SDK version: [e.g., 0.0.5]

**Additional context**
Any other context about the problem.
```

---

## 💡 Feature Requests

### Before Requesting

- Check if the feature has already been requested
- Consider if it fits the project scope
- Think about backward compatibility

### Feature Request Template

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
What you want to happen.

**Describe alternatives you've considered**
Other solutions you've thought about.

**API Design (if applicable)**
```typescript
// Proposed API
sdk.newMethod(params);
```

**Additional context**
Any other context or screenshots.
```

---

## 📞 Getting Help

- **Documentation**: Check the [README](./README.md)
- **Issues**: Search [existing issues](https://github.com/bharath-arch/chatly-sdk/issues)
- **Discussions**: Use [GitHub Discussions](https://github.com/bharath-arch/chatly-sdk/discussions)

---

## 🙏 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

Thank you for contributing to Chatly SDK! 🎉
