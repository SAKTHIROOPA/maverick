import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import { 
  authenticateUser, 
  getActiveSession, 
  checkIsAuthenticated, 
  terminateSession, 
  DEMO_CREDENTIALS 
} from '../src/services/authService.js';

// Polyfill localStorage and sessionStorage for Node.js test environment if needed
class MockStorage {
  constructor() {
    this.store = {};
  }
  getItem(key) {
    return this.store[key] || null;
  }
  setItem(key, value) {
    this.store[key] = String(value);
  }
  removeItem(key) {
    delete this.store[key];
  }
  clear() {
    this.store = {};
  }
}

globalThis.localStorage = new MockStorage();
globalThis.sessionStorage = new MockStorage();

describe('MAVERICK Authentication & Session Service', () => {
  beforeEach(() => {
    terminateSession();
    localStorage.clear();
    sessionStorage.clear();
  });

  it('authenticates successfully with standard demo email and password', () => {
    const result = authenticateUser('admin@example.com', 'admin123', true);
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.user.email, 'admin@example.com');
    assert.strictEqual(result.user.name, 'Analyst SIH-01');
    assert.strictEqual(checkIsAuthenticated(), true);
  });

  it('authenticates successfully with demo username (case-insensitive)', () => {
    const result = authenticateUser('ADMIN', 'admin123', false);
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.user.username, 'admin');
    assert.strictEqual(checkIsAuthenticated(), true);
  });

  it('fails with clear error when email/username is empty', () => {
    const result = authenticateUser('', 'admin123');
    assert.strictEqual(result.success, false);
    assert.match(result.error, /email or username is required/i);
    assert.strictEqual(checkIsAuthenticated(), false);
  });

  it('fails with clear error when password is empty', () => {
    const result = authenticateUser('admin@example.com', '');
    assert.strictEqual(result.success, false);
    assert.match(result.error, /password is required/i);
    assert.strictEqual(checkIsAuthenticated(), false);
  });

  it('fails with clear error when password is incorrect', () => {
    const result = authenticateUser('admin@example.com', 'wrongpassword');
    assert.strictEqual(result.success, false);
    assert.match(result.error, /invalid email or password/i);
    assert.strictEqual(checkIsAuthenticated(), false);
  });

  it('fails with clear error when username/email is unrecognized', () => {
    const result = authenticateUser('unauthorized@domain.com', 'admin123');
    assert.strictEqual(result.success, false);
    assert.match(result.error, /invalid email or password/i);
    assert.strictEqual(checkIsAuthenticated(), false);
  });

  it('correctly persists session in localStorage when rememberMe is true', () => {
    authenticateUser('admin@example.com', 'admin123', true);
    const session = getActiveSession();
    assert.ok(session);
    assert.strictEqual(session.rememberMe, true);
    assert.strictEqual(session.isAuthenticated, true);
    assert.strictEqual(localStorage.getItem('maverick_auth_session') !== null, true);
    assert.strictEqual(sessionStorage.getItem('maverick_auth_session'), null);
  });

  it('correctly persists session in sessionStorage when rememberMe is false', () => {
    authenticateUser('admin@example.com', 'admin123', false);
    const session = getActiveSession();
    assert.ok(session);
    assert.strictEqual(session.rememberMe, false);
    assert.strictEqual(session.isAuthenticated, true);
    assert.strictEqual(sessionStorage.getItem('maverick_auth_session') !== null, true);
    assert.strictEqual(localStorage.getItem('maverick_auth_session'), null);
  });

  it('terminates session and clears storage upon logout', () => {
    authenticateUser('admin@example.com', 'admin123', true);
    assert.strictEqual(checkIsAuthenticated(), true);

    terminateSession();
    assert.strictEqual(checkIsAuthenticated(), false);
    assert.strictEqual(getActiveSession(), null);
    assert.strictEqual(localStorage.getItem('maverick_auth_session'), null);
    assert.strictEqual(sessionStorage.getItem('maverick_auth_session'), null);
  });
});
