'use strict';

const crypto = require('crypto');

class SessionManager {
  constructor() {
    this.sessions = new Map();
    this.ttlMs = (parseInt(process.env.AUTH_SESSION_TTL_MINUTES, 10) || 60) * 60 * 1000;
    this.cleanupIntervalMs = (parseInt(process.env.AUTH_SESSION_SWEEP_MINUTES, 10) || 15) * 60 * 1000;
    this.startCleanupTimer();
  }

  startCleanupTimer() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
    this.cleanupTimer = setInterval(() => this.cleanupExpiredSessions(), this.cleanupIntervalMs);
  }

  generateToken() {
    if (typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID().replace(/-/g, '');
    }
    return crypto.randomBytes(32).toString('hex');
  }

  createSession(user) {
    const token = this.generateToken();
    const now = Date.now();
    const expiresAt = now + this.ttlMs;

    const payload = {
      token,
      userId: user.id,
      username: user.username,
      role: user.role,
      permissions: user.permissions,
      issuedAt: now,
      expiresAt
    };

    this.sessions.set(token, payload);
    return payload;
  }

  validate(token) {
    if (!token) {
      return null;
    }
    const record = this.sessions.get(token);
    if (!record) {
      return null;
    }
    if (record.expiresAt <= Date.now()) {
      this.sessions.delete(token);
      return null;
    }
    return record;
  }

  touch(token) {
    const session = this.validate(token);
    if (!session) {
      return null;
    }
    session.expiresAt = Date.now() + this.ttlMs;
    this.sessions.set(token, session);
    return session;
  }

  destroy(token) {
    if (!token) {
      return;
    }
    this.sessions.delete(token);
  }

  destroyByUsername(username) {
    const normalized = String(username || '').trim().toLowerCase();
    if (!normalized) {
      return;
    }

    for (const [token, session] of this.sessions.entries()) {
      if ((session.username || '').toLowerCase() === normalized) {
        this.sessions.delete(token);
      }
    }
  }

  cleanupExpiredSessions() {
    const now = Date.now();
    for (const [token, session] of this.sessions.entries()) {
      if (session.expiresAt <= now) {
        this.sessions.delete(token);
      }
    }
  }
}

module.exports = new SessionManager();
