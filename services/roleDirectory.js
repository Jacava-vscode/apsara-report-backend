'use strict';

const bcrypt = require('bcryptjs');
const clusterManager = require('./clusterManager');
const adminUserSchema = require('../models/AdminUser');

const DEFAULT_ADMIN_USERNAME = (process.env.DEFAULT_ADMIN_USERNAME || 'admin').toLowerCase();
const DEFAULT_ADMIN_DISPLAY_NAME = process.env.DEFAULT_ADMIN_DISPLAY_NAME || 'Administrator';
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || '@dminpanel';
const PASSWORD_SALT_ROUNDS = parseInt(process.env.AUTH_PASSWORD_SALT_ROUNDS, 10) || 10;

const sanitizePermissions = (input = {}) => ({
  view: Boolean(input.view),
  add: Boolean(input.add),
  edit: Boolean(input.edit),
  delete: Boolean(input.delete),
  admin: Boolean(input.admin)
});

class RoleDirectoryService {
  constructor() {
    this.cachedModel = null;
    this.cachedConnection = null;
    this.initialized = false;
  }

  isAvailable() {
    const connection = clusterManager.getConnection('roles');
    return Boolean(connection && connection.readyState === 1);
  }

  getModel() {
    const connection = clusterManager.getConnection('roles');
    if (!connection || connection.readyState !== 1) {
      return null;
    }

    if (!this.cachedModel || this.cachedConnection !== connection) {
      this.cachedConnection = connection;
      this.cachedModel = connection.model('AdminUser', adminUserSchema);
    }

    return this.cachedModel;
  }

  async initialize() {
    if (this.initialized) {
      return;
    }

    if (!this.isAvailable()) {
      console.warn('⚠️  Role directory cluster not available. Admin accounts will fall back to in-browser storage.');
      return;
    }

    const AdminUser = this.getModel();
    if (!AdminUser) {
      return;
    }

    const existing = await AdminUser.findOne({ username: DEFAULT_ADMIN_USERNAME }).exec();
    const permissions = {
      view: true,
      add: true,
      edit: true,
      delete: true,
      admin: true
    };

    if (!existing) {
      const passwordHash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, PASSWORD_SALT_ROUNDS);
      await AdminUser.create({
        username: DEFAULT_ADMIN_USERNAME,
        displayName: DEFAULT_ADMIN_DISPLAY_NAME,
        role: 'Administrator',
        passwordHash,
        permissions,
        createdBy: 'system',
        updatedBy: 'system'
      });
      console.log('✅ Default administrator seeded in roles cluster');
    } else {
      const updates = {};
      if (!existing.passwordHash) {
        updates.passwordHash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, PASSWORD_SALT_ROUNDS);
      }
      if (existing.role !== 'Administrator') {
        updates.role = 'Administrator';
      }
      updates.permissions = permissions;
      updates.displayName = existing.displayName || DEFAULT_ADMIN_DISPLAY_NAME;

      if (Object.keys(updates).length > 0) {
        await AdminUser.updateOne({ _id: existing._id }, { $set: updates });
        console.log('🔄 Default administrator permissions normalized');
      }
    }

    this.initialized = true;
  }

  sanitizeUser(userDoc) {
    if (!userDoc) {
      return null;
    }

    const plain = userDoc.toObject ? userDoc.toObject() : userDoc;

    return {
      id: plain._id?.toString?.() || plain.id,
      username: plain.username,
      displayName: plain.displayName || plain.username,
      role: plain.role || 'Custom',
      permissions: sanitizePermissions(plain.permissions),
      isActive: plain.isActive !== false,
      createdAt: plain.createdAt,
      updatedAt: plain.updatedAt
    };
  }

  async listUsers() {
    if (!this.isAvailable()) {
      return [];
    }

    const AdminUser = this.getModel();
    if (!AdminUser) {
      return [];
    }

    const docs = await AdminUser.find({}).sort({ createdAt: 1 }).exec();
    return docs.map((doc) => this.sanitizeUser(doc)).filter(Boolean);
  }

  async upsertUser(payload, actor = 'system') {
    if (!this.isAvailable()) {
      throw new Error('Role directory cluster unavailable');
    }

    const AdminUser = this.getModel();
    if (!AdminUser) {
      throw new Error('Role directory model unavailable');
    }

    const username = String(payload.username || '').trim().toLowerCase();
    if (!username) {
      throw new Error('Username is required');
    }

    const baseUpdate = {
      displayName: payload.displayName?.trim() || payload.username,
      role: payload.role || 'Custom',
      permissions: sanitizePermissions(payload.permissions),
      isActive: payload.isActive !== false,
      updatedBy: actor
    };

    if (payload.password && payload.password.trim().length > 0) {
      baseUpdate.passwordHash = await bcrypt.hash(payload.password.trim(), PASSWORD_SALT_ROUNDS);
    }

    const result = await AdminUser.findOneAndUpdate(
      { username },
      { $set: baseUpdate, $setOnInsert: { createdBy: actor } },
      { new: true, upsert: true }
    ).exec();

    return this.sanitizeUser(result);
  }

  async deleteUser(username, actor = 'system') {
    if (!this.isAvailable()) {
      const error = new Error('Role directory cluster unavailable');
      error.statusCode = 503;
      throw error;
    }

    const AdminUser = this.getModel();
    if (!AdminUser) {
      const error = new Error('Role directory model unavailable');
      error.statusCode = 503;
      throw error;
    }

    const normalizedUsername = String(username || '').trim().toLowerCase();
    if (!normalizedUsername) {
      const error = new Error('Username is required');
      error.statusCode = 400;
      throw error;
    }

    if (normalizedUsername === DEFAULT_ADMIN_USERNAME) {
      const error = new Error('The default administrator account cannot be deleted.');
      error.statusCode = 400;
      throw error;
    }

    const deleted = await AdminUser.findOneAndDelete({ username: normalizedUsername }).exec();
    if (!deleted) {
      const error = new Error('User not found.');
      error.statusCode = 404;
      throw error;
    }

    console.log(`🗑️  Admin user ${normalizedUsername} removed by ${actor}`);
    return this.sanitizeUser(deleted);
  }

  async authenticate(username, password) {
    if (!this.isAvailable()) {
      return null;
    }

    const AdminUser = this.getModel();
    if (!AdminUser) {
      return null;
    }

    const candidateUsername = String(username || '').trim().toLowerCase();
    const candidatePassword = String(password || '');

    if (!candidateUsername || !candidatePassword) {
      return null;
    }

    const doc = await AdminUser.findOne({ username: candidateUsername, isActive: { $ne: false } }).exec();
    if (!doc || !doc.passwordHash) {
      return null;
    }

    const matches = await bcrypt.compare(candidatePassword, doc.passwordHash);
    if (!matches) {
      return null;
    }

    return this.sanitizeUser(doc);
  }
}

module.exports = new RoleDirectoryService();
