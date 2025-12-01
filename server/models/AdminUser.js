const mongoose = require('mongoose');

const permissionsSchema = new mongoose.Schema({
  view: { type: Boolean, default: true },
  add: { type: Boolean, default: true },
  edit: { type: Boolean, default: true },
  delete: { type: Boolean, default: false },
  admin: { type: Boolean, default: false }
}, { _id: false });

const adminUserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  displayName: {
    type: String,
    default: 'Administrator',
    trim: true
  },
  role: {
    type: String,
    default: 'Custom',
    trim: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  permissions: {
    type: permissionsSchema,
    default: () => ({})
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: String,
    default: 'system'
  },
  updatedBy: {
    type: String,
    default: 'system'
  }
}, {
  timestamps: true,
  collection: 'adminusers'
});

adminUserSchema.index({ role: 1 });
adminUserSchema.index({ isActive: 1 });

module.exports = adminUserSchema;
