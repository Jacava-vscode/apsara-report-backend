const mongoose = require('mongoose');

const groupMemberSchema = new mongoose.Schema({
  username: { type: String, required: true },
  joinedAt: { type: Date, default: Date.now }
}, { _id: false });

const userGroupSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, trim: true },
  description: { type: String, default: '' },
  isActive: { type: Boolean, default: true },
  // Either manual list of members or dynamic filter expression
  filters: { type: Object, default: {} },
  members: { type: [groupMemberSchema], default: [] },
  createdBy: { type: String, default: 'admin' },
  updatedBy: { type: String, default: 'admin' }
}, {
  timestamps: true,
  collection: 'usergroups'
});

userGroupSchema.index({ name: 1 });
userGroupSchema.index({ isActive: 1 });

module.exports = userGroupSchema;
