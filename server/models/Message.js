const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  title: { type: String, required: true },
  body: { type: String, required: true },
  sender: { type: String, default: 'system' },
  targetGroup: { type: mongoose.Schema.Types.ObjectId, ref: 'UserGroup' },
  recipients: { type: [String], default: [] },
  channel: { type: String, enum: ['email','in-app','sms'], default: 'in-app' },
  status: { type: String, enum: ['draft','scheduled','sent','failed'], default: 'draft' },
  scheduledAt: { type: Date },
  sentAt: { type: Date },
  deliveryReport: { type: Object, default: {} },
  createdBy: { type: String, default: 'system' },
  updatedBy: { type: String, default: 'system' }
}, {
  timestamps: true,
  collection: 'messages'
});

messageSchema.index({ status: 1 });
messageSchema.index({ scheduledAt: 1 });

module.exports = messageSchema;
