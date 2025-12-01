const mongoose = require('mongoose');

const activityLogSchema = new mongoose.Schema({
  time: { type: Date, default: Date.now },
  user: { type: String, required: true },
  action: { type: String, required: true },
  details: { type: String },
  ip: { type: String },
  meta: { type: Object },
}, {
  timestamps: false,
  collection: 'activitylogs'
});

module.exports = mongoose.model('ActivityLog', activityLogSchema);