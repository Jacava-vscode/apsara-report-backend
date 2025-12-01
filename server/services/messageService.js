const mongoose = require('mongoose');
const Message = mongoose.model('Message', require('../models/Message'));
const UserGroup = mongoose.model('UserGroup', require('../models/UserGroup'));
const AdminUser = mongoose.model('AdminUser', require('../models/AdminUser'));
const delivery = require('./delivery');
const ActivityLog = require('../models/ActivityLog');

const sendMessageById = async (id, actor = 'system', ip = '127.0.0.1') => {
  const msg = await Message.findById(id).populate('targetGroup');
  if (!msg) return null;

  let recipients = msg.recipients || [];
  if (msg.targetGroup) {
    const group = await UserGroup.findById(msg.targetGroup._id);
    if (group) {
      // manual members
      recipients = recipients.concat(group.members.map(m => m.username));
      // dynamic filters: query AdminUser collection based on filters
      if (group.filters && Object.keys(group.filters).length) {
        const filters = { ...group.filters };
        // Only allow specific filter keys for safety
        const allowed = ['role', 'isActive', 'username'];
        const query = {};
        Object.entries(filters).forEach(([k, v]) => {
          if (allowed.includes(k)) {
            query[k] = v;
          }
        });
        if (Object.keys(query).length) {
          const matched = await AdminUser.find(query, 'username');
          recipients = recipients.concat(matched.map(m => m.username));
        }
      }
    }
  }
  recipients = Array.from(new Set(recipients));

  // Send via channel-specific handler
  if (msg.channel === 'email') {
    try {
      const emails = [];
      // fetch emails for all recipients if they are usernames
      const emailsFromUsers = await AdminUser.find({ username: { $in: recipients } }, 'email');
      emails.push(...emailsFromUsers.map(u => u.email).filter(Boolean));
      if (emails.length) {
        await delivery.sendEmail({ to: emails, subject: msg.title, html: `<p>${msg.body}</p>` });
      }
    } catch (err) {
      // log but do not fail the whole send
      await ActivityLog.create({ user: actor, action: 'Send Message Error', details: `Email send failed for ${msg._id}: ${err.message}`, ip });
    }
  }

  msg.status = 'sent';
  msg.sentAt = new Date();
  msg.deliveryReport = { recipientsCount: recipients.length };
  await msg.save();

  await ActivityLog.create({ user: actor, action: 'Send Message', details: `Sent message ${msg.title} to ${recipients.length} recipients`, ip });
  return { recipientsCount: recipients.length, messageId: msg._id };
};

// Simple scheduler to send scheduled messages
let schedulerTimer = null;
const startScheduler = (intervalMs = 60 * 1000) => {
  if (schedulerTimer) clearInterval(schedulerTimer);
  schedulerTimer = setInterval(async () => {
    try {
      const now = new Date();
      const scheduled = await Message.find({ status: 'scheduled', scheduledAt: { $lte: now } });
      for (const msg of scheduled) {
        try { await sendMessageById(msg._id, 'system', 'scheduler'); } catch (e) { /* ignore */ }
      }
    } catch (err) {
      // ignore scheduling errors for now
    }
  }, intervalMs);
};

const stopScheduler = () => {
  if (schedulerTimer) clearInterval(schedulerTimer);
  schedulerTimer = null;
};

module.exports = { sendMessageById, startScheduler, stopScheduler };
