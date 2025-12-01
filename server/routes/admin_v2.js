/*
 * admin_v2.js
 * Clean admin routes (sessions, users, groups, messages)
 */
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const sessionManager = require('../services/sessionManager');
const { requireAdmin } = require('./auth');
const AdminUser = mongoose.model('AdminUser', require('../models/AdminUser'));
const roleDirectory = require('../services/roleDirectory');
const ActivityLog = require('../models/ActivityLog');
const UserGroup = mongoose.model('UserGroup', require('../models/UserGroup'));
const Message = mongoose.model('Message', require('../models/Message'));
const messageService = require('../services/messageService');

async function logActivity({ user, action, details, ip, meta }) {
  try {
    await ActivityLog.create({ user, action, details, ip, meta });
  } catch (err) {
    console.warn('Failed to log activity', err);
  }
}

router.get('/sessions', requireAdmin, async (req, res) => {
  const sessions = Array.from(sessionManager.sessions.values()).map(s => ({ token: s.token, username: s.username, role: s.role, issuedAt: s.issuedAt, expiresAt: s.expiresAt }));
  res.json(sessions);
});

router.delete('/sessions/:token', requireAdmin, async (req, res) => {
  const { token } = req.params;
  sessionManager.destroy(token);
  await logActivity({ user: req.user?.username || 'admin', action: 'Terminate Session', details: `Terminated session ${token}`, ip: req.ip });
  res.json({ message: 'Session terminated' });
});

router.get('/notifications', requireAdmin, async (req, res) => {
  res.json([{ message: 'System update scheduled for 2025-12-01.', type: 'info' }, { message: 'No critical alerts.', type: 'success' }]);
});

router.get('/stats', requireAdmin, async (req, res) => {
  try {
    let userCount = 0;
    let activeCount = 0;
    if (roleDirectory.isAvailable()) {
      const users = await roleDirectory.listUsers();
      userCount = users.length;
      activeCount = users.filter(u => u.isActive).length;
    } else {
      userCount = await AdminUser.countDocuments();
      activeCount = await AdminUser.countDocuments({ isActive: true });
    }
    const activeSessions = Array.from(sessionManager.sessions.values()).length;
    res.json({ userCount, activeCount, activeSessions, systemErrors: 0 });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch stats' });
  }
});

router.get('/users', requireAdmin, async (req, res) => {
  try {
    if (roleDirectory.isAvailable()) {
      const users = await roleDirectory.listUsers();
      res.json(users);
      return;
    }
    const users = await AdminUser.find({}, 'username displayName email role isActive permissions createdAt updatedAt');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

router.post('/users', requireAdmin, async (req, res) => {
  const { username, displayName, password, role, isActive, permissions } = req.body;
  if (!username || !password || !role) return res.status(400).json({ message: 'Missing required fields' });
  try {
    if (roleDirectory.isAvailable()) {
      const existing = (await roleDirectory.listUsers()).find(u => u.username === String(username).toLowerCase());
      if (existing) return res.status(409).json({ message: 'Username already exists' });
      const user = await roleDirectory.upsertUser({ username, displayName, password, role, isActive, permissions }, req.user?.username || 'admin');
      await logActivity({ user: req.user?.username || 'admin', action: 'Create User', details: `Created user ${username} in role directory`, ip: req.ip });
      res.status(201).json({ message: 'User created', user });
      return;
    }

    const exists = await AdminUser.findOne({ username });
    if (exists) return res.status(409).json({ message: 'Username already exists' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = new AdminUser({ username, displayName: displayName || username, passwordHash, role, isActive: isActive !== undefined ? isActive : true, permissions: permissions || {}, createdBy: req.user?.username || 'admin', updatedBy: req.user?.username || 'admin' });
    await user.save();
    await logActivity({ user: req.user?.username || 'admin', action: 'Create User', details: `Created user ${username}`, ip: req.ip });
    res.status(201).json({ message: 'User created', user });
  } catch (err) {
    res.status(500).json({ message: 'Failed to create user' });
  }
});

router.put('/users/:username', requireAdmin, async (req, res) => {
  const { username } = req.params;
  const { displayName, role, isActive, permissions } = req.body;
  try {
    if (roleDirectory.isAvailable()) {
      const payload = { username, displayName, role, isActive, permissions };
      const user = await roleDirectory.upsertUser(payload, req.user?.username || 'admin');
      if (!user) return res.status(404).json({ message: 'User not found' });
      await logActivity({ user: req.user?.username || 'admin', action: 'Update User', details: `Updated user ${username} in role directory`, ip: req.ip });
      res.json(user);
      return;
    }

    const user = await AdminUser.findOneAndUpdate({ username }, { ...(displayName && { displayName }), ...(role && { role }), ...(isActive !== undefined && { isActive }), ...(permissions && { permissions }), updatedBy: req.user?.username || 'admin' }, { new: true, fields: 'username displayName role isActive permissions' });
    if (!user) return res.status(404).json({ message: 'User not found' });
    await logActivity({ user: req.user?.username || 'admin', action: 'Update User', details: `Updated user ${username}`, ip: req.ip });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Failed to update user' });
  }
});

router.put('/users/:username/password', requireAdmin, async (req, res) => {
  const { username } = req.params;
  const { password } = req.body;
  if (!password) return res.status(400).json({ message: 'Password required' });
  try {
    if (roleDirectory.isAvailable()) {
      const user = await roleDirectory.upsertUser({ username, password }, req.user?.username || 'admin');
      if (!user) return res.status(404).json({ message: 'User not found' });
      await logActivity({ user: req.user?.username || 'admin', action: 'Change Password', details: `Changed password for ${username} in role directory`, ip: req.ip });
      res.json({ message: 'Password updated' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await AdminUser.findOneAndUpdate({ username }, { passwordHash, updatedBy: req.user?.username || 'admin' }, { new: true, fields: 'username' });
    if (!user) return res.status(404).json({ message: 'User not found' });
    await logActivity({ user: req.user?.username || 'admin', action: 'Change Password', details: `Changed password for ${username}`, ip: req.ip });
    res.json({ message: 'Password updated' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update password' });
  }
});

router.put('/users/:username/status', requireAdmin, async (req, res) => {
  const { username } = req.params;
  const { isActive } = req.body;
  if (typeof isActive !== 'boolean') return res.status(400).json({ message: 'isActive must be boolean' });
  try {
    if (roleDirectory.isAvailable()) {
      const user = await roleDirectory.upsertUser({ username, isActive }, req.user?.username || 'admin');
      if (!user) return res.status(404).json({ message: 'User not found' });
      await logActivity({ user: req.user?.username || 'admin', action: isActive ? 'Activate User' : 'Suspend User', details: `${isActive ? 'Activated' : 'Suspended'} user ${username} in role directory`, ip: req.ip });
      res.json({ message: 'User status updated', user });
      return;
    }

    const user = await AdminUser.findOneAndUpdate({ username }, { isActive, updatedBy: req.user?.username || 'admin' }, { new: true, fields: 'username isActive' });
    if (!user) return res.status(404).json({ message: 'User not found' });
    await logActivity({ user: req.user?.username || 'admin', action: isActive ? 'Activate User' : 'Suspend User', details: `${isActive ? 'Activated' : 'Suspended'} user ${username}`, ip: req.ip });
    res.json({ message: 'User status updated', user });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update status' });
  }
});

router.delete('/users/:username', requireAdmin, async (req, res) => {
  const { username } = req.params;
  try {
    if (roleDirectory.isAvailable()) {
      await roleDirectory.deleteUser(username, req.user?.username || 'admin');
      await logActivity({ user: req.user?.username || 'admin', action: 'Delete User', details: `Deleted user ${username} from role directory`, ip: req.ip });
      res.json({ message: 'User deleted' });
      return;
    }

    const user = await AdminUser.findOneAndDelete({ username });
    if (!user) return res.status(404).json({ message: 'User not found' });
    await logActivity({ user: req.user?.username || 'admin', action: 'Delete User', details: `Deleted user ${username}`, ip: req.ip });
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete user' });
  }
});

router.put('/users/:username/role', requireAdmin, async (req, res) => {
  const { username } = req.params;
  const { role } = req.body;
  if (!['admin', 'moderator', 'user', 'guest'].includes(role)) return res.status(400).json({ message: 'Invalid role' });
  try {
    if (roleDirectory.isAvailable()) {
      const user = await roleDirectory.upsertUser({ username, role }, req.user?.username || 'admin');
      if (!user) return res.status(404).json({ message: 'User not found' });
      await logActivity({ user: req.user?.username || 'admin', action: 'Change Role', details: `Changed role for ${username} to ${role} in role directory`, ip: req.ip });
      res.json(user);
      return;
    }

    const user = await AdminUser.findOneAndUpdate({ username }, { role, updatedBy: req.user?.username || 'admin' }, { new: true, fields: 'username role' });
    if (!user) return res.status(404).json({ message: 'User not found' });
    await logActivity({ user: req.user?.username || 'admin', action: 'Change Role', details: `Changed role for ${username} to ${role}`, ip: req.ip });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Failed to update role' });
  }
});

router.get('/activity', requireAdmin, async (req, res) => {
  try {
    const logs = await ActivityLog.find({}, '-_id time user action details ip').sort({ time: -1 }).limit(100);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch activity logs' });
  }
});

router.get('/groups', requireAdmin, async (req, res) => {
  try {
    const groups = await UserGroup.find({}, '-__v');
    res.json(groups);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch groups' });
  }
});

router.post('/groups', requireAdmin, async (req, res) => {
  const { name, description, filters, members } = req.body;
  if (!name) return res.status(400).json({ message: 'Group name required' });
  try {
    const existing = await UserGroup.findOne({ name });
    if (existing) return res.status(409).json({ message: 'Group name already exists' });
    const group = new UserGroup({ name, description, filters, members, createdBy: req.user?.username || 'admin' });
    await group.save();
    await logActivity({ user: req.user?.username || 'admin', action: 'Create Group', details: `Created group ${name}`, ip: req.ip });
    res.status(201).json(group);
  } catch (err) {
    res.status(500).json({ message: 'Failed to create group' });
  }
});

router.put('/groups/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, description, filters, isActive } = req.body;
  try {
    const group = await UserGroup.findByIdAndUpdate(id, { ...(name && { name }), ...(description && { description }), ...(filters && { filters }), ...(isActive !== undefined && { isActive }), updatedBy: req.user?.username || 'admin' }, { new: true });
    if (!group) return res.status(404).json({ message: 'Group not found' });
    await logActivity({ user: req.user?.username || 'admin', action: 'Update Group', details: `Updated group ${group.name}`, ip: req.ip });
    res.json(group);
  } catch (err) {
    res.status(500).json({ message: 'Failed to update group' });
  }
});

router.delete('/groups/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const group = await UserGroup.findByIdAndDelete(id);
    if (!group) return res.status(404).json({ message: 'Group not found' });
    await logActivity({ user: req.user?.username || 'admin', action: 'Delete Group', details: `Deleted group ${group.name}`, ip: req.ip });
    res.json({ message: 'Group deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete group' });
  }
});

router.post('/groups/:id/members', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { username } = req.body;
  if (!username) return res.status(400).json({ message: 'Username required' });
  try {
    const group = await UserGroup.findById(id);
    if (!group) return res.status(404).json({ message: 'Group not found' });
    if (group.members.some(m => m.username === username)) return res.status(409).json({ message: 'User already in group' });
    group.members.push({ username });
    await group.save();
    await logActivity({ user: req.user?.username || 'admin', action: 'Add Group Member', details: `Added ${username} to ${group.name}`, ip: req.ip });
    res.json(group);
  } catch (err) {
    res.status(500).json({ message: 'Failed to add member' });
  }
});

router.delete('/groups/:id/members/:username', requireAdmin, async (req, res) => {
  const { id, username } = req.params;
  try {
    const group = await UserGroup.findById(id);
    if (!group) return res.status(404).json({ message: 'Group not found' });
    group.members = group.members.filter(m => m.username !== username);
    await group.save();
    await logActivity({ user: req.user?.username || 'admin', action: 'Remove Group Member', details: `Removed ${username} from ${group.name}`, ip: req.ip });
    res.json(group);
  } catch (err) {
    res.status(500).json({ message: 'Failed to remove member' });
  }
});

router.get('/messages', requireAdmin, async (req, res) => {
  try {
    const messages = await Message.find({}, '-__v').populate('targetGroup', 'name');
    res.json(messages);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

// List members for a group (manual + filtered dynamic matches)
router.get('/groups/:id/members', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const group = await UserGroup.findById(id);
    if (!group) return res.status(404).json({ message: 'Group not found' });
    let recipients = (group.members || []).map(m => m.username);
    // Apply filters if present
    if (group.filters && Object.keys(group.filters).length) {
      const filters = { ...group.filters };
      const allowed = ['role', 'isActive', 'username'];
      const query = {};
      Object.entries(filters).forEach(([k, v]) => {
        if (allowed.includes(k)) query[k] = v;
      });
      if (Object.keys(query).length) {
        const matched = await AdminUser.find(query, 'username email');
        recipients = recipients.concat(matched.map(m => m.username));
      }
    }
    recipients = Array.from(new Set(recipients));
    res.json({ recipients });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch group members' });
  }
});

router.post('/messages', requireAdmin, async (req, res) => {
  const { title, body, channel, targetGroupId, recipients, scheduledAt } = req.body;
  if (!title || !body) return res.status(400).json({ message: 'Title and body required' });
  try {
    const msg = new Message({ title, body, channel: channel || 'in-app', targetGroup: targetGroupId, recipients: recipients || [], scheduledAt, createdBy: req.user?.username || 'admin' });
    // Set status to 'scheduled' if scheduledAt is provided in the future
    if (scheduledAt) {
      const scheduledDate = new Date(scheduledAt);
      if (!isNaN(scheduledDate.getTime()) && scheduledDate > new Date()) {
        msg.status = 'scheduled';
      }
    }
    await msg.save();
    await logActivity({ user: req.user?.username || 'admin', action: 'Create Message', details: `Created message ${title}`, ip: req.ip });
    res.status(201).json(msg);
  } catch (err) {
    res.status(500).json({ message: 'Failed to create message' });
  }
});

router.post('/messages/:id/send', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await messageService.sendMessageById(id, req.user?.username || 'admin', req.ip);
    if (!result) return res.status(404).json({ message: 'Message not found or failed to send' });
    res.json({ message: 'Message sent', recipientsCount: result.recipientsCount });
  } catch (err) {
    res.status(500).json({ message: 'Failed to send message' });
  }
});

module.exports = router;
