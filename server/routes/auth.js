const express = require('express');
const router = express.Router();
const roleDirectory = require('../services/roleDirectory');
const sessionManager = require('../services/sessionManager');

const extractToken = (req) => {
  const header = req.get('Authorization') || '';
  const [, token] = header.split(' ');
  return token || req.get('x-session-token') || req.query.token;
};

const requireRoleCluster = (req, res, next) => {
  if (!roleDirectory.isAvailable()) {
    return res.status(503).json({
      success: false,
      error: 'roles-cluster-unavailable',
      message: 'Role directory cluster is not currently available. Try again later.'
    });
  }
  next();
};

const requireAuth = (req, res, next) => {
  const token = extractToken(req);
  const session = sessionManager.validate(token);
  if (!session) {
    return res.status(401).json({
      success: false,
      error: 'unauthorized',
      message: 'Authentication required.'
    });
  }
  req.session = sessionManager.touch(token);
  req.sessionToken = token;
  next();
};

const requireAdmin = (req, res, next) => {
  const permissions = req.session?.permissions || {};
  if (!permissions.admin) {
    return res.status(403).json({
      success: false,
      error: 'forbidden',
      message: 'Administrator permissions required.'
    });
  }
  next();
};

router.post('/login', requireRoleCluster, async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: 'invalid-request',
      message: 'Username and password are required.'
    });
  }

  try {
    const user = await roleDirectory.authenticate(username, password);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'invalid-credentials',
        message: 'Invalid username or password.'
      });
    }

    const session = sessionManager.createSession(user);

    res.json({
      success: true,
      data: {
        token: session.token,
        user
      }
    });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({
      success: false,
      error: 'login-failed',
      message: error.message
    });
  }
});

router.post('/logout', requireAuth, (req, res) => {
  sessionManager.destroy(req.sessionToken);
  res.json({ success: true });
});

router.get('/me', requireRoleCluster, requireAuth, async (req, res) => {
  try {
    const users = await roleDirectory.listUsers();
    const user = users.find((entry) => entry.username === req.session.username);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'not-found',
        message: 'User not found.'
      });
    }

    res.json({
      success: true,
      data: {
        user,
        token: req.sessionToken
      }
    });
  } catch (error) {
    console.error('Error loading current user:', error);
    res.status(500).json({
      success: false,
      error: 'me-failed',
      message: error.message
    });
  }
});

router.get('/users', requireRoleCluster, requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await roleDirectory.listUsers();
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Error listing users:', error);
    res.status(500).json({
      success: false,
      error: 'list-users-failed',
      message: error.message
    });
  }
});

router.post('/users', requireRoleCluster, requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await roleDirectory.upsertUser(req.body || {}, req.session.username);
    res.status(201).json({ success: true, data: result });
  } catch (error) {
    const status = error.message && error.message.toLowerCase().includes('unique') ? 409 : 400;
    console.error('Error upserting user:', error);
    res.status(status).json({
      success: false,
      error: 'upsert-user-failed',
      message: error.message
    });
  }
});

router.delete('/users/:username', requireRoleCluster, requireAuth, requireAdmin, async (req, res) => {
  const targetParam = String(req.params.username || '').trim().toLowerCase();
  if (!targetParam) {
    return res.status(400).json({
      success: false,
      error: 'invalid-request',
      message: 'Username is required.'
    });
  }

  if (req.session?.username && req.session.username.toLowerCase() === targetParam) {
    return res.status(400).json({
      success: false,
      error: 'cannot-delete-self',
      message: 'You cannot delete the account you are currently signed in with.'
    });
  }

  try {
    const deleted = await roleDirectory.deleteUser(targetParam, req.session?.username);
    sessionManager.destroyByUsername(targetParam);
    res.json({ success: true, data: deleted });
  } catch (error) {
    const status = error.statusCode || (error.message && error.message.toLowerCase().includes('not found') ? 404 : 400);
    console.error('Error deleting user:', error);
    res.status(status).json({
      success: false,
      error: 'delete-user-failed',
      message: error.message
    });
  }
});

module.exports = {
  router,
  requireAuth,
  requireAdmin,
  extractToken
};
