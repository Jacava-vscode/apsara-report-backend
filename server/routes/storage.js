const express = require('express');
const router = express.Router();
const clusterManager = require('../services/clusterManager');
const MultiClusterEquipment = require('../models/MultiClusterEquipment');
const { requireAuth, requireAdmin } = require('./auth');

router.use(requireAuth);

/**
 * GET /api/storage - Get storage report for all clusters
 */
router.get('/', async (req, res) => {
  try {
    const report = await clusterManager.getStorageReport();
    res.json(report);
  } catch (error) {
    console.error('Error getting storage report:', error);
    res.status(500).json({ 
      error: 'Failed to get storage report',
      message: error.message 
    });
  }
});

/**
 * GET /api/storage/check-archive - Check which records need archiving
 */
router.get('/check-archive', requireAdmin, async (req, res) => {
  try {
    const oldRecords = await clusterManager.checkArchivingNeeded();

    res.json({
      count: oldRecords.length,
      records: oldRecords,
      archiveAfterDays: parseInt(process.env.ARCHIVE_AFTER_DAYS, 10) || 180,
      autoArchiveEnabled: process.env.AUTO_ARCHIVE_ENABLED === 'true'
    });
  } catch (error) {
    console.error('Error checking archive needs:', error);
    res.status(500).json({ 
      error: 'Failed to check archive needs',
      message: error.message 
    });
  }
});

/**
 * GET /api/storage/:cluster - Get storage info for specific cluster
 */
router.get('/:cluster', async (req, res) => {
  try {
    const { cluster } = req.params;

    const allowedClusters = ['primary', 'secondary', 'tertiary', 'archive', 'images', 'roles'];
    if (!allowedClusters.includes(cluster)) {
      return res.status(400).json({ error: 'Invalid cluster name' });
    }

    const stats = await clusterManager.getClusterStorage(cluster);
    
    if (!stats) {
      return res.status(404).json({ error: `Cluster ${cluster} not available` });
    }

    res.json(stats);
  } catch (error) {
    console.error('Error getting cluster storage:', error);
    res.status(500).json({ 
      error: 'Failed to get cluster storage',
      message: error.message 
    });
  }
});

/**
 * POST /api/storage/refresh - Manually refresh storage statistics
 */
router.post('/refresh', requireAdmin, async (req, res) => {
  try {
    await clusterManager.updateStorageStats();
    const report = await clusterManager.getStorageReport();
    
    res.json({
      message: 'Storage statistics refreshed',
      report
    });
  } catch (error) {
    console.error('Error refreshing storage stats:', error);
    res.status(500).json({ 
      error: 'Failed to refresh storage statistics',
      message: error.message 
    });
  }
});

/**
 * POST /api/storage/archive - Manually trigger archiving
 */
router.post('/archive', requireAdmin, async (req, res) => {
  try {
    const result = await MultiClusterEquipment.archiveOldRecords();
    
    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    console.error('Error archiving records:', error);
    res.status(500).json({ 
      error: 'Failed to archive records',
      message: error.message 
    });
  }
});

module.exports = router;
