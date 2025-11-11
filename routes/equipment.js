const express = require('express');
const router = express.Router();
const MultiClusterEquipment = require('../models/MultiClusterEquipment');
const { requireAuth, requireAdmin } = require('./auth');

const parseDateValue = (value) => {
  if (value === null) {
    return null;
  }

  if (value === undefined) {
    return undefined;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed.length === 0) {
      return null;
    }

    const parsed = new Date(trimmed);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const MAX_IMAGE_ATTACHMENTS = 5;

const normalizeImageAttachments = (value) => {
  if (value === undefined) {
    return undefined;
  }

  if (value === null) {
    return [];
  }

  const asArray = Array.isArray(value) ? value : [value];

  return asArray
    .filter((item) => typeof item === 'string' && item.trim().length > 0)
    .slice(0, MAX_IMAGE_ATTACHMENTS);
};

const sanitizeEquipmentPayload = (input, { isUpdate = false } = {}) => {
  const payload = { ...input };

  ['purchaseDate', 'warrantyExpiry'].forEach((field) => {
    if (field in payload) {
      const parsed = parseDateValue(payload[field]);
      if (parsed === undefined) {
        delete payload[field];
      } else {
        payload[field] = parsed;
      }
    }
  });

  if ('checkInDate' in payload) {
    const parsed = parseDateValue(payload.checkInDate);

    if (parsed instanceof Date) {
      payload.checkInDate = parsed;
    } else if (parsed === null) {
      if (payload.checkInDate === null || isUpdate) {
        payload.checkInDate = null;
      } else {
        delete payload.checkInDate;
      }
    } else {
      delete payload.checkInDate;
    }
  } else if (!isUpdate) {
    // Leave undefined so schema default applies on create
  }

  if ('imageData' in payload) {
    const normalizedImages = normalizeImageAttachments(payload.imageData);
    if (normalizedImages === undefined) {
      delete payload.imageData;
    } else {
      payload.imageData = normalizedImages;
    }
  }

  return payload;
};

router.use(requireAuth);

// Get all equipment (computers and printers) from all clusters
router.get('/', async (req, res) => {
  try {
    const data = await MultiClusterEquipment.findAll();
    res.json({
      success: true,
      data: data,
      count: data.length
    });
  } catch (error) {
    console.error('Error fetching equipment:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch equipment data',
      error: error.message
    });
  }
});

// Get statistics across all clusters
router.get('/stats/summary', async (req, res) => {
  try {
    const stats = await MultiClusterEquipment.getStats();

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('Error getting statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get statistics',
      error: error.message
    });
  }
});

// Get equipment by ID from any cluster
router.get('/:id', async (req, res) => {
  try {
    const item = await MultiClusterEquipment.findById(req.params.id);
    
    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Equipment not found'
      });
    }
    
    res.json({
      success: true,
      data: item
    });
  } catch (error) {
    console.error('Error fetching equipment:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch equipment data',
      error: error.message
    });
  }
});

// Add new equipment to active cluster
router.post('/', requireAdmin, async (req, res) => {
  try {
    const payload = sanitizeEquipmentPayload(req.body);
    const savedEquipment = await MultiClusterEquipment.create(payload);

    res.status(201).json({
      success: true,
      message: 'Equipment added successfully',
      data: savedEquipment,
      cluster: savedEquipment.cluster
    });
  } catch (error) {
    console.error('Error adding equipment:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add equipment',
      error: error.message
    });
  }
});

// Update equipment in any cluster
router.put('/:id', requireAdmin, async (req, res) => {
  try {
    const payload = sanitizeEquipmentPayload(req.body, { isUpdate: true });
    const updatedEquipment = await MultiClusterEquipment.updateById(
      req.params.id,
      payload
    );

    if (!updatedEquipment) {
      return res.status(404).json({
        success: false,
        message: 'Equipment not found'
      });
    }

    res.json({
      success: true,
      message: 'Equipment updated successfully',
      data: updatedEquipment
    });
  } catch (error) {
    console.error('Error updating equipment:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update equipment',
      error: error.message
    });
  }
});

// Delete equipment from any cluster
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const deletedEquipment = await MultiClusterEquipment.deleteById(req.params.id);

    if (!deletedEquipment) {
      return res.status(404).json({
        success: false,
        message: 'Equipment not found'
      });
    }

    res.json({
      success: true,
      message: 'Equipment deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting equipment:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete equipment',
      error: error.message
    });
  }
});

module.exports = router;
