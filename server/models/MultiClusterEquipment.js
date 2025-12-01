const mongoose = require('mongoose');
const clusterManager = require('../services/clusterManager');
const imageStorage = require('../services/imageStorage');

const equipmentSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['computer', 'desktop', 'laptop', 'printer'],
  },
  brand: {
    type: String,
    required: true,
  },
  model: {
    type: String,
    required: true,
  },
  serialNumber: {
    type: String,
    default: '',
  },
  status: {
    type: String,
    required: true,
    enum: ['working', 'maintenance', 'broken', 'done'],
    default: 'working',
  },
  checkInDate: {
    type: Date,
    default: Date.now,
  },
  location: {
    type: String,
    default: '',
  },
  purchaseDate: {
    type: Date,
    default: null,
  },
  warrantyExpiry: {
    type: Date,
    default: null,
  },
  assignedTo: {
    type: String,
    default: '',
  },
  customerId: {
    type: String,
    default: '',
  },
  customerPhone: {
    type: String,
    default: '',
  },
  notes: {
    type: String,
    default: '',
  },
  imageData: {
    type: [String],
    default: [],
  },
  specs: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  cluster: {
    type: String,
    default: 'primary',
    enum: ['primary', 'secondary', 'tertiary', 'archive']
  },
  archivedAt: {
    type: Date,
    default: null,
  }
}, {
  timestamps: true,
});

// Create indexes for better query performance
equipmentSchema.index({ type: 1 });
equipmentSchema.index({ status: 1 });
equipmentSchema.index({ brand: 1 });
equipmentSchema.index({ serialNumber: 1 });
equipmentSchema.index({ cluster: 1 });
equipmentSchema.index({ updatedAt: -1 });
equipmentSchema.index({ checkInDate: -1 });

const normalizeImageArray = (value) => {
  if (Array.isArray(value)) {
    return value.filter(Boolean);
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    return [value];
  }

  return [];
};

/**
 * Multi-Cluster Equipment Model Wrapper
 * Provides unified interface for CRUD operations across multiple clusters
 */
class MultiClusterEquipment {
  
  /**
   * Get Equipment model for a specific cluster
   */
  static getModel(clusterName = 'primary') {
    const connection = clusterManager.getConnection(clusterName);
    if (!connection || connection.readyState !== 1) {
      throw new Error(`Cluster ${clusterName} not available`);
    }
    return connection.model('Equipment', equipmentSchema);
  }

  /**
   * Create new equipment in active cluster
   */
  static async create(equipmentData) {
    // Update storage stats and determine active cluster
    await clusterManager.updateStorageStats();
    clusterManager.determineActiveCluster();

    const activeConnection = clusterManager.getActiveConnection();
    if (!activeConnection || activeConnection.readyState !== 1) {
      throw new Error('No active cluster available for writes');
    }

    const Equipment = activeConnection.model('Equipment', equipmentSchema);

    const imageServiceAvailable = imageStorage.isAvailable();

    const attachments = Array.isArray(equipmentData.imageData)
      ? equipmentData.imageData.filter(Boolean)
      : [];

    const payload = {
      ...equipmentData,
      cluster: clusterManager.activeCluster,
    };

    if (imageServiceAvailable) {
      payload.imageData = [];
    }

    const equipment = new Equipment(payload);
    await equipment.save();

    if (imageServiceAvailable) {
      if (attachments.length > 0) {
        await imageStorage.replaceAttachments(equipment._id, attachments);
        equipment.imageData = attachments;
      } else {
        equipment.imageData = [];
      }
    } else {
      equipment.imageData = normalizeImageArray(equipment.imageData);
    }

    console.log(`✅ Equipment created in ${clusterManager.activeCluster.toUpperCase()} cluster`);
    
    return equipment;
  }

  /**
   * Find all equipment across all clusters
   */
  static async findAll(query = {}, options = {}) {
  const allConnections = clusterManager.getAllConnections({ category: 'equipment' });
    const results = [];
    const imageServiceAvailable = imageStorage.isAvailable();

    for (const { name, connection } of allConnections) {
      try {
        const Equipment = connection.model('Equipment', equipmentSchema);
        const items = await Equipment.find(query, null, options).lean();

        for (const item of items) {
          if (imageServiceAvailable) {
            item.imageData = await imageStorage.getAttachments(item._id);
          } else {
            item.imageData = normalizeImageArray(item.imageData);
          }
          item.cluster = name;
        }

        results.push(...items);
      } catch (error) {
        console.error(`Error reading from ${name} cluster:`, error.message);
      }
    }

    // Sort by updatedAt descending (most recent first)
    results.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    
    return results;
  }

  /**
   * Find equipment by ID across all clusters
   */
  static async findById(id) {
  const allConnections = clusterManager.getAllConnections({ category: 'equipment' });
    const imageServiceAvailable = imageStorage.isAvailable();

    for (const { name, connection } of allConnections) {
      try {
        const Equipment = connection.model('Equipment', equipmentSchema);
        const item = await Equipment.findById(id).lean();
        
        if (item) {
          if (imageServiceAvailable) {
            item.imageData = await imageStorage.getAttachments(item._id);
          } else {
            item.imageData = normalizeImageArray(item.imageData);
          }
          item.cluster = name;
          return item;
        }
      } catch (error) {
        // Continue searching in other clusters
        continue;
      }
    }

    return null;
  }

  /**
   * Update equipment by ID
   */
  static async updateById(id, updateData) {
  const allConnections = clusterManager.getAllConnections({ category: 'equipment' });
    const imageServiceAvailable = imageStorage.isAvailable();

    for (const { name, connection } of allConnections) {
      try {
        const Equipment = connection.model('Equipment', equipmentSchema);

        const attachments = Array.isArray(updateData.imageData)
          ? updateData.imageData.filter(Boolean)
          : null;

        if (imageServiceAvailable) {
          delete updateData.imageData;
        }

        const updated = await Equipment.findByIdAndUpdate(
          id,
          updateData,
          { new: true, runValidators: true }
        );
        
        if (updated) {
          if (imageServiceAvailable) {
            if (attachments !== null) {
              await imageStorage.replaceAttachments(updated._id, attachments);
            }
            updated.imageData = await imageStorage.getAttachments(updated._id);
          } else {
            updated.imageData = normalizeImageArray(updated.imageData);
          }
          console.log(`✅ Equipment updated in ${name.toUpperCase()} cluster`);
          return updated;
        }
      } catch (error) {
        // Continue searching in other clusters
        continue;
      }
    }

    throw new Error('Equipment not found in any cluster');
  }

  /**
   * Delete equipment by ID
   */
  static async deleteById(id) {
  const allConnections = clusterManager.getAllConnections({ category: 'equipment' });
    const imageServiceAvailable = imageStorage.isAvailable();

    for (const { name, connection } of allConnections) {
      try {
        const Equipment = connection.model('Equipment', equipmentSchema);
        const deleted = await Equipment.findByIdAndDelete(id);
        
        if (deleted) {
          if (imageServiceAvailable) {
            await imageStorage.deleteAttachments(id);
          }
          console.log(`✅ Equipment deleted from ${name.toUpperCase()} cluster`);
          return deleted;
        }
      } catch (error) {
        // Continue searching in other clusters
        continue;
      }
    }

    throw new Error('Equipment not found in any cluster');
  }

  /**
   * Get statistics across all clusters
   */
  static async getStats() {
  const allConnections = clusterManager.getAllConnections({ category: 'equipment' });
    const stats = {
      total: 0,
      computers: 0,
      desktops: 0,
      laptops: 0,
      printers: 0,
      byType: { computer: 0, desktop: 0, laptop: 0, printer: 0 },
      byStatus: { working: 0, maintenance: 0, broken: 0, done: 0 },
      byCluster: {},
      byBrand: {}
    };

    for (const { name, connection } of allConnections) {
      try {
        const Equipment = connection.model('Equipment', equipmentSchema);
        const items = await Equipment.find().lean();
        
        stats.byCluster[name] = items.length;
        stats.total += items.length;

        items.forEach(item => {
          const typeKey = item.type || 'unknown';
          const statusKey = item.status || 'unknown';
          const brandKey = (typeof item.brand === 'string' && item.brand.trim().length > 0)
            ? item.brand.trim()
            : 'Unknown';

          stats.byType[typeKey] = (stats.byType[typeKey] || 0) + 1;
          stats.byStatus[statusKey] = (stats.byStatus[statusKey] || 0) + 1;
          stats.byBrand[brandKey] = (stats.byBrand[brandKey] || 0) + 1;

          if (typeKey === 'desktop') {
            stats.desktops += 1;
            stats.computers += 1;
          } else if (typeKey === 'laptop') {
            stats.laptops += 1;
            stats.computers += 1;
          } else if (typeKey === 'computer') {
            stats.computers += 1;
          } else if (typeKey === 'printer') {
            stats.printers += 1;
          }
        });
      } catch (error) {
        console.error(`Error getting stats from ${name} cluster:`, error.message);
      }
    }

    // Ensure status keys exist even if no data was found
  stats.byStatus.working = stats.byStatus.working || 0;
  stats.byStatus.maintenance = stats.byStatus.maintenance || 0;
  stats.byStatus.broken = stats.byStatus.broken || 0;
  stats.byStatus.done = stats.byStatus.done || 0;

    // Keep byType totals in sync with convenience fields
    stats.byType.desktop = stats.byType.desktop || 0;
    stats.byType.laptop = stats.byType.laptop || 0;
    stats.byType.computer = stats.byType.computer || 0;
    stats.byType.printer = stats.byType.printer || 0;

    stats.desktops = stats.byType.desktop;
    stats.laptops = stats.byType.laptop;
    stats.computers = stats.byType.computer + stats.byType.desktop + stats.byType.laptop;
    stats.printers = stats.byType.printer || stats.printers;

    return stats;
  }

  /**
   * Archive old equipment records
   */
  static async archiveOldRecords() {
    const oldRecords = await clusterManager.checkArchivingNeeded();
    
    if (oldRecords.length === 0) {
      return { archived: 0, errors: 0, message: 'No records need archiving' };
    }

    const recordIds = oldRecords.map(r => r._id);
    const result = await clusterManager.archiveRecords(recordIds);
    
    console.log(`📦 Archived ${result.archived} records to ARCHIVE cluster`);
    
    return {
      ...result,
      message: `Archived ${result.archived} old records`
    };
  }

  /**
   * Search equipment across all clusters
   */
  static async search(searchTerm) {
    const query = {
      $or: [
        { brand: new RegExp(searchTerm, 'i') },
        { model: new RegExp(searchTerm, 'i') },
        { serialNumber: new RegExp(searchTerm, 'i') },
        { location: new RegExp(searchTerm, 'i') },
        { assignedTo: new RegExp(searchTerm, 'i') },
        { customerId: new RegExp(searchTerm, 'i') },
        { customerPhone: new RegExp(searchTerm, 'i') }
      ]
    };

    return await this.findAll(query);
  }
}

module.exports = MultiClusterEquipment;
