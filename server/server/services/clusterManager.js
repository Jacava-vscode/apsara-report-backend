const mongoose = require('mongoose');

class ClusterManager {
    constructor() {
        this.clusterDescriptors = [
            { name: 'primary', envKey: 'MONGODB_URI_PRIMARY', required: true, writable: true, category: 'equipment' },
            { name: 'secondary', envKey: 'MONGODB_URI_SECONDARY', required: false, writable: true, category: 'equipment' },
            { name: 'tertiary', envKey: 'MONGODB_URI_TERTIARY', required: false, writable: true, category: 'equipment' },
            { name: 'archive', envKey: 'MONGODB_URI_ARCHIVE', required: false, writable: false, category: 'archive' },
            { name: 'images', envKey: 'MONGODB_URI_IMAGES', required: false, writable: false, category: 'images', dbNameEnvKey: 'MONGODB_IMAGE_DB_NAME' },
            { name: 'roles', envKey: 'MONGODB_URI_ROLES', required: false, writable: true, category: 'roles', dbNameEnvKey: 'MONGODB_ROLE_DB_NAME' }
        ];

        this.clusters = this.clusterDescriptors.reduce((acc, descriptor) => {
            acc[descriptor.name] = null;
            return acc;
        }, {});

        this.activeCluster = 'primary';
        this.storageStats = {};
        this.maxStorageMB = parseInt(process.env.CLUSTER_STORAGE_LIMIT_MB, 10) || 512;
        this.initialized = false;
    }

    /**
     * Initialize all configured clusters
     */
    async initialize() {
        console.log('🔗 Initializing Multi-Cluster Manager...');

        const connections = [];

        for (const descriptor of this.clusterDescriptors) {
            const uri = process.env[descriptor.envKey];

            if (!uri) {
                if (descriptor.required) {
                    throw new Error(`${descriptor.envKey} is required but missing in environment variables`);
                }

                console.log(`   ⏭️  Skipping ${descriptor.name.toUpperCase()} cluster (no URI configured)`);
                continue;
            }

            try {
                console.log(`   📍 Connecting to ${descriptor.name.toUpperCase()} cluster...`);
                this.clusters[descriptor.name] = await this.createConnection(uri, descriptor);
                console.log(`   ✅ ${descriptor.name.toUpperCase()} cluster ready`);
                connections.push(descriptor.name);
            } catch (error) {
                const message = `   ❌ ${descriptor.name.toUpperCase()} cluster failed: ${error.message}`;
                if (descriptor.required) {
                    console.error(message);
                    throw new Error('Primary cluster connection required');
                }
                console.warn(message);
            }
        }

        if (!connections.includes('primary')) {
            throw new Error('No primary cluster connected. Check MONGODB_URI_PRIMARY.');
        }

        console.log(`\n✅ Cluster Manager initialized with ${connections.length} cluster(s): ${connections.join(', ')}`);

        await this.updateStorageStats();
        this.determineActiveCluster();
        this.initialized = true;

        return this;
    }

    /**
     * Create a connection to a cluster
     */
    async createConnection(uri, descriptor) {
        const { name, dbNameEnvKey } = descriptor;
        const connectionOptions = {
            serverSelectionTimeoutMS: parseInt(process.env.CLUSTER_SERVER_SELECTION_TIMEOUT_MS, 10) || 10000,
            maxPoolSize: parseInt(process.env.CLUSTER_MAX_POOL_SIZE, 10) || 10
        };

        if (dbNameEnvKey) {
            const dbName = process.env[dbNameEnvKey];
            if (dbName && dbName.trim().length > 0) {
                connectionOptions.dbName = dbName.trim();
            }
        }

        const connection = mongoose.createConnection(uri, connectionOptions);
        
        connection.on('connected', () => {
            console.log(`   🔗 ${name.toUpperCase()} cluster connected`);
        });

        connection.on('error', (err) => {
            console.error(`   ❌ ${name.toUpperCase()} cluster error:`, err.message);
        });

        connection.on('disconnected', () => {
            console.log(`   ⚠️ ${name.toUpperCase()} cluster disconnected`);
        });

        await connection.asPromise();
        return connection;
    }

    /**
     * Get storage statistics for a cluster
     */
    async getClusterStorage(clusterName) {
        const connection = this.clusters[clusterName];
        if (!connection || connection.readyState !== 1) {
            return null;
        }

        try {
            const stats = await connection.db.stats();
            
            const storageMB = stats.dataSize / (1024 * 1024);
            const percentUsed = this.maxStorageMB > 0
                ? (storageMB / this.maxStorageMB) * 100
                : 0;
            
            return {
                cluster: clusterName,
                dataSize: stats.dataSize,
                storageMB: parseFloat(storageMB.toFixed(2)),
                maxStorageMB: this.maxStorageMB,
                percentUsed: parseFloat(percentUsed.toFixed(2)),
                collections: stats.collections,
                documents: stats.objects,
                indexes: stats.indexes,
                available: this.maxStorageMB - storageMB,
                status: this.getStorageStatus(percentUsed)
            };
        } catch (error) {
            console.error(`Error getting stats for ${clusterName}:`, error.message);
            return null;
        }
    }

    /**
     * Get storage status based on thresholds
     */
    getStorageStatus(percentUsed) {
        const switchThreshold = parseInt(process.env.STORAGE_THRESHOLD_SWITCH) || 90;
        const criticalThreshold = parseInt(process.env.STORAGE_THRESHOLD_CRITICAL) || 75;
        const warningThreshold = parseInt(process.env.STORAGE_THRESHOLD_WARNING) || 50;

        if (percentUsed >= switchThreshold) return 'full';
        if (percentUsed >= criticalThreshold) return 'critical';
        if (percentUsed >= warningThreshold) return 'warning';
        return 'healthy';
    }

    /**
     * Update storage statistics for all clusters
     */
    async updateStorageStats() {
        for (const [name, connection] of Object.entries(this.clusters)) {
            if (connection && connection.readyState === 1) {
                const stats = await this.getClusterStorage(name);
                if (stats) {
                    this.storageStats[name] = stats;
                }
            } else {
                delete this.storageStats[name];
            }
        }
        return this.storageStats;
    }

    /**
     * Determine which cluster should be active for writes
     */
    determineActiveCluster() {
        const switchThreshold = parseInt(process.env.STORAGE_THRESHOLD_SWITCH, 10) || 90;

        for (const descriptor of this.clusterDescriptors) {
            if (descriptor.writable === false) {
                continue;
            }
            const { name } = descriptor;
            const connection = this.clusters[name];
            const stats = this.storageStats[name];

            const canWrite = connection && connection.readyState === 1;
            const underThreshold = !stats || stats.percentUsed < switchThreshold;

            if (canWrite && underThreshold) {
                if (this.activeCluster !== name) {
                    console.log(`⚙️  Active cluster set to ${name.toUpperCase()}`);
                }
                this.activeCluster = name;
                return name;
            }
        }

        console.warn('🚨 ALL CLUSTERS ARE FULL OR UNAVAILABLE! Defaulting to PRIMARY.');
        this.activeCluster = 'primary';
        return 'primary';
    }

    /**
     * Get the active cluster connection for writes
     */
    getActiveConnection() {
        const activeConnection = this.clusters[this.activeCluster];

        if (activeConnection && activeConnection.readyState === 1) {
            return activeConnection;
        }

        this.determineActiveCluster();
        return this.clusters[this.activeCluster];
    }

    /**
     * Get all available cluster connections for reads
     */
    getAllConnections(options = {}) {
        const { category = 'equipment' } = options;
        return this.clusterDescriptors
            .filter((descriptor) => {
                if (!category) {
                    return true;
                }
                return descriptor.category === category;
            })
            .map(({ name }) => ({ name, connection: this.clusters[name] }))
            .filter(({ connection }) => connection && connection.readyState === 1);
    }

    getConnectionForCategory(category) {
        if (!category) {
            return this.getActiveConnection();
        }

        const descriptors = this.clusterDescriptors.filter((descriptor) => descriptor.category === category);
        for (const descriptor of descriptors) {
            const connection = this.clusters[descriptor.name];
            if (connection && connection.readyState === 1) {
                return connection;
            }
        }
        return null;
    }

    /**
     * Get a specific cluster connection
     */
    getConnection(clusterName) {
        return this.clusters[clusterName];
    }

    /**
     * Get all storage statistics
     */
    async getStorageReport() {
        await this.updateStorageStats();
        
        const report = {
            activeCluster: this.activeCluster,
            clusters: this.storageStats,
            totalStorage: 0,
            totalUsed: 0,
            totalAvailable: 0,
            overallStatus: 'healthy'
        };

        // Calculate totals
        for (const stats of Object.values(this.storageStats)) {
            if (stats) {
                report.totalStorage += stats.maxStorageMB;
                report.totalUsed += stats.storageMB;
                report.totalAvailable += stats.available;
            }
        }

        // Determine overall status
        const overallPercent = report.totalStorage > 0
            ? (report.totalUsed / report.totalStorage) * 100
            : 0;
        report.overallPercent = parseFloat(overallPercent.toFixed(2));
        report.overallStatus = this.getStorageStatus(overallPercent);

        return report;
    }

    /**
     * Check if archiving is needed
     */
    async checkArchivingNeeded() {
        const archiveDays = parseInt(process.env.ARCHIVE_AFTER_DAYS) || 180;
        const autoArchiveEnabled = process.env.AUTO_ARCHIVE_ENABLED === 'true';

        if (!autoArchiveEnabled || !this.clusters.archive || this.clusters.archive.readyState !== 1) {
            return [];
        }

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - archiveDays);

    const { connection: primaryConnection } = this.getAllConnections({ category: 'equipment' }).find(c => c.name === 'primary') || {};
        if (!primaryConnection) {
            return [];
        }

        const Equipment = primaryConnection.model('Equipment');
        const batchLimit = parseInt(process.env.ARCHIVE_BATCH_LIMIT, 10) || 100;

        const oldRecords = await Equipment.find({
            updatedAt: { $lt: cutoffDate }
        })
        .select('_id type brand model updatedAt')
        .limit(batchLimit)
        .lean();

        return oldRecords;
    }

    /**
     * Archive old records to archive cluster
     */
    async archiveRecords(recordIds) {
        if (!this.clusters.archive || this.clusters.archive.readyState !== 1) {
            throw new Error('Archive cluster not configured');
        }

        const primaryConnection = this.clusters.primary;
        if (!primaryConnection || primaryConnection.readyState !== 1) {
            throw new Error('Primary cluster not available');
        }

        const PrimaryEquipment = primaryConnection.model('Equipment');
        const ArchiveEquipment = this.clusters.archive.model('Equipment');

        const batchLimit = parseInt(process.env.ARCHIVE_BATCH_LIMIT, 10) || recordIds.length;
        const idsToProcess = batchLimit > 0 ? recordIds.slice(0, batchLimit) : recordIds;

        let archived = 0;
        let errors = 0;

        for (const id of idsToProcess) {
            try {
                const record = await PrimaryEquipment.findById(id);
                if (record) {
                    // Copy to archive
                    const archiveDoc = new ArchiveEquipment(record.toObject());
                    archiveDoc._id = record._id; // Keep same ID
                    archiveDoc.archivedAt = new Date();
                    await archiveDoc.save();

                    // Delete from primary
                    await PrimaryEquipment.findByIdAndDelete(id);
                    archived++;
                }
            } catch (error) {
                console.error(`Error archiving record ${id}:`, error.message);
                errors++;
            }
        }

        return { archived, errors, processed: idsToProcess.length };
    }

    /**
     * Close all cluster connections
     */
    async disconnect() {
        console.log('🔌 Disconnecting from all clusters...');
        
        for (const [name, connection] of Object.entries(this.clusters)) {
            if (connection) {
                try {
                    await connection.close();
                    console.log(`   ✅ ${name.toUpperCase()} cluster disconnected`);
                } catch (error) {
                    console.error(`   ❌ Error disconnecting ${name}:`, error.message);
                }
            }
        }
        
        console.log('👋 All clusters disconnected');
    }
}

// Export singleton instance
module.exports = new ClusterManager();
