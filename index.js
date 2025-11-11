const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const path = require('path');
const clusterManager = require('./services/clusterManager');
const roleDirectory = require('./services/roleDirectory');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
const BODY_SIZE_LIMIT = process.env.REQUEST_SIZE_LIMIT || '15mb';

app.use(bodyParser.json({ limit: BODY_SIZE_LIMIT }));
app.use(bodyParser.urlencoded({ extended: true, limit: BODY_SIZE_LIMIT }));

// Serve static files from client directory
app.use(express.static(path.join(__dirname, '../client')));

// Import routes
const equipmentRoutes = require('./routes/equipment');
const storageRoutes = require('./routes/storage');
const { router: authRoutes } = require('./routes/auth');

// API Routes
app.use('/api/equipment', equipmentRoutes);
app.use('/api/storage', storageRoutes);
app.use('/api/auth', authRoutes);

// Root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/index.html'));
});

// Health check route
app.get('/api/health', async (req, res) => {
  const report = await clusterManager.getStorageReport();
  
  res.json({
    success: true,
    message: 'Server is running',
    clusters: report.clusters,
    activeCluster: report.activeCluster
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Connect to MongoDB clusters and start server
const startServer = async () => {
  try {
    // Initialize multi-cluster manager
  await clusterManager.initialize();
  await roleDirectory.initialize();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`🚀 Server is running on port ${PORT}`);
      console.log(`📂 Access the application at http://localhost:${PORT}`);
      console.log(`💾 Active cluster: ${clusterManager.activeCluster.toUpperCase()}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n⚠️  Shutting down gracefully...');
  await clusterManager.disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n⚠️  Shutting down gracefully...');
  await clusterManager.disconnect();
  process.exit(0);
});

// Start the server
startServer();

module.exports = app;
