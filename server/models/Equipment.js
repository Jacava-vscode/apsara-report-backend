const mongoose = require('mongoose');

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
}, {
  timestamps: true, // Automatically adds createdAt and updatedAt
});

// Create indexes for better query performance
equipmentSchema.index({ type: 1 });
equipmentSchema.index({ status: 1 });
equipmentSchema.index({ brand: 1 });
equipmentSchema.index({ serialNumber: 1 });
equipmentSchema.index({ checkInDate: -1 });

const Equipment = mongoose.model('Equipment', equipmentSchema);

module.exports = Equipment;
