const mongoose = require('mongoose');
const clusterManager = require('./clusterManager');

const attachmentSchema = new mongoose.Schema({
  equipmentId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true,
  },
  data: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

class ImageStorageService {
  constructor() {
    this.cachedModel = null;
    this.cachedConnection = null;
  }

  isAvailable() {
    const connection = clusterManager.getConnection('images');
    return Boolean(connection && connection.readyState === 1);
  }

  getModel() {
    const connection = clusterManager.getConnection('images');
    if (!connection || connection.readyState !== 1) {
      return null;
    }

    if (!this.cachedModel || this.cachedConnection !== connection) {
      this.cachedConnection = connection;
      this.cachedModel = connection.model('ImageAttachment', attachmentSchema);
    }

    return this.cachedModel;
  }

  async getAttachments(equipmentId) {
    if (!this.isAvailable()) {
      return [];
    }

    const ImageAttachment = this.getModel();
    if (!ImageAttachment) {
      return [];
    }

    const docs = await ImageAttachment.find({ equipmentId })
      .sort({ createdAt: 1 })
      .select('data')
      .lean();

    return docs.map((doc) => doc.data).filter(Boolean);
  }

  async replaceAttachments(equipmentId, attachments) {
    if (!this.isAvailable()) {
      return [];
    }

    const ImageAttachment = this.getModel();
    if (!ImageAttachment) {
      return [];
    }

    const validData = Array.isArray(attachments)
      ? attachments.filter((item) => typeof item === 'string' && item.trim().length > 0)
      : [];

    await ImageAttachment.deleteMany({ equipmentId });

    if (validData.length === 0) {
      return [];
    }

    const documents = validData.map((data) => ({ equipmentId, data }));
    await ImageAttachment.insertMany(documents);

    return validData;
  }

  async deleteAttachments(equipmentId) {
    if (!this.isAvailable()) {
      return;
    }

    const ImageAttachment = this.getModel();
    if (!ImageAttachment) {
      return;
    }

    await ImageAttachment.deleteMany({ equipmentId });
  }
}

module.exports = new ImageStorageService();
