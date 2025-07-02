const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    required: true,
    enum: [
      'badge', 'level_up', 'points', 'session', 'custom'
    ]
  },
  message: {
    type: String,
    required: true
  },
  read: {
    type: Boolean,
    default: false
  },
  metadata: {
    type: Object,
    default: {}
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

notificationSchema.index({ userId: 1, read: 1 });

module.exports = mongoose.model('Notification', notificationSchema); 