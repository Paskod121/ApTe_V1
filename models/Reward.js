const mongoose = require('mongoose');

const rewardSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    points: {
        type: Number,
        default: 0
    },
    level: {
        type: Number,
        default: 1
    },
    xp: {
        type: Number,
        default: 0
    },
    earnedBadges: [{
        type: String
    }],
    achievements: [{
        badgeId: String,
        earnedAt: {
            type: Date,
            default: Date.now
        }
    }],
    stats: {
        tasksCompleted: { type: Number, default: 0 },
        sessionsCompleted: { type: Number, default: 0 },
        studyStreak: { type: Number, default: 0 },
        lastStudyDate: Date,
        totalStudyTime: { type: Number, default: 0 } // en minutes
    }
}, {
    timestamps: true
});

// Index pour optimiser les requêtes
rewardSchema.index({ userId: 1 });

module.exports = mongoose.model('Reward', rewardSchema); 