const mongoose = require('mongoose');

const userActionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    actionType: {
        type: String,
        required: true,
        enum: [
            'task_completed',
            'task_created',
            'pomodoro_session_completed',
            'pomodoro_session_interrupted',
            'badge_earned',
            'level_up',
            'subject_created',
            'login',
            'study_streak'
        ]
    },
    pointsEarned: {
        type: Number,
        default: 0
    },
    metadata: {
        // Données spécifiques selon l'action
        taskId: { type: mongoose.Schema.Types.ObjectId, ref: 'Task' },
        subjectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Subject' },
        sessionDuration: Number, // en minutes
        badgeId: String,
        oldLevel: Number,
        newLevel: Number,
        description: String
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Index pour optimiser les requêtes
userActionSchema.index({ userId: 1, timestamp: -1 });
userActionSchema.index({ actionType: 1, timestamp: -1 });
userActionSchema.index({ userId: 1, actionType: 1 });

module.exports = mongoose.model('UserAction', userActionSchema); 