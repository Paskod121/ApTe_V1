const mongoose = require('mongoose');

const pomodoroSessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    subjectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Subject',
        default: null
    },
    taskId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Task',
        default: null
    },
    duration: {
        type: Number, // en minutes
        required: true,
        min: 1,
        max: 120
    },
    completed: {
        type: Boolean,
        default: true
    },
    interrupted: {
        type: Boolean,
        default: false
    },
    interruptionReason: {
        type: String,
        maxlength: [200, 'La raison ne peut dépasser 200 caractères'],
        default: null
    },
    notes: {
        type: String,
        maxlength: [500, 'Les notes ne peuvent dépasser 500 caractères'],
        default: null
    },
    startTime: {
        type: Date,
        default: Date.now
    },
    endTime: {
        type: Date,
        default: null
    },
    sessionType: {
        type: String,
        enum: ['focus', 'short_break', 'long_break'],
        default: 'focus'
    }
}, {
    timestamps: true
});

// Index pour optimiser les recherches
pomodoroSessionSchema.index({ userId: 1 });
pomodoroSessionSchema.index({ userId: 1, startTime: -1 });
pomodoroSessionSchema.index({ userId: 1, subjectId: 1 });
pomodoroSessionSchema.index({ userId: 1, completed: 1 });
pomodoroSessionSchema.index({ userId: 1, sessionType: 1 });

// Méthode pour terminer la session
pomodoroSessionSchema.methods.complete = function() {
    this.completed = true;
    this.endTime = new Date();
    return this.save();
};

// Méthode pour interrompre la session
pomodoroSessionSchema.methods.interrupt = function(reason) {
    this.interrupted = true;
    this.interruptionReason = reason;
    this.endTime = new Date();
    return this.save();
};

// Méthode pour calculer la durée réelle
pomodoroSessionSchema.methods.getActualDuration = function() {
    if (!this.endTime) return 0;
    return Math.round((this.endTime - this.startTime) / (1000 * 60)); // en minutes
};

// Méthode statique pour obtenir les sessions d'un utilisateur
pomodoroSessionSchema.statics.getUserSessions = async function(userId, options = {}) {
    const query = { userId: userId };
    
    if (options.completed !== undefined) {
        query.completed = options.completed;
    }
    
    if (options.sessionType) {
        query.sessionType = options.sessionType;
    }
    
    if (options.subjectId) {
        query.subjectId = options.subjectId;
    }
    
    if (options.dateFrom) {
        query.startTime = { $gte: new Date(options.dateFrom) };
    }
    
    if (options.dateTo) {
        if (query.startTime) {
            query.startTime.$lte = new Date(options.dateTo);
        } else {
            query.startTime = { $lte: new Date(options.dateTo) };
        }
    }
    
    return await this.find(query)
        .populate('subjectId', 'name color')
        .populate('taskId', 'title')
        .sort({ startTime: -1 })
        .limit(options.limit || 50);
};

// Méthode statique pour obtenir les statistiques des sessions
pomodoroSessionSchema.statics.getSessionStats = async function(userId, period = 'all') {
    let dateFilter = {};
    
    if (period === 'today') {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        dateFilter = { startTime: { $gte: today } };
    } else if (period === 'week') {
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        dateFilter = { startTime: { $gte: weekAgo } };
    } else if (period === 'month') {
        const monthAgo = new Date();
        monthAgo.setMonth(monthAgo.getMonth() - 1);
        dateFilter = { startTime: { $gte: monthAgo } };
    }
    
    const stats = await this.aggregate([
        { 
            $match: { 
                userId: new mongoose.Types.ObjectId(userId),
                completed: true,
                ...dateFilter
            } 
        },
        {
            $group: {
                _id: null,
                totalSessions: { $sum: 1 },
                totalMinutes: { $sum: '$duration' },
                focusSessions: {
                    $sum: { $cond: [{ $eq: ['$sessionType', 'focus'] }, 1, 0] }
                },
                focusMinutes: {
                    $sum: { $cond: [{ $eq: ['$sessionType', 'focus'] }, '$duration', 0] }
                },
                breakSessions: {
                    $sum: { $cond: [{ $in: ['$sessionType', ['short_break', 'long_break']] }, 1, 0] }
                },
                breakMinutes: {
                    $sum: { $cond: [{ $in: ['$sessionType', ['short_break', 'long_break']] }, '$duration', 0] }
                }
            }
        }
    ]);
    
    return stats.length > 0 ? stats[0] : {
        totalSessions: 0,
        totalMinutes: 0,
        focusSessions: 0,
        focusMinutes: 0,
        breakSessions: 0,
        breakMinutes: 0
    };
};

// Méthode statique pour obtenir le temps d'étude par jour
pomodoroSessionSchema.statics.getDailyStudyTime = async function(userId, days = 7) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    
    return await this.aggregate([
        {
            $match: {
                userId: new mongoose.Types.ObjectId(userId),
                completed: true,
                sessionType: 'focus',
                startTime: { $gte: startDate }
            }
        },
        {
            $group: {
                _id: {
                    $dateToString: { format: '%Y-%m-%d', date: '$startTime' }
                },
                totalMinutes: { $sum: '$duration' }
            }
        },
        {
            $sort: { _id: 1 }
        }
    ]);
};

module.exports = mongoose.model('PomodoroSession', pomodoroSessionSchema); 