const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
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
    title: {
        type: String,
        required: [true, 'Le titre de la tâche est requis'],
        trim: true,
        maxlength: [255, 'Le titre ne peut dépasser 255 caractères']
    },
    description: {
        type: String,
        maxlength: [1000, 'La description ne peut dépasser 1000 caractères'],
        default: null
    },
    completed: {
        type: Boolean,
        default: false
    },
    priority: {
        type: Number,
        default: 1,
        min: 1,
        max: 5,
        enum: [1, 2, 3, 4, 5] // 1 = Très basse, 5 = Très haute
    },
    dueDate: {
        type: Date,
        default: null
    },
    estimatedTime: {
        type: Number, // en minutes
        default: null,
        min: 0
    },
    actualTime: {
        type: Number, // en minutes
        default: 0,
        min: 0
    },
    tags: [{
        type: String,
        trim: true,
        maxlength: 50
    }],
    active: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Index pour optimiser les recherches
taskSchema.index({ userId: 1 });
taskSchema.index({ userId: 1, completed: 1 });
taskSchema.index({ userId: 1, priority: 1 });
taskSchema.index({ userId: 1, dueDate: 1 });
taskSchema.index({ userId: 1, subjectId: 1 });
taskSchema.index({ userId: 1, active: 1 });

// Méthode pour marquer comme terminée
taskSchema.methods.complete = function() {
    this.completed = true;
    return this.save();
};

// Méthode pour marquer comme non terminée
taskSchema.methods.uncomplete = function() {
    this.completed = false;
    return this.save();
};

// Méthode pour ajouter du temps réel
taskSchema.methods.addActualTime = function(minutes) {
    this.actualTime += minutes;
    return this.save();
};

// Méthode pour vérifier si la tâche est en retard
taskSchema.methods.isOverdue = function() {
    if (!this.dueDate || this.completed) return false;
    return new Date() > this.dueDate;
};

// Méthode statique pour obtenir les tâches d'un utilisateur
taskSchema.statics.getUserTasks = async function(userId, options = {}) {
    const query = { userId: userId, active: true };
    
    if (options.completed !== undefined) {
        query.completed = options.completed;
    }
    
    if (options.subjectId) {
        query.subjectId = options.subjectId;
    }
    
    if (options.priority) {
        query.priority = options.priority;
    }
    
    return await this.find(query)
        .populate('subjectId', 'name color')
        .sort({ 
            completed: 1, 
            priority: -1, 
            dueDate: 1, 
            createdAt: -1 
        });
};

// Méthode statique pour obtenir les statistiques des tâches
taskSchema.statics.getTaskStats = async function(userId) {
    const stats = await this.aggregate([
        { $match: { userId: new mongoose.Types.ObjectId(userId), active: true } },
        {
            $group: {
                _id: null,
                total: { $sum: 1 },
                completed: { $sum: { $cond: ['$completed', 1, 0] } },
                pending: { $sum: { $cond: ['$completed', 0, 1] } },
                overdue: {
                    $sum: {
                        $cond: [
                            { 
                                $and: [
                                    { $ne: ['$dueDate', null] },
                                    { $eq: ['$completed', false] },
                                    { $gt: ['$dueDate', new Date()] }
                                ]
                            },
                            1,
                            0
                        ]
                    }
                }
            }
        }
    ]);
    
    return stats.length > 0 ? stats[0] : {
        total: 0,
        completed: 0,
        pending: 0,
        overdue: 0
    };
};

module.exports = mongoose.model('Task', taskSchema); 