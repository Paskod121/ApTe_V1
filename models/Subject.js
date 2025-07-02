const mongoose = require('mongoose');

const subjectSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    name: {
        type: String,
        required: [true, 'Le nom de la matière est requis'],
        trim: true,
        maxlength: [100, 'Le nom ne peut dépasser 100 caractères']
    },
    codeUE: {
        type: String,
        required: [true, 'Le code UE est requis'],
        trim: true,
        maxlength: [20, 'Le code UE ne peut dépasser 20 caractères']
    },
    prof: {
        type: String,
        trim: true,
        maxlength: [100, 'Le nom du professeur ne peut dépasser 100 caractères'],
        default: null
    },
    credits: {
        type: Number,
        min: 0,
        max: 60,
        default: 0
    },
    examDate: {
        type: Date,
        default: null
    },
    color: {
        type: String,
        default: '#4F46E5',
        match: [/^#[0-9A-F]{6}$/i, 'Couleur invalide (format hex)']
    },
    studyTime: {
        type: Number,
        default: 0,
        min: 0
    },
    description: {
        type: String,
        maxlength: [500, 'La description ne peut dépasser 500 caractères'],
        default: null
    },
    active: {
        type: Boolean,
        default: true
    },
    order: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true
});

// Index pour optimiser les recherches
subjectSchema.index({ userId: 1 });
subjectSchema.index({ userId: 1, order: 1 });
// Index d'unicité sur le code UE par utilisateur
subjectSchema.index(
  { userId: 1, codeUE: 1 },
  { unique: true }
);

// Méthode pour ajouter du temps d'étude
subjectSchema.methods.addStudyTime = function(minutes) {
    this.studyTime += minutes;
    return this.save();
};

// Méthode pour réinitialiser le temps d'étude
subjectSchema.methods.resetStudyTime = function() {
    this.studyTime = 0;
    return this.save();
};

// Méthode statique pour obtenir les matières d'un utilisateur
subjectSchema.statics.getUserSubjects = async function(userId) {
    return await this.find({
        userId: userId
    }).sort({ order: 1, createdAt: 1 });
};

// Méthode statique pour obtenir le temps total d'étude d'un utilisateur
subjectSchema.statics.getTotalStudyTime = async function(userId) {
    const result = await this.aggregate([
        { $match: { userId: new mongoose.Types.ObjectId(userId) } },
        { $group: { _id: null, total: { $sum: '$studyTime' } } }
    ]);
    return result.length > 0 ? result[0].total : 0;
};

module.exports = mongoose.model('Subject', subjectSchema); 