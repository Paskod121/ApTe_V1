const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    token: {
        type: String,
        required: true,
        unique: true
    },
    dateExpiration: {
        type: Date,
        required: true,
        default: function() {
            // Expire dans 7 jours
            return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        }
    },
    userAgent: {
        type: String,
        default: null
    },
    ipAddress: {
        type: String,
        default: null
    },
    active: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Index pour optimiser les recherches
sessionSchema.index({ token: 1 });
sessionSchema.index({ userId: 1 });
sessionSchema.index({ dateExpiration: 1 });
sessionSchema.index({ active: 1 });

// Méthode pour vérifier si la session est expirée
sessionSchema.methods.isExpired = function() {
    return new Date() > this.dateExpiration;
};

// Méthode pour désactiver la session
sessionSchema.methods.deactivate = function() {
    this.active = false;
    return this.save();
};

// Méthode statique pour nettoyer les sessions expirées
sessionSchema.statics.cleanExpiredSessions = async function() {
    try {
        const result = await this.deleteMany({
            dateExpiration: { $lt: new Date() }
        });
        console.log(`🧹 ${result.deletedCount} sessions expirées supprimées`);
        return result.deletedCount;
    } catch (error) {
        console.error('Erreur nettoyage sessions:', error);
        return 0;
    }
};

// Méthode statique pour obtenir toutes les sessions actives d'un utilisateur
sessionSchema.statics.getActiveSessionsForUser = async function(userId) {
    return await this.find({
        userId: userId,
        active: true,
        dateExpiration: { $gt: new Date() }
    }).sort({ createdAt: -1 });
};

module.exports = mongoose.model('Session', sessionSchema); 