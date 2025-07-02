const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Le pseudo est requis'],
        unique: true,
        trim: true,
        minlength: [2, 'Le pseudo doit contenir au moins 2 caractères'],
        maxlength: [50, 'Le pseudo ne peut dépasser 50 caractères'],
        match: [/^[a-zA-Z0-9_-]+$/, 'Le pseudo ne peut contenir que des lettres, chiffres, tirets et underscores']
    },
    email: {
        type: String,
        required: [true, 'L\'email est requis'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Email invalide']
    },
    password: {
        type: String,
        required: [true, 'Le mot de passe est requis'],
        minlength: [6, 'Le mot de passe doit contenir au moins 6 caractères']
    },
    motivation: {
        type: String,
        maxlength: [500, 'La motivation ne peut dépasser 500 caractères'],
        default: null
    },
    niveau: {
        type: Number,
        default: 1,
        min: 1
    },
    tempsEtudeTotal: {
        type: Number,
        default: 0,
        min: 0
    },
    emailVerifie: {
        type: Boolean,
        default: false
    },
    tokenVerification: {
        type: String,
        default: null
    },
    dateVerification: {
        type: Date,
        default: null
    },
    dateCreation: {
        type: Date,
        default: Date.now
    },
    derniereConnexion: {
        type: Date,
        default: null
    },
    avatar: {
        type: String,
        default: null // URL de la photo de profil
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Index pour optimiser les recherches
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ emailVerifie: 1 });

// Méthode pour comparer les mots de passe
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Méthode pour hasher le mot de passe avant sauvegarde
userSchema.pre('save', async function(next) {
    // Ne hasher que si le mot de passe a été modifié
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Méthode pour mettre à jour la dernière connexion
userSchema.methods.updateLastLogin = function() {
    this.derniereConnexion = new Date();
    return this.save();
};

// Méthode pour générer un token de vérification
userSchema.methods.generateVerificationToken = async function() {
    try {
        const crypto = require('crypto');
        // Générer un nouveau token
        const token = crypto.randomBytes(32).toString('hex');
        
        // Mettre à jour le token et forcer la sauvegarde
        this.tokenVerification = token;
        await this.save({ validateBeforeSave: false });
        
        console.log('Token généré pour', this.email, ':', token);
        return token;
    } catch (error) {
        console.error('Erreur dans generateVerificationToken:', error);
        throw new Error('Erreur lors de la génération du token de vérification');
    }
};

// Méthode pour vérifier l'email
userSchema.methods.verifyEmail = async function() {
    try {
        console.log(`Tentative de vérification de l'email pour l'utilisateur: ${this._id}`);
        
        this.emailVerifie = true;
        this.tokenVerification = null;
        this.dateVerification = new Date();
        
        // Sauvegarder explicitement en désactivant la validation
        const user = await this.save({ validateBeforeSave: false });
        
        console.log(`Email vérifié avec succès pour l'utilisateur: ${this._id}`);
        return user;
    } catch (error) {
        console.error('Erreur lors de la vérification de l\'email:', error);
        throw error;
    }
};

// Méthode pour obtenir les données publiques (sans mot de passe)
userSchema.methods.toPublicJSON = function() {
    const user = this.toObject();
    delete user.password;
    delete user.tokenVerification;
    return user;
};

module.exports = mongoose.model('User', userSchema); 