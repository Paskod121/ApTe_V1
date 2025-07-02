// Charger dotenv en premier
const dotenv = require('dotenv');
const path = require('path');
const url = require('url');

// Charger le fichier .env à partir du répertoire courant
const envPath = path.resolve(__dirname, '.env');

const result = dotenv.config({ path: envPath });
if (result.error) {
    console.error('Erreur lors du chargement du fichier .env:', result.error);
    process.exit(1);
}

console.log('=== Variables d\'environnement chargées ===');
console.log('NODE_ENV:', process.env.NODE_ENV || 'non défini');
console.log('EMAIL_USER:', process.env.EMAIL_USER ? 'défini' : 'non défini');
console.log('MONGODB_URI:', process.env.MONGODB_URI ? 'défini' : 'non défini');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'défini' : 'non défini');
console.log('FRONTEND_URL:', process.env.FRONTEND_URL || 'http://localhost:3000');
console.log('===============================');

// Vérifier les variables requises
const requiredEnvVars = ['EMAIL_USER', 'EMAIL_PASSWORD', 'MONGODB_URI', 'JWT_SECRET'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('❌ Variables d\'environnement manquantes :', missingVars.join(', '));
    console.error('Veuillez les définir dans le fichier .env');
    process.exit(1);
}

// Vérifier les variables optionnelles
const optionalEnvVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_CALLBACK_URL'];
const missingOptionalVars = optionalEnvVars.filter(varName => !process.env[varName]);

if (missingOptionalVars.length > 0) {
    console.warn('⚠️  Variables d\'environnement optionnelles manquantes :', missingOptionalVars.join(', '));
    console.warn('   Ces variables sont nécessaires pour l\'authentification Google');
} else {
    console.log('✅ Configuration Google OAuth détectée');
    console.log('   - Client ID:', process.env.GOOGLE_CLIENT_ID ? 'défini' : 'non défini');
    console.log('   - Callback URL:', process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback');
}

console.log('===============================');

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const { sendVerificationEmail } = require('./services/emailService');
const UserAction = require('./models/UserAction');
const Notification = require('./models/Notification');

// Import des modèles
const User = require('./models/User');
const Session = require('./models/Session');
const Subject = require('./models/Subject');
const Task = require('./models/Task');
const PomodoroSession = require('./models/PomodoroSession');
const Reward = require('./models/Reward');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'apte-secret-key-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/apte';

// Connexion à MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('✅ Connecté à MongoDB');
    console.log(`📊 Base de données: ${MONGODB_URI}`);
})
.catch((err) => {
    console.error('❌ Erreur connexion MongoDB:', err.message);
    process.exit(1);
});

// Middleware
const allowedOrigins = [
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'http://localhost:5500',
    'http://127.0.0.1:5501',
    'http://localhost:5501',
    'http://127.0.0.1:3000'
];

// Configuration CORS simplifiée et robuste
app.use(cors({
    origin: true, // Autoriser toutes les origines en développement
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    optionsSuccessStatus: 200
}));

// Configuration CSP pour autoriser Google OAuth et autres ressources nécessaires
app.use((req, res, next) => {
    const origin = req.headers.origin || '';
    
    // Mettre à jour CSP pour inclure l'origine de la requête
    res.setHeader('Content-Security-Policy', 
        `default-src 'self'; ` +
        `base-uri 'self' https://accounts.google.com; ` +
        `script-src 'self' 'unsafe-inline' 'unsafe-eval' https://accounts.google.com https://apis.google.com https://www.googletagmanager.com https://www.google-analytics.com https://www.gstatic.com ${origin}; ` +
        `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://accounts.google.com https://www.gstatic.com ${origin}; ` +
        `img-src 'self' data: https: http: blob: ${origin}; ` +
        `font-src 'self' https://fonts.gstatic.com https://accounts.google.com data: https://www.gstatic.com ${origin}; ` +
        `frame-src 'self' https://accounts.google.com https://www.youtube.com https://www.google.com; ` +
        `connect-src 'self' https://accounts.google.com https://www.googleapis.com http://localhost:3000 http://127.0.0.1:3000 http://localhost:5501 http://127.0.0.1:5501 https://play.google.com; ` +
        `form-action 'self' https://accounts.google.com;`
    );
    
    // Gérer les requêtes OPTIONS de manière explicite
    if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Max-Age', '86400'); // 24 heures
        return res.sendStatus(200);
    }
    
    next();
});

// Servir les fichiers statiques (CSS, JS, images, etc.)
app.use(express.static('.'));
app.use(express.json({ limit: '2mb' }));

// Middleware session (obligatoire pour Passport)
app.use(session({
    secret: process.env.SESSION_SECRET || 'apte-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 jours
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// Middleware de validation des erreurs
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Données invalides',
            errors: errors.array()
        });
    }
    next();
};

// Middleware d'authentification JWT
const authenticateToken = async (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Token d\'authentification requis'
        });
    }

    try {
        // Vérifier le token JWT
        const decoded = jwt.verify(token, JWT_SECRET);

        // Récupérer l'utilisateur
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(403).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({
            success: false,
            message: 'Token invalide'
        });
    }
};

// Configuration Passport
passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Configuration de la stratégie JWT pour Passport
passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        (req) => req.cookies?.apte_token // Extraire depuis les cookies aussi
    ]),
    secretOrKey: JWT_SECRET
}, async (payload, done) => {
    try {
        const user = await User.findById(payload.userId);
        if (user) {
            return done(null, user);
        }
        return done(null, false);
    } catch (error) {
        return done(error, false);
    }
}));

// Initialisation conditionnelle de la stratégie Google OAuth
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    console.log('=== Initialisation de la stratégie Google OAuth ===');
    console.log('Client ID:', process.env.GOOGLE_CLIENT_ID ? 'défini' : 'non défini');
    console.log('Callback URL:', process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback');
    
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
        passReqToCallback: true
    }, async (req, accessToken, refreshToken, profile, done) => {
        try {
            console.log('=== Début de la stratégie Google OAuth ===');
            console.log('Profil Google reçu:', {
                id: profile.id,
                displayName: profile.displayName,
                emails: profile.emails,
                provider: profile.provider
            });
            
            if (!profile.emails || !profile.emails[0]) {
                console.error('❌ Aucun email trouvé dans le profil Google');
                return done(new Error('Aucun email associé à ce compte Google'), null);
            }

            const email = profile.emails[0].value.toLowerCase();
            console.log(`Recherche de l'utilisateur avec l'email: ${email}`);
            
            let user = await User.findOne({ email });
            
            if (!user) {
                console.log('Création d\'un nouvel utilisateur pour:', email);
                user = new User({
                    username: (profile.displayName || email.split('@')[0]).replace(/[^a-zA-Z0-9_-]/g, '_'),
                    email,
                    password: Math.random().toString(36).slice(-12),
                    motivation: '',
                    emailVerifie: false,
                    tokenVerification: null
                });
                await user.save();
                // Générer un token de vérification
                const verificationToken = await user.generateVerificationToken();
                // Construire le lien de vérification
                const verificationLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
                // Envoyer l'email de vérification
                await sendVerificationEmail(user.email, user.username, verificationLink);
                console.log(`✅ Nouvel utilisateur créé via Google: ${user._id} - ${user.email} (email de vérification envoyé)`);
            } else {
                console.log(`Utilisateur existant trouvé: ${user._id} - ${user.email}`);
                // Mise à jour des informations si nécessaire
                if (!user.emailVerifie) {
                    // Générer un nouveau token de vérification
                    const verificationToken = await user.generateVerificationToken();
                    const verificationLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
                    await sendVerificationEmail(user.email, user.username, verificationLink);
                    console.log(`✅ Email de vérification renvoyé pour: ${user.email}`);
                }
            }
            
            console.log('=== Fin de la stratégie Google OAuth avec succès ===');
            return done(null, user);
            
        } catch (err) {
            console.error('❌ Erreur dans la stratégie Google OAuth:', err);
            return done(err, null);
        }
    }));
    
    console.log('=== Configuration des routes Google OAuth ===');
    console.log('GET /auth/google');
    console.log('GET /auth/google/callback');
    
    app.get('/auth/google', (req, res, next) => {
        console.log('Début du flux OAuth Google');
        next();
    }, (req, res, next) => {
        // Récupérer le mode (signup/login) depuis la query
        const mode = req.query.mode || 'login';
        // Utiliser le paramètre state pour transmettre le mode
        passport.authenticate('google', {
            scope: ['profile', 'email'],
            prompt: 'select_account',
            state: mode
        })(req, res, next);
    });

    app.get('/auth/google/callback', (req, res, next) => {
        console.log('Callback Google OAuth reçu');
        next();
    }, (req, res, next) => {
        // Récupérer le mode depuis le paramètre state
        req.authMode = req.query.state || 'login';
        next();
    }, passport.authenticate('google', {
        failureRedirect: '/?error=auth_failed',
        session: false
    }), async (req, res) => {
        try {
            if (!req.user) {
                return res.redirect('/?error=auth_failed');
            }
            // Si l'utilisateur n'a pas vérifié son email, le rediriger vers la page de vérification
            if (!req.user.emailVerifie) {
                const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?email=${encodeURIComponent(req.user.email)}`;
                return res.redirect(redirectUrl);
            }
            // Générer un token JWT
            const token = jwt.sign(
                {
                    userId: req.user._id,
                    email: req.user.email,
                    username: req.user.username
                },
                JWT_SECRET,
                { expiresIn: '7d' }
            );
            // Créer une session en base de données
            const session = new Session({
                userId: req.user._id,
                token: token,
                userAgent: req.get('User-Agent') || 'Google OAuth',
                ipAddress: req.ip || req.connection.remoteAddress
            });
            await session.save();
            await req.user.updateLastLogin();
            // Déterminer si c'est un nouvel utilisateur ou un existant
            let isNew = false;
            if (req.query && req.query.state) {
                // On ne peut pas savoir ici, donc on va checker si l'utilisateur a été créé il y a moins de 2 minutes
                const now = Date.now();
                const created = req.user.createdAt ? new Date(req.user.createdAt).getTime() : 0;
                if (now - created < 2 * 60 * 1000) {
                    isNew = true;
                }
            }
            // Rediriger avec le token et les bons paramètres
            const params = new url.URLSearchParams({
                google_token: token,
                mode: req.authMode || 'login',
            });
            if (isNew) {
                params.set('new', '1');
            } else {
                params.set('existing', '1');
            }
            const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}?${params.toString()}`;
            res.redirect(redirectUrl);
        } catch (error) {
            console.error('❌ Erreur lors de la création du token JWT:', error);
            res.redirect('/?error=token_error');
        }
    });

    // Route pour obtenir les informations de l'utilisateur connecté via JWT
    app.get('/api/me', 
        passport.authenticate('jwt', { session: false }), 
        (req, res) => {
            res.json({
                success: true,
                user: {
                    id: req.user._id,
                    username: req.user.username,
                    email: req.user.email,
                    emailVerifie: req.user.emailVerifie || true
                }
            });
        }
    );

    // Route de callback pour le frontend après Google OAuth
    app.get('/auth/callback', (req, res) => {
        const { token } = req.query;
        
        if (!token) {
            return res.redirect('/?error=no_token');
        }

        // Rediriger vers le frontend avec le token
        const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}?google_token=${token}`;
        res.redirect(redirectUrl);
    });
} else {
    console.log('⚠️  GOOGLE_CLIENT_ID ou GOOGLE_CLIENT_SECRET non définis : Google OAuth désactivé');
}

// Routes API

// Route d'inscription
app.post('/api/register', [
    body('username')
        .isLength({ min: 2, max: 50 })
        .withMessage('Le pseudo doit contenir entre 2 et 50 caractères')
        .matches(/^[a-zA-Z0-9_-]+$/)
        .withMessage('Le pseudo ne peut contenir que des lettres, chiffres, tirets et underscores'),
    body('email')
        .isEmail()
        .withMessage('Email invalide'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Le mot de passe doit contenir au moins 6 caractères'),
    body('motivation')
        .optional()
        .isLength({ max: 500 })
        .withMessage('La motivation ne peut dépasser 500 caractères'),
    handleValidationErrors
], async (req, res) => {
    try {
        const { username, email, password, motivation } = req.body;

        // Vérifier si le pseudo existe déjà
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Ce pseudo est déjà utilisé'
            });
        }

        // Vérifier si l'email existe déjà
        const existingEmail = await User.findOne({ email: email.toLowerCase() });
        if (existingEmail) {
            return res.status(400).json({
                success: false,
                message: 'Cet email est déjà utilisé'
            });
        }

        // Créer l'utilisateur
        const user = new User({
            username,
            email: email.toLowerCase(),
            password,
            motivation
        });

        // Sauvegarder l'utilisateur d'abord pour avoir un ID
        await user.save();
        
        // Générer un token de vérification et le sauvegarder
        const verificationToken = await user.generateVerificationToken();
        
        // Construire le lien de vérification avec le token fraîchement généré
        const verificationLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
        
        // Envoyer l'email de vérification
        try {
            await sendVerificationEmail(user.email, user.username, verificationLink);
            
            res.status(201).json({
                success: true,
                message: 'Inscription réussie ! Vérifiez votre email pour activer votre compte.',
                data: {
                    userId: user._id,
                    username: user.username,
                    email: user.email,
                    verificationToken
                }
            });
        } catch (emailError) {
            // Supprimer l'utilisateur si l'envoi d'email échoue
            await User.findByIdAndDelete(user._id);
            
            return res.status(500).json({
                success: false,
                message: 'Inscription échouée : impossible d\'envoyer l\'email de vérification',
                error: process.env.NODE_ENV === 'development' ? emailError.message : undefined
            });
        }
    } catch (error) {
        console.error('❌ Erreur inattendue lors de l\'inscription:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de l\'inscription',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Route de connexion
app.post('/api/login', [
    body('email').isEmail().withMessage('Email invalide'),
    body('password').notEmpty().withMessage('Mot de passe requis'),
    handleValidationErrors
], async (req, res) => {
    try {
        const { email, password } = req.body;

        // Rechercher l'utilisateur par email
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Email ou mot de passe incorrect'
            });
        }

        // Vérifier si l'email est vérifié
        if (!user.emailVerifie) {
            return res.status(401).json({
                success: false,
                message: 'Veuillez vérifier votre email avant de vous connecter'
            });
        }

        // Vérifier le mot de passe
        const passwordValid = await user.comparePassword(password);
        if (!passwordValid) {
            return res.status(401).json({
                success: false,
                message: 'Email ou mot de passe incorrect'
            });
        }

        // Générer un token JWT
        const token = jwt.sign(
            { 
                userId: user._id, 
                username: user.username, 
                email: user.email 
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Créer une session
        const session = new Session({
            userId: user._id,
            token: token,
            userAgent: req.get('User-Agent'),
            ipAddress: req.ip
        });

        await session.save();

        // Mettre à jour la dernière connexion
        await user.updateLastLogin();

        res.json({
            success: true,
            message: 'Connexion réussie !',
            data: {
                token,
                user: user.toPublicJSON()
            }
        });

    } catch (error) {
        console.error('Erreur connexion:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route de vérification d'email (API)
app.get('/api/verify-email', async (req, res) => {
    try {
        const { token, email } = req.query;
        console.log('Tentative de vérification d\'email:', { token: token ? 'présent' : 'manquant', email: email || 'manquant' });

        if (!token || !email) {
            console.error('Paramètres manquants pour la vérification d\'email');
            return res.status(400).json({
                success: false,
                message: 'Token et email requis'
            });
        }

        // Vérifier le token et l'email
        const user = await User.findOne({
            tokenVerification: token,
            email: email.toLowerCase()
        });

        if (!user) {
            console.error('Aucun utilisateur trouvé avec ce token et cet email');
            return res.status(400).json({
                success: false,
                message: 'Lien de vérification invalide ou expiré. Veuillez en demander un nouveau.'
            });
        }

        // Vérifier si l'email est déjà vérifié
        if (user.emailVerifie) {
            console.log('Email déjà vérifié pour l\'utilisateur:', user._id);
            return res.json({
                success: true,
                message: 'Votre email a déjà été vérifié. Vous pouvez vous connecter.'
            });
        }

        console.log('Utilisateur trouvé, vérification de l\'email...');
        
        // Marquer l'email comme vérifié
        await user.verifyEmail();
        console.log('Email vérifié avec succès pour l\'utilisateur:', user._id);

        res.json({
            success: true,
            message: 'Email vérifié avec succès ! Vous pouvez maintenant vous connecter.'
        });

    } catch (error) {
        console.error('Erreur lors de la vérification d\'email:', error);
        res.status(500).json({
            success: false,
            message: 'Une erreur est survenue lors de la vérification de votre email. Veuillez réessayer.'
        });
    }
});

// Route pour la page de vérification d'email (frontend)
app.get('/verify-email', async (req, res) => {
    try {
        const { token, email } = req.query;
        const emailVerificationTemplate = fs.readFileSync(path.join(__dirname, 'email-verification-template.html'), 'utf8');

        let messageHtml = '';
        let statusCode = 200;

        if (!token || !email) {
            messageHtml = `
                <div class="error">❌ Erreur de vérification</div>
                <p>Le lien de vérification est incomplet. Veuillez utiliser le lien fourni dans votre email.</p>
            `;
            statusCode = 400;
        } else {
            try {
                // Vérifier le token et l'email
                const user = await User.findOne({
                    tokenVerification: token,
                    email: email.toLowerCase(),
                    emailVerifie: false
                });

                if (!user) {
                    messageHtml = `
                        <div class="error">❌ Lien invalide ou expiré</div>
                        <p>Le lien de vérification est incorrect, a expiré ou a déjà été utilisé.</p>
                        <p>Si vous n'avez pas encore vérifié votre email, essayez de vous connecter pour recevoir un nouveau lien.</p>
                    `;
                    statusCode = 400;
                } else {
                    // Marquer l'email comme vérifié
                    await user.verifyEmail();
                    messageHtml = `
                        <div class="success">✅ Email vérifié avec succès !</div>
                        <p>Votre compte ApTe a été activé avec succès.</p>
                        <p>Vous pouvez maintenant vous connecter et commencer à utiliser l'application.</p>
                        <a href="/" class="btn btn-primary">Aller à la page de connexion</a>
                    `;
                }
            } catch (error) {
                console.error('Erreur lors de la vérification de l\'email :', error);
                messageHtml = `
                    <div class="error">❌ Erreur lors de la vérification</div>
                    <p>Une erreur est survenue lors de la vérification de votre email. Veuillez réessayer plus tard.</p>
                `;
                statusCode = 500;
            }
        }

        // Remplacer dynamiquement le contenu du bloc #message-block
        const page = emailVerificationTemplate.replace(
            /<div id="message-block">([\s\S]*?)<\/div>/,
            `<div id="message-block">${messageHtml}</div>`
        );

        return res.status(statusCode).send(page);

    } catch (error) {
        console.error('Erreur critique dans la vérification d\'email :', error);
        
        // En cas d'erreur critique, renvoyer une page d'erreur basique
        try {
            return res.status(500).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Erreur de vérification</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .error { color: #dc2626; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <h1>Erreur de vérification</h1>
                    <div class="error">Une erreur inattendue s'est produite lors de la vérification de votre email.</div>
                    <p>Veuillez réessayer plus tard ou contacter le support si le problème persiste.</p>
                    <a href="/">Retour à l'accueil</a>
                </body>
                </html>
            `);
        } catch (e) {
            return res.status(500).send('Erreur de vérification. Veuillez réessayer plus tard.');
        }
    }
});

// Route de déconnexion
app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        // Désactiver la session
        await req.session.deactivate();

        res.json({
            success: true,
            message: 'Déconnexion réussie'
        });
    } catch (error) {
        console.error('Erreur déconnexion:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la déconnexion'
        });
    }
});

// Route protégée - profil utilisateur
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        res.json({
            success: true,
            data: req.user.toPublicJSON()
        });
    } catch (error) {
        console.error('Erreur récupération profil:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour obtenir les statistiques utilisateur
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user._id;

        // Statistiques des sessions Pomodoro
        const sessionStats = await PomodoroSession.getSessionStats(userId, 'today');
        
        // Statistiques des tâches
        const taskStats = await Task.getTaskStats(userId);
        
        // Temps total d'étude
        const totalStudyTime = await Subject.getTotalStudyTime(userId);

        res.json({
            success: true,
            data: {
                sessions: sessionStats,
                tasks: taskStats,
                totalStudyTime
            }
        });
    } catch (error) {
        console.error('Erreur récupération stats:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route protégée pour mettre à jour l'avatar
app.post('/api/profile/avatar', authenticateToken, async (req, res) => {
    try {
        const { avatar } = req.body;
        if (!avatar || typeof avatar !== 'string') {
            return res.status(400).json({
                success: false,
                message: 'Avatar manquant ou invalide.'
            });
        }
        req.user.avatar = avatar;
        await req.user.save();
        res.json({
            success: true,
            message: 'Avatar mis à jour avec succès.',
            data: req.user.toPublicJSON()
        });
    } catch (error) {
        console.error('Erreur mise à jour avatar:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de la mise à jour de l\'avatar.'
        });
    }
});

// === API REST pour les matières (subjects) ===
// Liste des matières de l'utilisateur
app.get('/api/subjects', authenticateToken, async (req, res) => {
    try {
        const subjects = await Subject.getUserSubjects(req.user._id);
        res.json({ success: true, data: subjects });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Ajouter une matière
app.post('/api/subjects', authenticateToken, async (req, res) => {
    try {
        const { name, codeUE, prof, credits, examDate, color, description } = req.body;
        if (!name || !codeUE) return res.status(400).json({ success: false, message: 'Nom et code UE requis' });
        const subject = new Subject({
            userId: req.user._id,
            name,
            codeUE,
            prof: prof || null,
            credits: credits || 0,
            examDate: examDate || null,
            color: color || '#4F46E5',
            description: description || null
        });
        await subject.save();
        res.status(201).json({ success: true, data: subject });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ success: false, message: 'Ce code UE existe déjà pour cet utilisateur.' });
        }
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Modifier une matière
app.put('/api/subjects/:id', authenticateToken, async (req, res) => {
    try {
        const { name, codeUE, prof, credits, examDate, color, description } = req.body;
        const subject = await Subject.findOneAndUpdate(
            { _id: req.params.id, userId: req.user._id },
            { name, codeUE, prof, credits, examDate, color, description },
            { new: true, runValidators: true }
        );
        if (!subject) return res.status(404).json({ success: false, message: 'Matière non trouvée' });
        res.json({ success: true, data: subject });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ success: false, message: 'Ce code UE existe déjà pour cet utilisateur.' });
        }
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Supprimer une matière (suppression physique)
app.delete('/api/subjects/:id', authenticateToken, async (req, res) => {
    try {
        console.log('🗑️ Tentative de suppression de la matière:', req.params.id);
        
        const subject = await Subject.findOneAndDelete(
            { _id: req.params.id, userId: req.user._id }
        );
        
        if (!subject) {
            console.log('❌ Matière non trouvée ou non autorisée');
            return res.status(404).json({ 
                success: false, 
                message: 'Matière non trouvée ou non autorisée' 
            });
        }
        
        console.log('✅ Matière supprimée avec succès:', subject.name);
        res.json({ 
            success: true, 
            message: 'Matière supprimée définitivement', 
            data: subject 
        });
    } catch (error) {
        console.error('❌ Erreur lors de la suppression:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erreur serveur lors de la suppression' 
        });
    }
});

// === API REST pour les tâches (tasks) ===
// Liste des tâches de l'utilisateur
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const { completed, subjectId, priority } = req.query;
        const options = {};
        
        if (completed !== undefined) {
            options.completed = completed === 'true';
        }
        if (subjectId) {
            options.subjectId = subjectId;
        }
        if (priority) {
            options.priority = parseInt(priority);
        }
        
        const tasks = await Task.getUserTasks(req.user._id, options);
        res.json({ success: true, data: tasks });
    } catch (error) {
        console.error('Erreur récupération tâches:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Ajouter une tâche
app.post('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const { 
            title, 
            description, 
            subjectId, 
            priority, 
            dueDate, 
            estimatedTime, 
            tags 
        } = req.body;
        
        if (!title) {
            return res.status(400).json({ 
                success: false, 
                message: 'Le titre de la tâche est requis' 
            });
        }
        
        const task = new Task({
            userId: req.user._id,
            title,
            description: description || null,
            subjectId: subjectId || null,
            priority: priority || 1,
            dueDate: dueDate || null,
            estimatedTime: estimatedTime || null,
            tags: tags || []
        });
        
        await task.save();
        
        // Récupérer la tâche avec les détails de la matière
        const populatedTask = await Task.findById(task._id).populate('subjectId', 'name color');
        
        res.status(201).json({ success: true, data: populatedTask });
    } catch (error) {
        console.error('Erreur ajout tâche:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Modifier une tâche
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
    try {
        const { 
            title, 
            description, 
            subjectId, 
            priority, 
            dueDate, 
            estimatedTime, 
            tags,
            completed 
        } = req.body;
        
        const updateData = {};
        if (title !== undefined) updateData.title = title;
        if (description !== undefined) updateData.description = description;
        if (subjectId !== undefined) updateData.subjectId = subjectId;
        if (priority !== undefined) updateData.priority = priority;
        if (dueDate !== undefined) updateData.dueDate = dueDate;
        if (estimatedTime !== undefined) updateData.estimatedTime = estimatedTime;
        if (tags !== undefined) updateData.tags = tags;
        if (completed !== undefined) updateData.completed = completed;
        
        const task = await Task.findOneAndUpdate(
            { _id: req.params.id, userId: req.user._id },
            updateData,
            { new: true, runValidators: true }
        ).populate('subjectId', 'name color');
        
        if (!task) {
            return res.status(404).json({ 
                success: false, 
                message: 'Tâche non trouvée' 
            });
        }
        
        res.json({ success: true, data: task });
    } catch (error) {
        console.error('Erreur modification tâche:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Supprimer une tâche (suppression physique)
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
    try {
        console.log('🗑️ Tentative de suppression de la tâche:', req.params.id);
        
        const task = await Task.findOneAndDelete(
            { _id: req.params.id, userId: req.user._id }
        );
        
        if (!task) {
            console.log('❌ Tâche non trouvée ou non autorisée');
            return res.status(404).json({ 
                success: false, 
                message: 'Tâche non trouvée ou non autorisée' 
            });
        }
        
        console.log('✅ Tâche supprimée avec succès:', task.title);
        res.json({ 
            success: true, 
            message: 'Tâche supprimée définitivement', 
            data: task 
        });
    } catch (error) {
        console.error('❌ Erreur lors de la suppression:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erreur serveur lors de la suppression' 
        });
    }
});

// Marquer une tâche comme terminée/non terminée
app.patch('/api/tasks/:id/toggle', authenticateToken, async (req, res) => {
    try {
        const task = await Task.findOne({ _id: req.params.id, userId: req.user._id });
        
        if (!task) {
            return res.status(404).json({ 
                success: false, 
                message: 'Tâche non trouvée' 
            });
        }
        
        task.completed = !task.completed;
        await task.save();
        
        const populatedTask = await Task.findById(task._id).populate('subjectId', 'name color');
        
        res.json({ 
            success: true, 
            data: populatedTask,
            message: task.completed ? 'Tâche marquée comme terminée' : 'Tâche marquée comme non terminée'
        });
    } catch (error) {
        console.error('Erreur toggle tâche:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Ajouter du temps réel à une tâche
app.patch('/api/tasks/:id/time', authenticateToken, async (req, res) => {
    try {
        const { minutes } = req.body;
        
        if (!minutes || minutes <= 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Temps en minutes requis et positif' 
            });
        }
        
        const task = await Task.findOne({ _id: req.params.id, userId: req.user._id });
        
        if (!task) {
            return res.status(404).json({ 
                success: false, 
                message: 'Tâche non trouvée' 
            });
        }
        
        await task.addActualTime(minutes);
        
        const populatedTask = await Task.findById(task._id).populate('subjectId', 'name color');
        
        res.json({ 
            success: true, 
            data: populatedTask,
            message: `${minutes} minutes ajoutées à la tâche`
        });
    } catch (error) {
        console.error('Erreur ajout temps tâche:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// === Routes pour les récompenses ===
app.get('/api/rewards/profile', authenticateToken, async (req, res) => {
    try {
        let reward = await Reward.findOne({ userId: req.user.id });
        
        if (!reward) {
            // Créer un profil de récompenses pour l'utilisateur
            reward = new Reward({
                userId: req.user.id,
                points: 0,
                level: 1,
                xp: 0,
                earnedBadges: [],
                achievements: [],
                stats: {
                    tasksCompleted: 0,
                    sessionsCompleted: 0,
                    studyStreak: 0,
                    totalStudyTime: 0
                }
            });
            await reward.save();
        }
        
        res.json({
            success: true,
            data: reward
        });
    } catch (error) {
        console.error('Erreur récupération récompenses:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

app.post('/api/rewards/add-points', authenticateToken, async (req, res) => {
    try {
        const { points, reason } = req.body;
        
        let reward = await Reward.findOne({ userId: req.user.id });
        if (!reward) {
            reward = new Reward({ userId: req.user.id });
        }
        
        const oldLevel = reward.level;
        reward.points += points;
        reward.xp += points;
        
        // Vérifier le passage de niveau
        const xpNeeded = reward.level * 100;
        if (reward.xp >= xpNeeded) {
            reward.level++;
            reward.xp -= xpNeeded;
        }
        
        await reward.save();
        
        res.json({
            success: true,
            data: reward,
            levelUp: oldLevel !== reward.level
        });
    } catch (error) {
        console.error('Erreur ajout points:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

app.post('/api/rewards/earn-badge', authenticateToken, async (req, res) => {
    try {
        const { badgeId } = req.body;
        
        let reward = await Reward.findOne({ userId: req.user.id });
        if (!reward) {
            reward = new Reward({ userId: req.user.id });
        }
        
        if (!reward.earnedBadges.includes(badgeId)) {
            reward.earnedBadges.push(badgeId);
            reward.achievements.push({
                badgeId,
                earnedAt: new Date()
            });
            
            // Ajouter des points pour le badge
            reward.points += 50;
            reward.xp += 50;
            
            await reward.save();
        }
        
        res.json({
            success: true,
            data: reward
        });
    } catch (error) {
        console.error('Erreur badge obtenu:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

app.get('/api/rewards/leaderboard', authenticateToken, async (req, res) => {
    try {
        const leaderboard = await Reward.find()
            .populate('userId', 'username email avatar')
            .sort({ points: -1, level: -1 })
            .limit(10);
        
        res.json({
            success: true,
            data: leaderboard
        });
    } catch (error) {
        console.error('Erreur classement:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour créer une session Pomodoro
app.post('/api/pomodoro-sessions', authenticateToken, async (req, res) => {
    try {
        const { subjectId, taskId, duration, sessionType, notes } = req.body;
        if (!duration || duration < 1 || duration > 120) {
            return res.status(400).json({ success: false, message: 'Durée invalide' });
        }
        const session = new PomodoroSession({
            userId: req.user._id,
            subjectId: subjectId || null,
            taskId: taskId || null,
            duration,
            sessionType: sessionType || 'focus',
            notes: notes || null,
            completed: true,
            startTime: new Date(),
            endTime: new Date()
        });
        await session.save();

        // Récompense automatique : 10 points par session Pomodoro
        let reward = await Reward.findOne({ userId: req.user._id });
        if (!reward) {
            reward = new Reward({ userId: req.user._id });
        }
        reward.points += 10;
        reward.xp += 10;
        reward.stats.sessionsCompleted = (reward.stats.sessionsCompleted || 0) + 1;
        // Passage de niveau si besoin
        const oldLevel = reward.level;
        const xpNeeded = reward.level * 100;
        let levelUp = false;
        if (reward.xp >= xpNeeded) {
            reward.level++;
            reward.xp -= xpNeeded;
            levelUp = true;
            // Notification de level up
            await Notification.create({
                userId: req.user._id,
                type: 'level_up',
                message: `Bravo, tu passes au niveau ${reward.level} !`,
                metadata: { newLevel: reward.level }
            });
        }
        // Attribution automatique de badges
        const newBadges = [];
        const now = new Date();
        // Badge 1ère session
        if (reward.stats.sessionsCompleted >= 1 && !reward.earnedBadges.includes('pomodoro_starter')) {
            reward.earnedBadges.push('pomodoro_starter');
            reward.achievements.push({ badgeId: 'pomodoro_starter', earnedAt: now });
            newBadges.push('pomodoro_starter');
            await UserAction.create({
                userId: req.user._id,
                actionType: 'badge_earned',
                pointsEarned: 0,
                metadata: { badgeId: 'pomodoro_starter' }
            });
            // Notification badge (uniquement si non existante)
            const existingBadgeNotif = await Notification.findOne({
                userId: req.user._id,
                type: 'badge',
                'metadata.badgeId': 'pomodoro_starter'
            });
            if (!existingBadgeNotif) {
                await Notification.create({
                    userId: req.user._id,
                    type: 'badge',
                    message: `Nouveau badge : Première session Pomodoro !`,
                    metadata: { badgeId: 'pomodoro_starter' }
                });
            }
        }
        // Badge 10 sessions
        if (reward.stats.sessionsCompleted >= 10 && !reward.earnedBadges.includes('pomodoro_master')) {
            reward.earnedBadges.push('pomodoro_master');
            reward.achievements.push({ badgeId: 'pomodoro_master', earnedAt: now });
            newBadges.push('pomodoro_master');
            await UserAction.create({
                userId: req.user._id,
                actionType: 'badge_earned',
                pointsEarned: 0,
                metadata: { badgeId: 'pomodoro_master' }
            });
            // Notification badge (uniquement si non existante)
            const existingBadgeNotif = await Notification.findOne({
                userId: req.user._id,
                type: 'badge',
                'metadata.badgeId': 'pomodoro_master'
            });
            if (!existingBadgeNotif) {
                await Notification.create({
                    userId: req.user._id,
                    type: 'badge',
                    message: `Nouveau badge : Maître Pomodoro !`,
                    metadata: { badgeId: 'pomodoro_master' }
                });
            }
        }
        // Badge 100 points
        if (reward.points >= 100 && !reward.earnedBadges.includes('points_100')) {
            reward.earnedBadges.push('points_100');
            reward.achievements.push({ badgeId: 'points_100', earnedAt: now });
            newBadges.push('points_100');
            await UserAction.create({
                userId: req.user._id,
                actionType: 'badge_earned',
                pointsEarned: 0,
                metadata: { badgeId: 'points_100' }
            });
            // Notification badge (uniquement si non existante)
            const existingBadgeNotif = await Notification.findOne({
                userId: req.user._id,
                type: 'badge',
                'metadata.badgeId': 'points_100'
            });
            if (!existingBadgeNotif) {
                await Notification.create({
                    userId: req.user._id,
                    type: 'badge',
                    message: `Nouveau badge : 100 points !`,
                    metadata: { badgeId: 'points_100' }
                });
            }
        }
        // Notification de points gagnés : éviter les doublons
        const existingPointsNotif = await Notification.findOne({
            userId: req.user._id,
            type: 'points',
            'metadata.sessionId': session._id
        });
        if (!existingPointsNotif) {
            await Notification.create({
                userId: req.user._id,
                type: 'points',
                message: `+10 points gagnés !`,
                metadata: { points: 10, total: reward.points, sessionId: session._id }
            });
        }
        // (Ajoute ici d'autres badges facilement)

        await reward.save();

        // Traçabilité : UserAction
        await UserAction.create({
            userId: req.user._id,
            actionType: 'pomodoro_session_completed',
            pointsEarned: 10,
            metadata: {
                sessionDuration: duration,
                subjectId: subjectId || null,
                taskId: taskId || null
            }
        });

        // Message d'encouragement dynamique
        const encouragements = [
            "Bravo, tu gagnes 10 points de discipline !",
            "Super, une session de plus et 10 points pour toi !",
            "Discipline +10 : continue comme ça !",
            "Tu avances, tu gagnes 10 points à chaque session !",
            "Chaque Pomodoro te rapproche de tes objectifs !"
        ];
        const message = encouragements[Math.floor(Math.random() * encouragements.length)];

        res.status(201).json({
            success: true,
            data: session,
            reward: {
                points: reward.points,
                level: reward.level,
                xp: reward.xp,
                sessionsCompleted: reward.stats.sessionsCompleted,
                levelUp,
                badges: newBadges
            },
            message
        });
    } catch (error) {
        console.error('Erreur création session Pomodoro:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// === API Notifications ===
// Récupérer les notifications de l'utilisateur (triées, paginées)
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        const notifications = await Notification.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);
        const total = await Notification.countDocuments({ userId: req.user._id });
        res.json({ success: true, data: notifications, total });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});
// Marquer une notification comme lue
app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        const notif = await Notification.findOneAndUpdate(
            { _id: req.params.id, userId: req.user._id },
            { read: true },
            { new: true }
        );
        if (!notif) return res.status(404).json({ success: false, message: 'Notification non trouvée' });
        res.json({ success: true, data: notif });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});
// Supprimer une notification
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    try {
        const notif = await Notification.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
        if (!notif) return res.status(404).json({ success: false, message: 'Notification non trouvée' });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});
// Supprimer toutes les notifications de l'utilisateur
app.delete('/api/notifications/all', authenticateToken, async (req, res) => {
    try {
        await Notification.deleteMany({ userId: req.user._id });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Route pour exporter les statistiques (traçabilité export PDF)
app.post('/api/stats/export', authenticateToken, async (req, res) => {
    try {
        const userId = req.user._id;
        // Récupérer les stats comme dans /api/stats
        const sessionStats = await PomodoroSession.getSessionStats(userId, 'today');
        const taskStats = await Task.getTaskStats(userId);
        const totalStudyTime = await Subject.getTotalStudyTime(userId);
        // Enregistrer l'action d'export PDF
        await UserAction.create({
            userId,
            actionType: 'export_stats_pdf',
            pointsEarned: 0,
            metadata: { exportedAt: new Date() }
        });
        res.json({
            success: true,
            data: {
                sessions: sessionStats,
                tasks: taskStats,
                totalStudyTime
            }
        });
    } catch (error) {
        console.error('Erreur export stats PDF:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de l\'export PDF'
        });
    }
});

// Route pour servir l'application frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Gestion des erreurs 404
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route non trouvée'
    });
});

// Middleware de gestion d'erreurs global
app.use((error, req, res, next) => {
    console.error('❌ Erreur serveur:', error);
    
    // Si c'est une erreur CORS
    if (error.message && error.message.includes('CORS')) {
        return res.status(403).json({
            success: false,
            message: 'Erreur CORS: Origine non autorisée',
            error: error.message
        });
    }
    
    // Erreur générique
    res.status(500).json({
        success: false,
        message: 'Erreur interne du serveur',
        error: process.env.NODE_ENV === 'development' ? error.message : 'Une erreur est survenue'
    });
});

// Nettoyage automatique des sessions expirées (toutes les heures)
setInterval(async () => {
    try {
        await Session.cleanExpiredSessions();
    } catch (error) {
        console.error('Erreur nettoyage sessions:', error);
    }
}, 60 * 60 * 60 * 1000); // 1 heure

// Démarrage du serveur
app.listen(PORT, () => {
    console.log(`🚀 Serveur ApTe démarré sur le port ${PORT}`);
    console.log(`📱 Application disponible sur: http://localhost:${PORT}`);
    console.log(`🔧 API disponible sur: http://localhost:${PORT}/api`);
    console.log(`🗄️ Base de données: MongoDB`);
});

// Gestion propre de l'arrêt
process.on('SIGINT', async () => {
    console.log('\n🛑 Arrêt du serveur...');
    try {
        await mongoose.connection.close();
        console.log('✅ Connexion MongoDB fermée');
    } catch (error) {
        console.error('Erreur fermeture MongoDB:', error);
    }
    process.exit(0);
});