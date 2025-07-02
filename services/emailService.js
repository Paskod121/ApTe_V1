const nodemailer = require('nodemailer');
require('dotenv').config();

// Vérification des variables d'environnement requises
const requiredEnvVars = ['EMAIL_USER', 'EMAIL_PASSWORD'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('❌ Variables d\'environnement manquantes pour le service d\'email :', missingVars.join(', '));
    console.log('Assurez-vous de configurer ces variables dans votre fichier .env');
}

// Créer un transporteur réutilisable
let transporter;
try {
    transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    // Vérifier la configuration du transporteur
    transporter.verify(function(error, success) {
        if (error) {
            console.error('❌ Erreur de configuration du transporteur email:', error);
        } else {
            console.log('✅ Serveur email configuré avec succès');
        }
    });
} catch (error) {
    console.error('❌ Erreur lors de la création du transporteur email:', error);
}

/**
 * Envoie un email de vérification
 * @param {string} to - Adresse email du destinataire
 * @param {string} username - Nom d'utilisateur
 * @param {string} verificationLink - Lien de vérification
 * @returns {Promise<Object>} Résultat de l'envoi
 */
const sendVerificationEmail = async (to, username, verificationLink) => {
    if (!transporter) {
        console.error('❌ Transporteur email non initialisé');
        throw new Error('Service d\'email non configuré');
    }

    try {
        console.log(`📧 Tentative d'envoi d'email à: ${to}`);
        
        const mailOptions = {
            from: `"ApTe" <${process.env.EMAIL_USER}>`,
            to,
            subject: 'Vérifiez votre adresse email - ApTe',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: #4F46E5; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                        <h1 style="color: white; margin: 0;">Bienvenue sur ApTe !</h1>
                    </div>
                    <div style="padding: 20px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 8px 8px;">
                        <p>Bonjour ${username},</p>
                        <p>Merci de vous être inscrit sur ApTe. Pour commencer, veuillez vérifier votre adresse email en cliquant sur le bouton ci-dessous :</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${verificationLink}" 
                               style="background: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
                                Vérifier mon email
                            </a>
                        </div>
                        <p>Si le bouton ne fonctionne pas, copiez et collez ce lien dans votre navigateur :</p>
                        <p style="word-break: break-all;">${verificationLink}</p>
                        <p>Ce lien expirera dans 24 heures.</p>
                        <p>Cordialement,<br>L'équipe ApTe</p>
                    </div>
                </div>
            `
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('✅ Email envoyé avec succès:', info.messageId);
        return info;
    } catch (error) {
        console.error('❌ Erreur lors de l\'envoi de l\'email:', error);
        throw new Error('Erreur lors de l\'envoi de l\'email de vérification');
    }
};

module.exports = {
    sendVerificationEmail
};
