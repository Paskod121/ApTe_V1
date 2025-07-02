# ApTe Backend - MVP

Backend Node.js pour l'application ApTe, plateforme de motivation pour étudiants.

## 🚀 Fonctionnalités

- **Inscription** avec validation des contraintes d'unicité
- **Connexion** sécurisée avec JWT
- **Vérification d'email** (simulation)
- **Gestion des sessions** utilisateur
- **Base de données SQLite** pour la persistance
- **API REST** complète

## 📋 Prérequis

- Node.js (version 14 ou supérieure)
- npm ou yarn

## 🛠️ Installation

1. **Installer les dépendances**
```bash
npm install
```

2. **Initialiser la base de données**
```bash
npm run init-db
```

3. **Démarrer le serveur**
```bash
# Mode développement (avec auto-reload)
npm run dev

# Mode production
npm start
```

## 🗄️ Structure de la base de données

### Table `users`
- `id` - Identifiant unique
- `username` - Pseudo (unique)
- `email` - Email (unique)
- `password_hash` - Mot de passe hashé
- `motivation` - Lettre de motivation
- `date_creation` - Date d'inscription
- `niveau` - Niveau utilisateur
- `temps_etude_total` - Temps d'étude total
- `email_verifie` - Statut vérification email
- `token_verification` - Token de vérification

### Contraintes d'unicité
- ❌ **Même pseudo** : Impossible
- ❌ **Même email** : Impossible
- ❌ **Même pseudo + même email** : Impossible

## 🔌 API Endpoints

### Inscription
```http
POST /api/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "motdepasse123",
  "motivation": "Je veux réussir mes examens !"
}
```

**Réponse succès (201) :**
```json
{
  "success": true,
  "message": "Inscription réussie ! Vérifiez votre email.",
  "data": {
    "userId": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "verificationLink": "http://localhost:3000/verify-email?token=..."
  }
}
```

### Connexion
```http
POST /api/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "motdepasse123"
}
```

**Réponse succès (200) :**
```json
{
  "success": true,
  "message": "Connexion réussie !",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "username": "john_doe",
      "email": "john@example.com",
      "motivation": "Je veux réussir mes examens !",
      "niveau": 1,
      "tempsEtudeTotal": 0
    }
  }
}
```

### Vérification d'email
```http
GET /api/verify-email?token=abc123&email=john@example.com
```

### Déconnexion
```http
POST /api/logout
Authorization: Bearer <token>
```

### Profil utilisateur (protégé)
```http
GET /api/profile
Authorization: Bearer <token>
```

## 🔒 Sécurité

- **Mots de passe** hashés avec bcrypt (12 rounds)
- **JWT** pour l'authentification
- **Validation** des données d'entrée
- **Contraintes d'unicité** en base de données
- **Sessions** gérées côté serveur

## 🧪 Tests

### Test d'inscription
```bash
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "motivation": "Test motivation"
  }'
```

### Test de connexion
```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

## 📁 Structure du projet

```
-PasR-vis/
├── server.js              # Serveur principal
├── init-database.js       # Script d'initialisation DB
├── package.json           # Dépendances
├── config.env            # Configuration
├── apte.db              # Base de données SQLite
├── index.html           # Frontend
├── app.js               # Frontend JS
├── style.css            # Frontend CSS
└── README.md            # Documentation
```

## 🚀 Déploiement

1. **Variables d'environnement**
   - Copier `config.env` vers `.env`
   - Modifier `JWT_SECRET` pour la production

2. **Base de données**
   - Exécuter `npm run init-db`
   - Vérifier les permissions du fichier `apte.db`

3. **Serveur**
   - `npm start` pour la production
   - Utiliser PM2 ou similaire pour la persistance

## 🔧 Configuration

Modifier `config.env` pour :
- Changer le port du serveur
- Définir un JWT_SECRET sécurisé
- Configurer l'environnement (dev/prod)

## 📝 Logs

Le serveur affiche :
- ✅ Connexions réussies
- ❌ Erreurs de validation
- 📧 Liens de vérification (dev)
- 🔐 Sessions créées/supprimées

## 🐛 Debug

En cas de problème :
1. Vérifier les logs du serveur
2. Contrôler la base de données : `sqlite3 apte.db`
3. Tester les endpoints avec curl/Postman
4. Vérifier les contraintes d'unicité

## 📞 Support

Pour toute question ou problème :
- Vérifier les logs du serveur
- Contrôler la documentation des endpoints
- Tester avec les exemples curl fournis 

<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Vérification de l'email - ApTe</title>
  <link rel="stylesheet" href="/style.css">
  <style>
    body { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: var(--gray-100);}
    .verification-container { background: #fff; border-radius: 16px; box-shadow: var(--shadow-lg); padding: 2rem 3rem; text-align: center; }
    .success { color: var(--success); font-size: 2rem; }
    .error { color: var(--danger); font-size: 2rem; }
    .btn-main { margin-top: 2rem; }
  </style>
</head>
<body>
  <div class="verification-container">
    <div class="logo-pro" style="margin-bottom:1rem;"><span class="emoji">⚡</span> <span>ApTe</span></div>
    <div id="message-block">
      <!-- Message de succès ou d'erreur ici -->
    </div>
    <a href="/" class="btn btn-main">Retour à la connexion</a>
  </div>
</body>
</html> 