# 🚀 Guide d'utilisation - ApTe

## Configuration requise

### 1. Serveur Node.js (API Backend)
- **Port :** 3000
- **URL :** http://localhost:3000
- **Rôle :** API REST, authentification, base de données

### 2. Serveur de développement (Frontend)
- **Port :** 5500 (Live Server)
- **URL :** http://127.0.0.1:5500/-PasR-vis-Develop/
- **Rôle :** Fichiers statiques (HTML, CSS, JS)

## 🏃‍♂️ Démarrage rapide

### Étape 1 : Démarrer le serveur Node.js
```bash
cd -PasR-vis-Develop
npm start
```
✅ Le serveur doit afficher : "🚀 Serveur ApTe démarré sur le port 3000"

### Étape 2 : Ouvrir l'application
1. Ouvrez VS Code
2. Clic droit sur `index.html`
3. Sélectionnez "Open with Live Server"
4. L'application s'ouvre sur http://127.0.0.1:5500/-PasR-vis-Develop/

## 🔧 Résolution des problèmes

### Problème : "address already in use :::3000"
```bash
# Trouver le processus qui utilise le port 3000
netstat -ano | findstr :3000

# Tuer le processus (remplacez 5020 par le PID trouvé)
taskkill /PID 5020 /F

# Redémarrer le serveur
npm start
```

### Problème : "404 Not Found" sur les appels API
- ✅ Vérifiez que le serveur Node.js tourne sur le port 3000
- ✅ Vérifiez que l'URL de l'API est correcte : `http://localhost:3000/api`
- ✅ Ouvrez la console du navigateur (F12) pour voir les erreurs

### Problème : Connexion qui ne fonctionne pas
1. Ouvrez http://127.0.0.1:5500/-PasR-vis-Develop/test-connexion.html
2. Testez la connexion directement
3. Regardez les logs pour identifier le problème

## 📁 Structure des fichiers

```
-PasR-vis-Develop/
├── server.js          # Serveur Node.js (port 3000)
├── index.html         # Interface utilisateur
├── app.js            # Logique frontend
├── style.css         # Styles CSS
├── test-connexion.html    # Test de connexion
└── test-modification-matiere.html  # Test des matières
```

## 🔍 Debug

### Logs du serveur Node.js
- Les logs s'affichent dans le terminal où vous avez lancé `npm start`
- Recherchez les erreurs en rouge ❌

### Logs du navigateur
- Appuyez sur F12 pour ouvrir les outils de développement
- Allez dans l'onglet "Console"
- Recherchez les messages avec des emojis (🔐, 🌐, 📡, etc.)

## ✅ Test de fonctionnement

1. **Test de connexion :** http://127.0.0.1:5500/-PasR-vis-Develop/test-connexion.html
2. **Test des matières :** http://127.0.0.1:5500/-PasR-vis-Develop/test-modification-matiere.html
3. **Application principale :** http://127.0.0.1:5500/-PasR-vis-Develop/

## 🆘 En cas de problème

1. Vérifiez que les deux serveurs tournent
2. Regardez les logs dans la console du navigateur
3. Regardez les logs dans le terminal du serveur Node.js
4. Utilisez les fichiers de test pour diagnostiquer 