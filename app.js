// Configuration de l'API
const API_BASE_URL = 'http://localhost:3000/api';

// Fonction pour les appels API avec gestion d'erreur améliorée
async function apiCall(endpoint, options = {}) {
    try {
        console.log('🌐 Appel API:', `${API_BASE_URL}${endpoint}`, options);
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        console.log('📡 Réponse API brute:', response.status, response.statusText);
        const data = await response.json();
        console.log('📡 Données API:', data);
        
        if (!response.ok) {
            // Déconnexion automatique si token invalide
            if (data.message && (data.message.includes('Token invalide') || data.message.includes('Token d\'authentification requis'))) {
                removeAuthToken();
                EtatApp.mettreAJour('utilisateur', null);
                afficherAuth();
                showFeedback('Session expirée, veuillez vous reconnecter.', 'error', 5000);
            }
            throw new Error(data.message || `Erreur ${response.status}: ${response.statusText}`);
        }

        return data;
    } catch (error) {
        console.error('❌ Erreur API:', error);
        throw error;
    }
}

// Fonction pour obtenir le token depuis le localStorage
function getAuthToken() {
    return localStorage.getItem('apte_token');
}

// Fonction pour sauvegarder le token
function saveAuthToken(token) {
    localStorage.setItem('apte_token', token);
}

// Fonction pour supprimer le token
function removeAuthToken() {
    localStorage.removeItem('apte_token');
}

// État global de l'application
const EtatApp = {
    utilisateur: null,
    sessionEnCours: null,
    matieres: [],
    taches: [],
    historiquePomo: [],
    parametres: {
        dureePomo: 25,
        pauseCourte: 5,
        pauseLongue: 15,
        notifications: true
    },
    
    // Méthodes réactives
    abonnes: [],
    
    sAbonner(callback) {
        this.abonnes.push(callback);
    },
    
    mettreAJour(cle, valeur) {
        this[cle] = valeur;
        this.notifier();
        this.persister();
    },
    
    notifier() {
        this.abonnes.forEach(callback => callback());
    },
    
    persister() {
        const donnees = {
            matieres: this.matieres,
            taches: this.taches,
            historiquePomo: this.historiquePomo,
            parametres: this.parametres,
            derniereMAJ: Date.now()
        };
        localStorage.setItem('studyBoostData', JSON.stringify(donnees));
    },
    
    charger() {
        const donnees = localStorage.getItem('studyBoostData');
        if (donnees) {
            try {
                const parsed = JSON.parse(donnees);
                this.matieres = parsed.matieres || [];
                this.taches = parsed.taches || [];
                this.historiquePomo = parsed.historiquePomo || [];
                this.parametres = { ...this.parametres, ...parsed.parametres };
                return true;
            } catch (e) {
                console.error('Erreur lors du chargement des données:', e);
            }
        }
        return false;
    },

    // Nouvelle méthode pour charger l'utilisateur depuis l'API
    async chargerUtilisateur() {
        const token = getAuthToken();
        if (!token) return false;

        try {
            const response = await apiCall('/profile', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.success) {
                this.utilisateur = response.data;
                return true;
            }
        } catch (error) {
            console.error('Erreur chargement utilisateur:', error);
            // Si le token est invalide, on le supprime
            removeAuthToken();
        }
        return false;
    }
};

// Système de feedback utilisateur
function showFeedback(message, type = 'success', duration = 3000) {
    const container = document.getElementById('feedback-container');
    if (!container) return;
    
    const feedback = document.createElement('div');
    feedback.className = `feedback-message feedback-${type}`;
    feedback.textContent = message;
    
    container.appendChild(feedback);
    
    // Animation d'entrée
    setTimeout(() => feedback.classList.add('show'), 100);
    
    // Animation de sortie
    setTimeout(() => {
        feedback.classList.remove('show');
        setTimeout(() => {
            if (container.contains(feedback)) {
                container.removeChild(feedback);
            }
        }, 300);
    }, duration);
}

// Fonction pour faire défiler vers le formulaire d'auth avec animation
function scrollToAuth() {
    const authForm = document.getElementById('auth-form');
    if (authForm) {
        authForm.scrollIntoView({ behavior: 'smooth' });
        
        // Ajouter une animation de pulse au formulaire
        authForm.classList.add('animate-pulse');
        setTimeout(() => authForm.classList.remove('animate-pulse'), 1000);
    }
}

// Fonction pour gérer l'auth Google avec feedback
function handleGoogleAuth() {
    // Déterminer le mode (inscription ou connexion)
    const mode = modeInscription ? 'signup' : 'login';
    const authUrl = `http://localhost:3000/auth/google?mode=${mode}`;
    window.location.href = authUrl;
}

// Fonction pour renvoyer l'email avec feedback
function renvoyerEmail() {
    showFeedback('Email de vérification renvoyé !', 'success');
}

// Gestion de l'authentification
let modeInscription = false;

// === Initialisation ===
function showLoader(show = true) {
    const loader = document.getElementById('loader');
    if (loader) loader.style.display = show ? 'flex' : 'none';
}

document.addEventListener('DOMContentLoaded', async function() {
    showLoader(true);
    EtatApp.charger();

    // --- Navigation sidebar dynamique améliorée ---
    const navMap = {
        'nav-home': ['dashboard-home-section', 'dashboard-stats-section', 'dashboard-matieres-section', 'dashboard-taches-section', 'dashboard-leaderboard-section', 'dashboard-rewards-section'],
        'nav-pomodoro': [], // À compléter si tu veux une vue Pomodoro plein écran
        'nav-matieres': ['dashboard-matieres-section'],
        'nav-taches': ['dashboard-taches-section'],
        'nav-stats': ['dashboard-stats-section'],
        'nav-leaderboard': ['dashboard-leaderboard-section'],
        'nav-rewards': ['dashboard-rewards-section']
    };
    const allSections = [
        'dashboard-home-section',
        'dashboard-stats-section',
        'dashboard-matieres-section',
        'dashboard-taches-section',
        'dashboard-leaderboard-section',
        'dashboard-rewards-section'
    ];
    // Ajout aria-label sur les boutons sidebar
    document.querySelectorAll('.sidebar-minimal nav a').forEach(a => {
        if (!a.hasAttribute('aria-label')) {
            a.setAttribute('aria-label', a.title || a.textContent);
        }
    });
    Object.keys(navMap).forEach(navId => {
        const btn = document.getElementById(navId);
        if (btn) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                // Gère l'état actif
                document.querySelectorAll('.sidebar-minimal nav a').forEach(a => a.classList.remove('active'));
                btn.classList.add('active');
                // Affiche/masque les sections avec animation
                allSections.forEach(secId => {
                    const el = document.getElementById(secId);
                    if (el) {
                        el.classList.add('dashboard-section-hidden');
                        el.classList.remove('dashboard-section-full', 'dashboard-section-fadein');
                    }
                });
                if (navId === 'nav-home') {
                    allSections.forEach(secId => {
                        const el = document.getElementById(secId);
                        if (el) {
                            el.classList.remove('dashboard-section-hidden', 'dashboard-section-full');
                            el.classList.add('dashboard-section-fadein');
                        }
                    });
                } else {
                    navMap[navId].forEach(secId => {
                        const el = document.getElementById(secId);
                        if (el) {
                            el.classList.remove('dashboard-section-hidden');
                            el.classList.add('dashboard-section-full', 'dashboard-section-fadein');
                        }
                    });
                }
                btn.focus();
            });
            // Accessibilité : navigation clavier
            btn.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    btn.click();
                }
            });
        }
    });

    const token = getAuthToken();
    if (token) {
        try {
            const response = await apiCall('/profile', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (response.success) {
                EtatApp.utilisateur = response.data;
                afficherDashboard();
                showLoader(false);
                return;
            }
        } catch (e) {
            removeAuthToken();
        }
    }
    showLoader(false);
    afficherAuth();
    
    // Vérifier s'il y a des paramètres de vérification d'email dans l'URL
    const urlParams = new URLSearchParams(window.location.search);
    const verifyToken = urlParams.get('verify');
    const verifyEmail = urlParams.get('email');
    
    if (verifyToken && verifyEmail) {
        // Tenter de vérifier l'email
        if (await verifierEmail(verifyToken, verifyEmail)) {
            // Nettoyer l'URL
            window.history.replaceState({}, document.title, window.location.pathname);
            showFeedback('Email vérifié avec succès ! Bienvenue !', 'success');
        } else {
            showFeedback('Erreur lors de la vérification de l\'email.', 'error');
        }
    }
    
    // Gestionnaire pour le toggle de thème
    const toggleThemeBtn = document.getElementById('toggle-theme-pro');
    if (toggleThemeBtn) {
        toggleThemeBtn.addEventListener('click', toggleTheme);
    }
    
    // Initialiser le thème
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);
    
    // Attacher les gestionnaires d'événements de manière sécurisée
    attachEventHandlers();

    // Gestion de la redirection après Google OAuth
    (function handleGoogleOAuthRedirect() {
        const urlParams = new URLSearchParams(window.location.search);
        const googleToken = urlParams.get('google_token');
        const mode = urlParams.get('mode');
        const isNew = urlParams.get('new');
        const isExisting = urlParams.get('existing');
        if (googleToken) {
            saveAuthToken(googleToken);
            // Nettoyer l'URL
            window.history.replaceState({}, document.title, window.location.pathname);
            // Charger l'utilisateur et afficher le dashboard
            EtatApp.chargerUtilisateur().then((ok) => {
                if (ok) afficherDashboard();
            });
            // Feedback selon le cas
            if (isNew === '1') {
                showFeedback('Bienvenue, votre compte Google a été créé !', 'success', 5000);
                console.log('[Google OAuth] Nouveau compte créé via Google.');
            } else if (isExisting === '1') {
                showFeedback('Connexion réussie avec Google.', 'success', 4000);
                console.log('[Google OAuth] Connexion avec un compte Google existant.');
            } else {
                showFeedback('Connexion via Google.', 'info', 3000);
                console.log('[Google OAuth] Connexion via Google (cas générique).');
            }
        }
    })();

    if (document.getElementById('subjects-container')) {
        chargerMatieresDepuisAPI();
    }
    
    if (document.getElementById('tasks-container')) {
        chargerTachesDepuisAPI();
    }
    // Edition et suppression depuis la liste - Déjà déclarées globalement plus haut
    // window.editerMatiere = function(id) { ... };
    // window.supprimerMatiere = async function(id) { ... };
});

// Fonction pour attacher les gestionnaires d'événements de manière sécurisée
function attachEventHandlers() {
    // Gestionnaire pour le toggle auth (inscription/connexion)
    const authToggle = document.getElementById('auth-toggle');
    if (authToggle) {
        authToggle.onclick = function() {
            modeInscription = !modeInscription;
            const titre = document.getElementById('auth-title');
            const submitText = document.getElementById('auth-submit-text');
            const usernameGroup = document.getElementById('username-group');
            const motivationGroup = document.getElementById('motivation-group');
            const confirmPasswordGroup = document.getElementById('confirm-password-group');
            const toggleBtn = document.getElementById('auth-toggle');
            const confirmPasswordInput = document.getElementById('confirm-password');
            
            // Animation de transition
            const formCard = document.querySelector('.form-card');
            if (formCard) {
                formCard.classList.add('animate-shake');
                setTimeout(() => formCard.classList.remove('animate-shake'), 500);
            }
            
            if (modeInscription) {
                titre.textContent = 'Inscription';
                submitText.textContent = "S'inscrire";
                usernameGroup.style.display = 'block';
                motivationGroup.style.display = 'block';
                confirmPasswordGroup.style.display = 'block';
                toggleBtn.innerHTML = "Déjà un compte ? <span>Se connecter</span>";
                showFeedback('Mode inscription activé !', 'info', 2000);
                if (confirmPasswordInput) confirmPasswordInput.setAttribute('required', 'required');
            } else {
                titre.textContent = 'Connexion';
                submitText.textContent = 'Se connecter';
                usernameGroup.style.display = 'none';
                motivationGroup.style.display = 'none';
                confirmPasswordGroup.style.display = 'none';
                toggleBtn.innerHTML = "Pas encore de compte ? <span>S'inscrire</span>";
                showFeedback('Mode connexion activé !', 'info', 2000);
                if (confirmPasswordInput) confirmPasswordInput.removeAttribute('required');
            }
            toggleBtn.classList.add('toggle-signup');
        };
    }
    
    // Gestionnaire pour le formulaire d'authentification
    const authForm = document.getElementById('auth-form');
    if (authForm) {
        authForm.onsubmit = function(e) {
            e.preventDefault();
            console.log('[TEST] Submit du formulaire de connexion détecté');
            showFeedback('Test : le submit du formulaire fonctionne !', 'info', 2000);
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const username = document.getElementById('username').value;
            const motivation = document.getElementById('motivation').value;
            
            // Ajouter l'état de chargement au bouton
            const submitBtn = document.getElementById('auth-submit');
            const originalText = submitBtn.innerHTML;
            submitBtn.classList.add('btn-loading');
            submitBtn.disabled = true;
            
            if (modeInscription) {
                if (username.length < 2 || username.length > 8) {
                    showFeedback("Le pseudo doit contenir entre 2 et 8 caractères.", 'error');
                    resetSubmitButton(submitBtn, originalText);
                    return;
                }
                if (password !== confirmPassword) {
                    showFeedback("Les mots de passe ne correspondent pas.", 'error');
                    resetSubmitButton(submitBtn, originalText);
                    return;
                }
                if (password.length < 6) {
                    showFeedback("Le mot de passe doit contenir au moins 6 caractères.", 'error');
                    resetSubmitButton(submitBtn, originalText);
                    return;
                }
                
                // Appel à la fonction d'inscription réelle
                inscrireUtilisateur(email, password, username, motivation)
                    .then(success => {
                        if (!success) {
                            resetSubmitButton(submitBtn, originalText);
                        }
                    });
            } else {
                // Mode connexion
                console.log('🔐 Mode connexion - appel de seConnecter avec email et password uniquement');
                (async () => {
                    const success = await seConnecter(email, password);
                    if (success) {
                        showFeedback('Connexion réussie ! Bienvenue !', 'success');
                    } else {
                        showFeedback('Email ou mot de passe incorrect.', 'error');
                    }
                    resetSubmitButton(submitBtn, originalText);
                })();
            }
        };
    }
    
    // Gestionnaire pour le compteur de caractères de motivation
    const motivationInput = document.getElementById('motivation');
    const motivationCharCount = document.getElementById('motivation-char-count');
    if (motivationInput && motivationCharCount) {
        motivationInput.addEventListener('input', function() {
            const max = 150;
            const len = motivationInput.value.length;
            motivationCharCount.textContent = `${max - len} caractères restants`;
            
            // Ajouter des classes pour le feedback visuel
            motivationCharCount.classList.remove('warning', 'danger');
            if (len > max * 0.8) {
                motivationCharCount.classList.add('warning');
            }
            if (len > max * 0.95) {
                motivationCharCount.classList.add('danger');
            }
            
            if (len > max) {
                motivationInput.value = motivationInput.value.slice(0, max);
            }
        });
    }
    
    // Gestionnaire pour le thème
    const themeBtn = document.getElementById('toggle-theme');
    if (themeBtn) {
        themeBtn.onclick = toggleTheme;
    }
}

function resetSubmitButton(button, originalText) {
    button.classList.remove('btn-loading');
    button.disabled = false;
    button.innerHTML = originalText;
}

function seConnecter(email, motDePasse, nomUtilisateur = null, motivation = null) {
    console.log('🚀 Fonction seConnecter appelée avec:', { email, nomUtilisateur, motivation });
    // Si on a un nomUtilisateur et motivation, c'est une inscription
    if (nomUtilisateur && motivation) {
        console.log('📝 Mode inscription détecté');
        return inscrireUtilisateur(email, motDePasse, nomUtilisateur, motivation);
    }
    
    // Sinon c'est une connexion
    console.log('🔐 Mode connexion détecté');
    return connecterUtilisateur(email, motDePasse);
}

// Nouvelle fonction pour l'inscription via API
async function inscrireUtilisateur(email, motDePasse, nomUtilisateur, motivation) {
    try {
        const response = await apiCall('/register', {
            method: 'POST',
            body: JSON.stringify({
                username: nomUtilisateur,
                email: email,
                password: motDePasse,
                motivation: motivation
            })
        });

        // Log détaillé pour debug
        console.log('Réponse inscription:', response);

        if (response.success) {
            // Sauvegarder le token (toujours écraser l'ancien)
            if (response.data && response.data.token) {
                saveAuthToken(response.data.token);
                await EtatApp.chargerUtilisateur();
            }
            showFeedback('Inscription réussie ! Vérification en cours...', 'success');
            afficherPageVerification(email, nomUtilisateur, motivation, response.data.verificationToken);
            return true;
        }
    } catch (error) {
        showFeedback(error.message || 'Erreur lors de l\'inscription', 'error');
        return false;
    }
}

// Nouvelle fonction pour la connexion via API
async function connecterUtilisateur(email, motDePasse) {
    console.log('🔐 Tentative de connexion pour:', email);
    try {
        const response = await apiCall('/login', {
            method: 'POST',
            body: JSON.stringify({
                email: email,
                password: motDePasse
            })
        });

        console.log('✅ Réponse connexion:', response);

        if (response.success) {
            // Log du token reçu
            if (response.data && response.data.token) {
                console.log('🎫 Token reçu:', response.data.token);
                // Décodage du JWT (partie payload)
                try {
                    const payload = JSON.parse(atob(response.data.token.split('.')[1]));
                    console.log('🔍 Payload JWT:', payload);
                } catch (e) {
                    console.warn('Impossible de décoder le JWT:', e);
                }
            }
            // Sauvegarder le token (toujours écraser l'ancien)
            saveAuthToken(response.data.token);
            // Recharger l'utilisateur depuis l'API
            const ok = await EtatApp.chargerUtilisateur();
            console.log('👤 Utilisateur chargé après login:', EtatApp.utilisateur);
            if (ok) {
                showFeedback('Connexion réussie ! Bienvenue !', 'success');
                afficherDashboard();
                // Mettre à jour le dashboard pro avec le nouvel utilisateur
                mettreAJourDashboardPro(EtatApp.utilisateur);
            } else {
                showFeedback('Erreur lors du chargement du profil utilisateur.', 'error');
                afficherAuth();
            }
            return true;
        } else {
            console.error('❌ Connexion échouée:', response.message);
            showFeedback(response.message || 'Erreur de connexion', 'error');
            return false;
        }
    } catch (error) {
        console.error('❌ Erreur lors de la connexion:', error);
        showFeedback(error.message || 'Email ou mot de passe incorrect', 'error');
        return false;
    }
}

function seDeconnecter() {
    // Appeler l'API de déconnexion
    const token = getAuthToken();
    if (token) {
        apiCall('/logout', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        }).catch(error => {
            console.error('Erreur déconnexion API:', error);
        });
    }
    // Nettoyer le local storage et l'état utilisateur
    removeAuthToken();
    EtatApp.mettreAJour('utilisateur', null);
    arreterTimer();
    // Masquer tous les écrans
    if (document.getElementById('dashboard-pro')) {
        document.getElementById('dashboard-pro').style.display = 'none';
    }
    document.getElementById('split-landing').style.display = 'flex';
    document.getElementById('split-verification').style.display = 'none';
    showFeedback('Déconnexion réussie !', 'info');
}

function afficherAuth() {
    document.getElementById('split-landing').style.display = 'flex';
    document.getElementById('split-verification').style.display = 'none';
    // Si dashboard existe, le masquer
    if (document.getElementById('dashboard-pro')) {
        document.getElementById('dashboard-pro').style.display = 'none';
    }
}

function afficherDashboard() {
    document.getElementById('split-landing').style.display = 'none';
    document.getElementById('split-verification').style.display = 'none';
    if (document.getElementById('dashboard-pro')) {
        document.getElementById('dashboard-pro').style.display = 'flex';
    }
    // Toujours mettre à jour le dashboard pro avec l'utilisateur courant
    mettreAJourDashboardPro(EtatApp.utilisateur);

    // Charger la liste des matières à chaque affichage du dashboard
    chargerMatieresDepuisAPI();
    
    // Charger la liste des tâches à chaque affichage du dashboard
    chargerTachesDepuisAPI();

    // Mettre à jour les stats (au cas où les matières sont déjà en mémoire)
    mettreAJourStatsDashboard();
    
    // Démarrer la mise à jour automatique du prochain examen
    demarrerMiseAJourProchainExamen();

    // Attacher l'événement du bouton "Ajouter matière" APRÈS que le dashboard soit affiché
    setTimeout(() => {
        const openSubjectModalBtn = document.getElementById('open-subject-modal');
        console.log('🔍 Recherche du bouton open-subject-modal:', openSubjectModalBtn);
        if (openSubjectModalBtn) {
            openSubjectModalBtn.onclick = () => {
                console.log('🎯 Bouton "Ajouter matière" cliqué !');
                openSubjectModal();
            };
            console.log('✅ Événement onclick attaché au bouton "Ajouter matière"');
        } else {
            console.error('❌ Bouton open-subject-modal non trouvé !');
        }
        
        // Attacher les événements de la modal
        const cancelBtn = document.getElementById('subject-cancel');
        if (cancelBtn) {
            cancelBtn.onclick = () => {
                console.log('🚪 Bouton Annuler cliqué');
                closeSubjectModal();
            };
            console.log('✅ Événement onclick attaché au bouton Annuler');
        }
        
        const modalBg = document.getElementById('subject-modal');
        if (modalBg) {
            modalBg.onclick = function(e) {
                if (e.target === modalBg) {
                    console.log('🚪 Clic sur le fond de la modal');
                    closeSubjectModal();
                }
            };
            console.log('✅ Événement onclick attaché au fond de la modal');
        }
        
        // Attacher l'événement du formulaire
        setupSubjectForm();
        
        // Attacher les événements de la modal des tâches
        const taskCancelBtn = document.getElementById('task-cancel');
        if (taskCancelBtn) {
            taskCancelBtn.onclick = () => {
                console.log('🚪 Bouton Annuler tâche cliqué');
                closeTaskModal();
            };
            console.log('✅ Événement onclick attaché au bouton Annuler tâche');
        }
        
        const taskModalBg = document.getElementById('task-modal');
        if (taskModalBg) {
            taskModalBg.onclick = function(e) {
                if (e.target === taskModalBg) {
                    console.log('🚪 Clic sur le fond de la modal tâche');
                    closeTaskModal();
                }
            };
            console.log('✅ Événement onclick attaché au fond de la modal tâche');
        }
        
        // Attacher l'événement d'upload d'avatar
        console.log('🔧 Configuration de l\'upload d\'avatar...');
        setupAvatarUpload();
        console.log('✅ Upload d\'avatar configuré');
        
    }, 100);
}

// Met à jour dynamiquement le dashboard pro (nom, avatar, motivation)
function mettreAJourDashboardPro(utilisateur) {
    if (!utilisateur) return;
    const userNameEl = document.getElementById('user-name-pro');
    if (userNameEl) {
        userNameEl.textContent = utilisateur.prenom || utilisateur.username || 'Étudiant';
    }
    document.querySelectorAll('.avatar-pro, .avatar-header, .avatar-mini').forEach(el => {
        // Sauvegarder le bouton d'upload s'il existe
        const uploadBtn = el.querySelector('.avatar-edit-btn');
        const uploadInput = el.querySelector('#avatar-input');
        
        if (utilisateur.avatar) {
            el.innerHTML = `<img src="${utilisateur.avatar}" alt="Avatar" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`;
        } else {
            el.textContent = (utilisateur.prenom || utilisateur.username || 'AT').slice(0,2).toUpperCase();
        }
        
        // Restaurer le bouton d'upload s'il existait
        if (uploadBtn) {
            el.appendChild(uploadBtn);
        }
        if (uploadInput) {
            el.appendChild(uploadInput);
        }
    });
    if (utilisateur.motivation) {
        const motivationEl = document.getElementById('motivation-pro');
        if (motivationEl) motivationEl.textContent = utilisateur.motivation;
    }
}

function afficherMessageMotivationAccueil() {
    const el = document.getElementById('motivation-text-home');
    if (el) {
        el.textContent = messagesMotivation[Math.floor(Math.random() * messagesMotivation.length)];
    }
}

function calculerTempsEtudeDuJour() {
    // Additionne les sessions pomodoro du jour pour l'utilisateur
    const historique = EtatApp.historiquePomo || [];
    const now = new Date();
    let totalMinutes = 0;
    historique.forEach(session => {
        const sessionDate = new Date(session.date);
        if (
            sessionDate.getFullYear() === now.getFullYear() &&
            sessionDate.getMonth() === now.getMonth() &&
            sessionDate.getDate() === now.getDate()
        ) {
            totalMinutes += session.duration || 0;
        }
    });
    const heures = Math.floor(totalMinutes / 60);
    const minutes = totalMinutes % 60;
    return `${heures}h ${minutes}m`;
}

function calculerProgressionGlobale() {
    // Progression basée sur les points utilisateur (exemple : 1000 points = 100%)
    const utilisateur = EtatApp.utilisateur;
    if (!utilisateur || !utilisateur.reward || typeof utilisateur.reward.points !== 'number') return '0%';
    const points = utilisateur.reward.points;
    const maxPoints = 1000; // À ajuster selon ta logique de progression
    const percent = Math.min(100, Math.round((points / maxPoints) * 100));
    return `${percent}%`;
}

function prochainExamen() {
    const now = new Date();
    const matieres = EtatApp.matieres || [];
    const prochaines = matieres
        .filter(m => m.examDate)
        .map(m => ({
            date: new Date(m.examDate),
            name: m.name,
            color: m.color
        }))
        .filter(d => d.date > now)
        .sort((a, b) => a.date - b.date);
    if (!prochaines.length) return '--';
    const prochain = prochaines[0];
    const nomCourt = prochain.name.slice(0, 6);
    
    // Calculer le temps restant
    const tempsRestant = prochain.date - now;
    const joursRestants = Math.floor(tempsRestant / (1000 * 60 * 60 * 24));
    const heuresRestantes = Math.floor((tempsRestant % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    
    // Déterminer la couleur du point selon l'urgence
    let pointColor = '#10B981'; // Vert par défaut
    if (joursRestants === 0 && heuresRestantes < 2) {
        pointColor = '#EF4444'; // Rouge (très urgent)
    } else if (joursRestants === 0 && heuresRestantes < 24) {
        pointColor = '#F59E0B'; // Orange (urgent)
    } else if (joursRestants < 7) {
        pointColor = '#F59E0B'; // Orange (proche)
    }
    
    return `<span style="color: ${prochain.color};">${nomCourt}</span> <span class="blink-dot" style="color: ${pointColor};">●</span> ${prochain.date.toLocaleDateString()} ${prochain.date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
}

function demarrerPomodoroAccueil() {
    // Appel à la fonction moderne du Pomodoro immersif
    openPomodoroModal();
}

function closePomodoroSection() {
    document.body.classList.remove('pomodoro-active');
    document.getElementById('pomodoro-modal').style.display = 'none';
    document.getElementById('dashboard-pro').style.display = 'block';
    document.getElementById('pomodoro-modal').classList.remove('pomodoro-fullscreen');
    clearInterval(pomodoroTimer);
}

// Gestion du timer Pomodoro
let timer = null;
let tempsRestant = 25 * 60; // 25 minutes en secondes
let enCours = false;

function toggleTimer() {
    if (enCours) {
        arreterTimer();
    } else {
        demarrerTimer();
    }
}

function demarrerTimer() {
    enCours = true;
    const timerBtn = document.getElementById('timer-btn');
    if (timerBtn) {
        timerBtn.textContent = '⏸️ Pause';
    }
    
    timer = setInterval(() => {
        if (tempsRestant > 0) {
            tempsRestant--;
            afficherTemps();
        } else {
            arreterTimer();
            enregistrerSessionPomodoro();
            afficherMessageMotivation('Bravo ! Session terminée 🎉');
        }
    }, 1000);
}

function arreterTimer() {
    enCours = false;
    clearInterval(timer);
    const timerBtn = document.getElementById('timer-btn');
    if (timerBtn) {
        timerBtn.textContent = '▶️ Commencer';
    }
}

function afficherTemps() {
    const min = Math.floor(tempsRestant / 60).toString().padStart(2, '0');
    const sec = (tempsRestant % 60).toString().padStart(2, '0');
    const timeDisplay = document.getElementById('time-display');
    if (timeDisplay) {
        timeDisplay.textContent = `${min}:${sec}`;
    }
}

async function enregistrerSessionPomodoro() {
    const token = getAuthToken();
    const duration = EtatApp.parametres.dureePomo;
    try {
        const response = await fetch(`${API_BASE_URL}/pomodoro-sessions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                duration,
                sessionType: 'focus'
                // subjectId: ... (si tu veux lier à une matière)
                // taskId: ... (si tu veux lier à une tâche)
            })
        });
        const data = await response.json();
        if (data.success) {
            showFeedback('Session Pomodoro enregistrée !', 'success');
            // Synchronisation avec la base de données
            await chargerStatsUtilisateur();
        } else {
            showFeedback(data.message || 'Erreur lors de l\'enregistrement', 'error');
        }
    } catch (e) {
        showFeedback('Erreur réseau lors de l\'enregistrement', 'error');
    }
}

// ... existing code ...

// === Gestion des tâches ===
async function ajouterTache() {
    // Ouvrir la modal d'ajout de tâche
    openTaskModal();
}

async function chargerTachesDepuisAPI() {
    try {
        const token = getAuthToken();
        const response = await fetch(`${API_BASE_URL}/tasks`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            EtatApp.taches = data.data;
            afficherTaches();
            mettreAJourStatsDashboard();
        } else {
            showFeedback(data.message || 'Erreur chargement tâches', 'error');
        }
    } catch (e) {
        console.error('Erreur chargement tâches:', e);
        showFeedback('Erreur réseau chargement tâches', 'error');
    }
}

// --- Recherche par mot-clé sur les tâches ---
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('task-search');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            filtrerTaches();
        });
    }
    
    // Gestion des filtres avancés
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            // Retirer la classe active de tous les boutons
            filterButtons.forEach(b => b.classList.remove('active'));
            // Ajouter la classe active au bouton cliqué
            this.classList.add('active');
            // Appliquer le filtre
            filtrerTaches();
        });
    });
});

// Fonction de filtrage combiné (recherche + filtres)
function filtrerTaches() {
    const keyword = document.getElementById('task-search')?.value.trim().toLowerCase() || '';
    const activeFilter = document.querySelector('.filter-btn.active')?.dataset.filter || 'all';
    
    let filtered = EtatApp.taches || [];
    
    // Filtrage par mot-clé
    if (keyword) {
        filtered = filtered.filter(t =>
            (t.title && t.title.toLowerCase().includes(keyword)) ||
            (t.description && t.description.toLowerCase().includes(keyword))
        );
    }
    
    // Filtrage par type
    switch (activeFilter) {
        case 'high-priority':
            filtered = filtered.filter(t => t.priority >= 4);
            break;
        case 'overdue':
            filtered = filtered.filter(t => 
                t.dueDate && !t.completed && new Date() > new Date(t.dueDate)
            );
            break;
        case 'completed':
            filtered = filtered.filter(t => t.completed);
            break;
        case 'all':
        default:
            // Pas de filtre supplémentaire
            break;
    }
    
    afficherTaches(filtered);
}

// Modification de afficherTaches pour accepter un tableau filtré
function afficherTaches(tachesFiltrees) {
    const container = document.getElementById('tasks-container');
    if (!container) return;
    container.innerHTML = '';
    const taches = tachesFiltrees || EtatApp.taches;
    if (!taches || !taches.length) {
        container.innerHTML = '';
        return;
    }
    taches.forEach(tache => {
        const div = document.createElement('div');
        div.className = 'task-item' + (tache.completed ? ' completed' : '');
        
        // Calculer si la tâche est en retard
        const isOverdue = tache.dueDate && !tache.completed && new Date() > new Date(tache.dueDate);
        
        // Couleur de priorité
        const priorityColors = {
            1: '#10B981', // Vert (basse)
            2: '#3B82F6', // Bleu
            3: '#F59E0B', // Orange
            4: '#EF4444', // Rouge
            5: '#8B5CF6'  // Violet (très haute)
        };
        
        const priorityColor = priorityColors[tache.priority] || '#6B7280';
        
        div.innerHTML = `
            <div class="task-header">
                <input type="checkbox" class="task-checkbox" ${tache.completed ? 'checked' : ''} onchange="toggleTache('${tache._id}')">
                <div class="task-priority" style="background-color: ${priorityColor}"></div>
                <div class="task-content">
                    <div class="task-header-top" style="display:flex;align-items:center;gap:0.7em;">
                        ${tache.subjectId ? `<span class=\"task-subject\" style=\"color: ${tache.subjectId.color}\">${tache.subjectId.name}</span>` : ''}
                        <div class="task-title info-glow ${tache.completed ? 'completed' : ''}">${tache.title}</div>
                    </div>
                    <div class="task-meta">
                        ${tache.dueDate ? `<span class=\"task-due-date ${isOverdue ? 'overdue' : ''}\">Échéance: ${new Date(tache.dueDate).toLocaleDateString()}</span>` : ''}
                        ${tache.estimatedTime ? `<span class=\"task-time\">⏱️ ${tache.estimatedTime}min</span>` : ''}
                    </div>
                </div>
                <div class="task-actions">
                    <button class="task-edit-btn" title="Éditer" onclick="editerTache('${tache._id}')">✏️</button>
                    <button class="task-delete-btn" title="Supprimer" onclick="supprimerTache('${tache._id}')">🗑️</button>
                </div>
            </div>
            ${tache.description ? `<div class=\"task-description\">${tache.description}</div>` : ''}
        `;
        container.appendChild(div);
    });

    // Mettre à jour le compteur de tâches dynamiquement
    const countEl = document.getElementById('tasks-count');
    if (countEl) {
        const nb = taches ? taches.length : 0;
        if (nb === 0) {
            countEl.textContent = "Aucune tâche";
        } else {
            countEl.textContent = nb + " tâche" + (nb > 1 ? "s" : "");
        }
    }
}

async function toggleTache(id) {
    try {
        const token = getAuthToken();
        const response = await fetch(`${API_BASE_URL}/tasks/${id}/toggle`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        if (data.success) {
            await chargerTachesDepuisAPI();
            showFeedback(data.message, 'success');
        } else {
            showFeedback(data.message || 'Erreur toggle tâche', 'error');
        }
    } catch (e) {
        console.error('Erreur toggle tâche:', e);
        showFeedback('Erreur réseau toggle tâche', 'error');
    }
}

async function supprimerTache(id) {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette tâche ?')) {
        return;
    }
    
    try {
        const token = getAuthToken();
        const response = await fetch(`${API_BASE_URL}/tasks/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        if (data.success) {
            await chargerTachesDepuisAPI();
            showFeedback('Tâche supprimée avec succès', 'success');
        } else {
            showFeedback(data.message || 'Erreur suppression tâche', 'error');
        }
    } catch (e) {
        console.error('Erreur suppression tâche:', e);
        showFeedback('Erreur réseau suppression tâche', 'error');
    }
}

async function editerTache(id) {
    const tache = EtatApp.taches.find(t => t._id === id);
    if (!tache) {
        showFeedback('Tâche non trouvée', 'error');
        return;
    }
    
    // Ouvrir une modal d'édition (similaire aux matières)
    openTaskModal(tache);
}

function openTaskModal(editTache = null) {
    const modal = document.getElementById('task-modal');
    if (!modal) {
        console.error('Modal task-modal non trouvée');
        return;
    }
    
    const form = document.getElementById('task-form');
    const title = document.getElementById('task-modal-title');
    const submitBtn = document.getElementById('task-submit');
    
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    form.reset();
    
    // Remplir les matières dans le select
    const subjectSelect = document.getElementById('task-subject');
    if (subjectSelect) {
        subjectSelect.innerHTML = '<option value="">Aucune matière</option>';
        if (EtatApp.matieres) {
            EtatApp.matieres.forEach(matiere => {
                const option = document.createElement('option');
                option.value = matiere._id;
                option.textContent = matiere.name;
                subjectSelect.appendChild(option);
            });
        }
    }
    
    if (editTache) {
        title.textContent = 'Modifier la tâche';
        submitBtn.textContent = 'Enregistrer';
        document.getElementById('task-title').value = editTache.title;
        document.getElementById('task-description').value = editTache.description || '';
        document.getElementById('task-subject').value = editTache.subjectId ? editTache.subjectId._id : '';
        document.getElementById('task-priority').value = editTache.priority;
        if (editTache.dueDate) {
            document.getElementById('task-due-date').value = new Date(editTache.dueDate).toISOString().slice(0,10);
        }
        document.getElementById('task-estimated-time').value = editTache.estimatedTime || '';
        form.setAttribute('data-edit-id', editTache._id);
    } else {
        title.textContent = 'Ajouter une tâche';
        submitBtn.textContent = 'Ajouter';
        form.removeAttribute('data-edit-id');
    }
    
    // Configurer le formulaire si pas déjà fait
    setupTaskForm();
    
    setTimeout(() => { document.getElementById('task-title').focus(); }, 100);
}

function closeTaskModal() {
    const modal = document.getElementById('task-modal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = '';
        document.getElementById('task-form').reset();
        document.getElementById('task-form').removeAttribute('data-edit-id');
    }
}

function setupTaskForm() {
    const form = document.getElementById('task-form');
    if (!form) return;
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const submitBtn = document.getElementById('task-submit');
        const originalText = submitBtn.textContent;
        submitBtn.textContent = 'Enregistrement...';
        submitBtn.disabled = true;
        
        try {
            const editId = form.getAttribute('data-edit-id');
            const formData = {
                title: document.getElementById('task-title').value.trim(),
                description: document.getElementById('task-description').value.trim() || null,
                subjectId: document.getElementById('task-subject').value || null,
                priority: Number(document.getElementById('task-priority').value),
                dueDate: document.getElementById('task-due-date').value || null,
                estimatedTime: document.getElementById('task-estimated-time').value ? Number(document.getElementById('task-estimated-time').value) : null
            };
            
            const token = getAuthToken();
            const url = editId ? `${API_BASE_URL}/tasks/${editId}` : `${API_BASE_URL}/tasks`;
            const method = editId ? 'PUT' : 'POST';
            
            const response = await fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            if (data.success) {
                closeTaskModal();
                await chargerTachesDepuisAPI();
                showFeedback(editId ? 'Tâche modifiée avec succès !' : 'Tâche ajoutée avec succès !', 'success');
            } else {
                showFeedback(data.message || 'Erreur sauvegarde tâche', 'error');
            }
        } catch (e) {
            console.error('Erreur sauvegarde tâche:', e);
            showFeedback('Erreur réseau sauvegarde tâche', 'error');
        } finally {
            resetSubmitButton(submitBtn, originalText);
        }
    });
}

// === Gestion des matières connectée à l'API ===
async function chargerMatieresDepuisAPI() {
    try {
        const token = getAuthToken();
        const response = await fetch(`${API_BASE_URL}/subjects`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            EtatApp.matieres = data.data;
            afficherMatieres();
            mettreAJourStatsDashboard();
        } else {
            showFeedback(data.message || 'Erreur chargement matières', 'error');
        }
    } catch (e) {
        showFeedback('Erreur réseau chargement matières', 'error');
    }
}

async function ajouterMatiereAPI(matiere) {
    try {
        const token = getAuthToken();
        const response = await fetch(`${API_BASE_URL}/subjects`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(matiere)
        });
        const data = await response.json();
        if (data.success) {
            showFeedback('Matière ajoutée avec succès !', 'success');
            await chargerMatieresDepuisAPI();
            mettreAJourStatsDashboard();
        } else {
            showFeedback(data.message || 'Erreur ajout matière', 'error');
        }
    } catch (e) {
        showFeedback('Erreur réseau ajout matière', 'error');
    }
}

function afficherMatieres() {
    const container = document.getElementById('subjects-container');
    const countEl = document.getElementById('subjects-count');
    if (!container) return;
    container.innerHTML = '';
    
    // Toutes les matières sont maintenant actives (suppression physique)
    const matieres = EtatApp.matieres || [];
    
    if (countEl) {
        if (!matieres.length) countEl.textContent = 'Aucune matière';
        else countEl.textContent = matieres.length + (matieres.length > 1 ? ' matières' : ' matière');
    }
    if (!matieres.length) {
        container.innerHTML = '<em>Aucune matière</em>';
        return;
    }
    matieres.forEach(matiere => {
        const div = document.createElement('div');
        div.className = 'subject-item';
        div.style.borderLeftColor = matiere.color || '#4F46E5';
        div.innerHTML = `
            <button class="subject-edit-btn" title="Éditer" onclick="editerMatiere('${matiere._id}')">✏️</button>
            <div class="subject-content">
                <div class="subject-name">${matiere.name} <span style="font-size:0.95em;color:#b3b8c7;">(${matiere.codeUE})</span></div>
                <div class="subject-meta">
                    <span>Prof : ${matiere.prof || '-'}</span>
                    <span>Crédits : ${matiere.credits || 0}</span>
                    <span>Examen : ${matiere.examDate ? new Date(matiere.examDate).toLocaleDateString() : '-'}</span>
                </div>
            </div>
            <button class="subject-delete-btn" title="Supprimer" onclick="supprimerMatiere('${matiere._id}')">🗑️</button>
        `;
        container.appendChild(div);
    });
}

// === Gestion de la modal matières ===
function openSubjectModal(editMatiere = null) {
    const modal = document.getElementById('subject-modal');
    const form = document.getElementById('subject-form');
    const title = document.getElementById('subject-modal-title');
    const submitBtn = document.getElementById('subject-submit');
    const cancelBtn = document.getElementById('subject-cancel');
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    form.reset();
    if (editMatiere) {
        title.textContent = 'Modifier la matière';
        submitBtn.textContent = 'Enregistrer';
        document.getElementById('subject-name').value = editMatiere.name;
        document.getElementById('subject-codeUE').value = editMatiere.codeUE;
        document.getElementById('subject-prof').value = editMatiere.prof || '';
        document.getElementById('subject-credits').value = editMatiere.credits || 0;
        if (editMatiere.examDate) {
            const d = new Date(editMatiere.examDate);
            document.getElementById('subject-examDate').value = d.toISOString().slice(0,10);
            document.getElementById('subject-examTime').value = d.toTimeString().slice(0,5);
        } else {
            document.getElementById('subject-examDate').value = '';
            document.getElementById('subject-examTime').value = '';
        }
        document.getElementById('subject-color').value = editMatiere.color || '#4F46E5';
        document.getElementById('subject-description').value = editMatiere.description || '';
        form.setAttribute('data-edit-id', editMatiere._id);
    } else {
        title.textContent = 'Ajouter une matière';
        submitBtn.textContent = 'Ajouter';
        form.removeAttribute('data-edit-id');
        document.getElementById('subject-examDate').value = '';
        document.getElementById('subject-examTime').value = '';
    }
    setTimeout(() => { document.getElementById('subject-name').focus(); }, 100);
}

function closeSubjectModal() {
    const modal = document.getElementById('subject-modal');
    modal.style.display = 'none';
    document.body.style.overflow = '';
    document.getElementById('subject-form').reset();
    document.getElementById('subject-form').removeAttribute('data-edit-id');
}

// Fonction pour configurer le formulaire des matières
function setupSubjectForm() {
    console.log('🔧 Configuration du formulaire matière...');
    const form = document.getElementById('subject-form');
    if (!form) {
        console.error('❌ Formulaire subject-form non trouvé');
        return;
    }
    
    console.log('✅ Formulaire trouvé:', form);
    
    form.onsubmit = async function(e) {
        e.preventDefault();
        console.log('📝 Soumission du formulaire matière détectée !');
        
        // Récupération des données du formulaire avec validation
        const nameEl = document.getElementById('subject-name');
        const codeUEEl = document.getElementById('subject-codeUE');
        const profEl = document.getElementById('subject-prof');
        const creditsEl = document.getElementById('subject-credits');
        const examDateEl = document.getElementById('subject-examDate');
        const examTimeEl = document.getElementById('subject-examTime');
        const colorEl = document.getElementById('subject-color');
        const descriptionEl = document.getElementById('subject-description');
        
        console.log('🔍 Éléments du formulaire trouvés:', {
            name: nameEl?.value,
            codeUE: codeUEEl?.value,
            prof: profEl?.value,
            credits: creditsEl?.value,
            examDate: examDateEl?.value,
            examTime: examTimeEl?.value,
            color: colorEl?.value,
            description: descriptionEl?.value
        });
        
        const date = examDateEl?.value;
        const time = examTimeEl?.value;
        let examDate = null;
        if (date) {
            examDate = time ? `${date}T${time}` : date;
        }
        
        const formData = {
            name: nameEl?.value.trim() || '',
            codeUE: codeUEEl?.value.trim() || '',
            prof: profEl?.value.trim() || null,
            credits: parseInt(creditsEl?.value) || 0,
            examDate: examDate || null,
            color: colorEl?.value || '#4F46E5',
            description: descriptionEl?.value.trim() || null
        };
        
        console.log('📋 Données du formulaire préparées:', formData);
        
        // Validation
        if (!formData.name || !formData.codeUE) {
            console.error('❌ Validation échouée: nom ou code UE manquant');
            showFeedback('Nom et code UE sont requis', 'error');
            return;
        }
        
        try {
            const editId = form.getAttribute('data-edit-id');
            console.log('🔍 Mode édition détecté:', editId ? 'OUI' : 'NON');
            
            if (editId) {
                // Mode édition
                console.log('✏️ Mode édition pour la matière:', editId);
                await modifierMatiereAPI(editId, formData);
            } else {
                // Mode ajout
                console.log('➕ Mode ajout de nouvelle matière');
                await ajouterMatiereAPI(formData);
            }
            
            closeSubjectModal();
        } catch (error) {
            console.error('❌ Erreur lors de la soumission:', error);
            showFeedback('Erreur lors de la sauvegarde', 'error');
        }
    };
    
    console.log('✅ Événement onsubmit attaché au formulaire');
    
    // Test : attacher aussi un événement click direct au bouton submit
    const submitBtn = document.getElementById('subject-submit');
    if (submitBtn) {
        submitBtn.onclick = function(e) {
            console.log('🎯 Bouton submit cliqué directement !');
            // Déclencher la soumission du formulaire
            form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        };
        console.log('✅ Événement onclick attaché au bouton submit');
    } else {
        console.error('❌ Bouton submit non trouvé');
    }
}

// Fonction pour modifier une matière via l'API
async function modifierMatiereAPI(id, matiere) {
    console.log('✏️ modifierMatiereAPI appelée avec ID:', id, 'et données:', matiere);
    try {
        const token = getAuthToken();
        if (!token) {
            console.error('❌ Pas de token d\'authentification');
            showFeedback('Erreur d\'authentification', 'error');
            return;
        }
        console.log('🔑 Token récupéré pour modification');
        
        const response = await fetch(`${API_BASE_URL}/subjects/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(matiere)
        });
        
        console.log('📡 Réponse brute:', response);
        const data = await response.json();
        console.log('📡 Données de réponse:', data);
        
        if (data.success) {
            console.log('✅ Modification réussie');
            showFeedback('Matière modifiée !', 'success');
            await chargerMatieresDepuisAPI();
            mettreAJourStatsDashboard();
        } else {
            console.error('❌ Erreur API modification:', data.message);
            showFeedback(data.message || 'Erreur modification matière', 'error');
        }
    } catch (e) {
        console.error('❌ Erreur réseau modification:', e);
        showFeedback('Erreur réseau modification matière', 'error');
    }
}

// === Messages de motivation dynamiques ===
const messagesMotivation = [
    "Continue, tu es sur la bonne voie !",
    "Chaque session compte, ne lâche rien !",
    "La régularité paie toujours.",
    "Un pas de plus vers la réussite !",
    "Ta concentration est ta super-puissance !",
    "Garde le cap, tu vas y arriver !"
];

function afficherMessageMotivation(msg = null) {
    const el = document.getElementById('motivation-text');
    if (msg) {
        el.textContent = msg;
    } else {
        el.textContent = messagesMotivation[Math.floor(Math.random() * messagesMotivation.length)];
    }
}

// === Mise à jour de l'interface ===
function mettreAJourInterface() {
    // User greeting
    if (EtatApp.utilisateur) {
        document.getElementById('user-greeting').textContent = `Bonjour, ${EtatApp.utilisateur.nomUtilisateur} !`;
        // Ajouter la motivation dans le header si elle existe
        if (EtatApp.utilisateur.motivation) {
            const userInfo = document.querySelector('.user-info');
            let motivationEl = document.getElementById('user-motivation');
            if (!motivationEl) {
                motivationEl = document.createElement('div');
                motivationEl.id = 'user-motivation';
                motivationEl.style.fontSize = '0.9rem';
                motivationEl.style.opacity = '0.8';
                motivationEl.style.marginTop = '0.25rem';
                userInfo.appendChild(motivationEl);
            }
            motivationEl.textContent = `"${EtatApp.utilisateur.motivation}"`;
        }
    }
    afficherTaches();
    afficherMatieres();
    afficherMessageMotivation();
    afficherTemps();
    mettreAJourStatsDashboard();
}

// === Mise à jour des stats du dashboard pro ===
function mettreAJourStatsDashboard() {
    // Aujourd'hui
    const elToday = document.getElementById('stat-today-pro');
    if (elToday) elToday.textContent = calculerTempsEtudeDuJour();
    // Progression
    const elProgress = document.getElementById('stat-progress-pro');
    if (elProgress) elProgress.textContent = calculerProgressionGlobale();
    // Prochain examen
    const elExam = document.getElementById('stat-countdown-pro');
    if (elExam) elExam.innerHTML = prochainExamen();
}

// Fonction pour démarrer la mise à jour automatique du prochain examen
function demarrerMiseAJourProchainExamen() {
    // Mettre à jour immédiatement
    mettreAJourStatsDashboard();
    
    // Mettre à jour toutes les minutes
    setInterval(() => {
        const elExam = document.getElementById('stat-countdown-pro');
        if (elExam) {
            elExam.innerHTML = prochainExamen();
        }
    }, 60000); // 60 secondes
}

// === Redirection sécurisée après déconnexion ===
function seDeconnecter() {
    EtatApp.mettreAJour('utilisateur', null);
    arreterTimer();
    
    // Masquer tous les écrans
    if (document.getElementById('dashboard-pro')) {
        document.getElementById('dashboard-pro').style.display = 'none';
    }
    document.getElementById('split-landing').style.display = 'flex';
    document.getElementById('split-verification').style.display = 'none';
    
    showFeedback('Déconnexion réussie !', 'info');
}

// === Redirige le lien de vérification vers le dashboard pro ===
async function verifierEmail(token, email) {
    try {
        // Utiliser l'URL complète pour la vérification
        const response = await fetch(`${API_BASE_URL}/verify-email?token=${token}&email=${encodeURIComponent(email)}`);
        
        if (response.ok) {
            showFeedback('Email vérifié avec succès ! Vous pouvez maintenant vous connecter.', 'success');
            
            // Nettoyer l'URL
            window.history.replaceState({}, document.title, window.location.pathname);
            
            // Rediriger vers la page de connexion
            setTimeout(() => {
                retourConnexion();
            }, 2000);
            
            return true;
        } else {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || 'Erreur lors de la vérification');
        }
    } catch (error) {
        console.error('Erreur vérification email:', error);
        showFeedback(error.message || 'Erreur lors de la vérification de l\'email.', 'error');
        return false;
    }
}

// === Affiche la page de vérification email après inscription ===
function afficherPageVerification(email, username, motivation, verificationToken) {
    // Masquer la page d'authentification et afficher la page de vérification
    document.getElementById('split-landing').style.display = 'none';
    document.getElementById('split-verification').style.display = 'flex';
    
    // Afficher l'email dans la page de vérification
    document.getElementById('verification-email').textContent = email;
    
    // Générer le lien de vérification correct
    const verificationLink = `http://localhost:3000/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;
    
    // Afficher le lien dans la console et sur la page pour le développement
    console.log('Lien de vérification (dev):', verificationLink);
    document.getElementById('dev-verification-link').innerHTML = `
        <strong>Lien de vérification (développement):</strong><br>
        <a href="${verificationLink}" style="color: #4F46E5; text-decoration: underline;">Cliquer ici pour vérifier l'email</a>
    `;
}

// === Gestion du mode light/dark ===
function setTheme(mode) {
    document.body.classList.remove('light-mode', 'dark-mode');
    document.body.classList.add(mode);
    localStorage.setItem('theme', mode);
    const btn = document.getElementById('toggle-theme');
    if (btn) btn.textContent = mode === 'dark-mode' ? '🌙' : '☀️';
}

function toggleTheme() {
    const current = document.body.classList.contains('dark-mode') ? 'dark-mode' : 'light-mode';
    setTheme(current === 'dark-mode' ? 'light-mode' : 'dark-mode');
}

const themeBtn = document.getElementById('toggle-theme');
if (themeBtn) themeBtn.onclick = toggleTheme;

function retourConnexion() {
    document.getElementById('split-verification').style.display = 'none';
    document.getElementById('split-landing').style.display = 'flex';
    
    // Réinitialiser le formulaire
    document.getElementById('auth-form').reset();
    modeInscription = false;
    document.getElementById('username-group').style.display = 'none';
    document.getElementById('motivation-group').style.display = 'none';
    document.getElementById('confirm-password-group').style.display = 'none';
    document.getElementById('auth-title').textContent = 'Connexion';
    document.getElementById('auth-submit-text').textContent = 'Se connecter';
    document.getElementById('auth-toggle').innerHTML = "Pas encore de compte ? <span>S'inscrire</span>";
    
    showFeedback('Retour à la connexion', 'info', 2000);
}

// Fonction pour basculer la visibilité du mot de passe
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    if (!input) return;
    
    const button = input.parentElement.querySelector('.toggle-password');
    if (!button) return;
    
    if (input.type === 'password') {
        input.type = 'text';
        button.textContent = '🙈';
    } else {
        input.type = 'password';
        button.textContent = '👁️';
    }
}

// Gestion de l'upload/modification de l'avatar
function setupAvatarUpload() {
    const avatarBtn = document.getElementById('avatar-upload-btn');
    const avatarInput = document.getElementById('avatar-input');
    if (!avatarBtn || !avatarInput) return;
    avatarBtn.onclick = () => avatarInput.click();
    avatarInput.onchange = async function() {
        if (!this.files || !this.files[0]) return;
        const file = this.files[0];
        // Vérifier le type
        if (!file.type.startsWith('image/')) {
            showFeedback('Format d\'image non supporté', 'error');
            return;
        }
        // Lire le fichier en base64
        const reader = new FileReader();
        reader.onload = async function(e) {
            const base64 = e.target.result;
            try {
                const token = getAuthToken();
                const response = await fetch(`${API_BASE_URL}/profile/avatar`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ avatar: base64 })
                });
                const data = await response.json();
                if (data.success) {
                    showFeedback('Photo de profil mise à jour !', 'success');
                    EtatApp.utilisateur.avatar = data.data.avatar;
                    mettreAJourDashboardPro(EtatApp.utilisateur);
                } else {
                    showFeedback(data.message || 'Erreur lors de la mise à jour', 'error');
                }
            } catch (err) {
                showFeedback('Erreur lors de l\'upload', 'error');
            }
        };
        reader.readAsDataURL(file);
    };
}

document.addEventListener('DOMContentLoaded', setupAvatarUpload);

// === Fonctions globales pour l'édition et suppression des matières ===
// Déclaration explicite des fonctions globales pour éviter les problèmes d'accessibilité
window.editerMatiere = function(id) {
    console.log('🔧 Fonction editerMatiere appelée avec ID:', id);
    const matiere = EtatApp.matieres.find(m => m._id === id);
    if (!matiere) {
        console.error('❌ Matière non trouvée avec ID:', id);
        showFeedback('Matière non trouvée', 'error');
        return;
    }
    console.log('✅ Matière trouvée pour édition:', matiere);
    openSubjectModal(matiere);
};

window.supprimerMatiere = async function(id) {
    console.log('🗑️ Fonction supprimerMatiere appelée avec ID:', id);
    if (!confirm('Supprimer cette matière ?')) {
        console.log('❌ Suppression annulée par l\'utilisateur');
        return;
    }
    try {
        const token = getAuthToken();
        console.log('🔑 Token récupéré pour suppression');
        const response = await fetch(`${API_BASE_URL}/subjects/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        console.log('📡 Réponse API suppression:', data);
        if (data.success) {
            showFeedback('Matière supprimée', 'success');
            await chargerMatieresDepuisAPI();
            mettreAJourStatsDashboard();
        } else {
            console.error('❌ Erreur API suppression:', data.message);
            showFeedback(data.message || 'Erreur suppression matière', 'error');
        }
    } catch (e) {
        console.error('❌ Erreur réseau suppression:', e);
        showFeedback('Erreur réseau suppression matière', 'error');
    }
};

// === Système de notifications intelligentes ===
const NotificationSystem = {
    notifications: [],
    maxNotifications: 20,
    // Charger depuis l'API backend
    async loadFromAPI() {
        const token = getAuthToken();
        const response = await fetch(`${API_BASE_URL}/notifications`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            this.notifications = data.data.map(n => ({
                id: n._id,
                message: n.message,
                type: n.type,
                taskId: n.metadata?.taskId || null,
                timestamp: new Date(n.createdAt),
                read: n.read
            }));
            this.updateBadge();
            this.renderNotifications();
        }
    },
    // Ajouter une notification locale (tâches, etc.)
    addNotification(message, type = 'info', taskId = null) {
        const notification = {
            id: Date.now() + Math.random(),
            message,
            type,
            taskId,
            timestamp: new Date(),
            read: false,
            local: true
        };
        this.notifications.unshift(notification);
        if (this.notifications.length > this.maxNotifications) {
            this.notifications = this.notifications.slice(0, this.maxNotifications);
        }
        this.updateBadge();
        this.renderNotifications();
        this.saveToStorage();
    },
    // Marquer comme lue (API ou local)
    async markAsRead(id) {
        const notif = this.notifications.find(n => n.id === id);
        if (!notif) return;
        notif.read = true;
        if (!notif.local) {
            const token = getAuthToken();
            await fetch(`${API_BASE_URL}/notifications/${id}/read`, {
                method: 'PATCH',
                headers: { 'Authorization': `Bearer ${token}` }
            });
        }
        this.updateBadge();
        this.renderNotifications();
        this.saveToStorage();
    },
    // Effacer toutes les notifications (API et local)
    async clearAll() {
        // Supprimer toutes les notifications côté backend en une seule requête
        const token = getAuthToken();
        await fetch(`${API_BASE_URL}/notifications/all`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        // Vider la liste côté frontend
        this.notifications = [];
        this.updateBadge();
        this.renderNotifications();
        this.saveToStorage();
    },
    // Mettre à jour le badge
    updateBadge() {
        const badge = document.getElementById('notification-badge');
        const unreadCount = this.notifications.filter(n => !n.read).length;
        if (badge) {
            if (unreadCount > 0) {
                badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
                badge.style.display = 'flex';
            } else {
                badge.style.display = 'none';
            }
        }
    },
    // Afficher les notifications
    renderNotifications() {
        const list = document.getElementById('notifications-list');
        if (!list) return;
        if (this.notifications.length === 0) {
            list.innerHTML = '<div class="no-notifications" style="color:#f55;font-weight:bold;">Aucune notification trouvée.<br>Vérifie le token, l\'API et l\'utilisateur connecté.</div>';
            return;
        }
        list.innerHTML = this.notifications.map(notification => `
            <div class="notification-item ${notification.type} ${notification.read ? 'read' : ''} ${notification.local ? 'local-notif' : 'backend-notif'}" 
                 data-id="${notification.id}" data-local="${!!notification.local}">
                <div class="notification-content">${notification.message}</div>
                <div class="notification-time">${this.formatTime(notification.timestamp)}</div>
            </div>
        `).join('');
        // Ajout du handler de clic dynamique
        Array.from(list.getElementsByClassName('notification-item')).forEach(item => {
            item.onclick = async (e) => {
                const id = item.getAttribute('data-id');
                const isLocal = item.getAttribute('data-local') === 'true';
                // Marquer comme lue côté UI immédiatement
                item.classList.add('read');
                await NotificationSystem.markAsRead(isLocal ? Number(id) : id);
                NotificationSystem.updateBadge();
            };
        });
        // Handler pour le bouton 'Tout effacer'
        const clearBtn = document.getElementById('clear-notifications');
        if (clearBtn) {
            clearBtn.onclick = async () => {
                await NotificationSystem.clearAll();
            };
        }
        // Charger les notifications locales une seule fois (si pas déjà présentes)
        const saved = localStorage.getItem('apte_notifications');
        if (saved) {
            try {
                const localNotifs = JSON.parse(saved) || [];
                // Fusionner sans dupliquer (par message et timestamp proche)
                localNotifs.forEach(localNotif => {
                    const exists = this.notifications.some(n =>
                        n.message === localNotif.message &&
                        Math.abs(new Date(n.timestamp) - new Date(localNotif.timestamp)) < 60000 // 1 min
                    );
                    if (!exists) {
                        this.notifications.push(localNotif);
                    }
                });
            } catch (e) {
                console.error('Erreur chargement notifications locales:', e);
            }
        }
    },
    // Formatage du temps (utilitaire)
    formatTime(timestamp) {
        const now = new Date();
        const diff = now - timestamp;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        if (minutes < 1) return 'À l\'instant';
        if (minutes < 60) {
            // Afficher l'heure exacte si < 1h
            return `Il y a ${minutes} min (${timestamp.getHours().toString().padStart(2, '0')}:${timestamp.getMinutes().toString().padStart(2, '0')})`;
        }
        if (hours < 24) {
            return `Il y a ${hours}h (${timestamp.getHours().toString().padStart(2, '0')}:${timestamp.getMinutes().toString().padStart(2, '0')})`;
        }
        // Afficher la date et l'heure si > 24h
        return `${timestamp.getDate().toString().padStart(2, '0')}/${(timestamp.getMonth()+1).toString().padStart(2, '0')}/${timestamp.getFullYear()} ${timestamp.getHours().toString().padStart(2, '0')}:${timestamp.getMinutes().toString().padStart(2, '0')}`;
    },
    // Sauvegarder dans le localStorage
    saveToStorage() {
        localStorage.setItem('apte_notifications', JSON.stringify(this.notifications));
    },
    // Charger depuis le localStorage
    loadFromStorage() {
        const saved = localStorage.getItem('apte_notifications');
        if (saved) {
            try {
                this.notifications = JSON.parse(saved);
                this.updateBadge();
                this.renderNotifications();
            } catch (e) {
                console.error('Erreur chargement notifications:', e);
            }
        }
    },
    // Vérifier les tâches en retard
    checkOverdueTasks() {
        // Désactivé : la création de notifications se fait désormais côté serveur
        // (plus de notifications locales côté client)
    },
    // Vérifier les tâches importantes
    checkHighPriorityTasks() {
        // Désactivé : la création de notifications se fait désormais côté serveur
        // (plus de notifications locales côté client)
    },
    // Initialisation
    async init() {
        await this.loadFromAPI();
        // Désormais, on ignore totalement le localStorage :
        // Plus de fusion ni de notifications locales
        this.notifications.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        this.updateBadge();
        this.renderNotifications();
    }
};

// Initialisation du système de notifications
// Remplacer l'appel à loadFromStorage par init

document.addEventListener('DOMContentLoaded', function() {
    NotificationSystem.init();
    // Affichage/fermeture de la dropdown notifications
    const notifBtn = document.getElementById('notification-btn');
    const notifDropdown = document.getElementById('notifications-dropdown');
    if (notifBtn && notifDropdown) {
        notifBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            notifDropdown.classList.toggle('show');
        });
        // Fermer la dropdown si on clique ailleurs
        document.addEventListener('click', function(e) {
            if (!notifDropdown.contains(e.target) && e.target !== notifBtn) {
                notifDropdown.classList.remove('show');
            }
        });
    }
});

// === Système de graphiques avancés ===
const ChartSystem = {
    charts: {},
    // Initialiser tous les graphiques
    initCharts() {
        // Vérifier la présence de Chart.js
        if (typeof Chart === 'undefined') {
            // Masquer les canvas et afficher un message d'info
            const ids = ['study-time-chart', 'tasks-completion-chart', 'subjects-chart'];
            ids.forEach(id => {
                const canvas = document.getElementById(id);
                if (canvas) canvas.style.display = 'none';
                const parent = canvas?.parentElement;
                if (parent && !parent.querySelector('.chart-unavailable')) {
                    const msg = document.createElement('div');
                    msg.className = 'chart-unavailable';
                    msg.style.color = '#f55';
                    msg.style.textAlign = 'center';
                    msg.style.margin = '2em 0';
                    msg.textContent = 'Graphiques non disponibles (Chart.js absent ou bloqué)';
                    parent.appendChild(msg);
                }
            });
            return;
        }
        this.createStudyTimeChart();
        this.createTasksCompletionChart();
        this.createSubjectsChart();
        this.updateGoals();
    },
    // Graphique du temps d'étude
    createStudyTimeChart() {
        const ctx = document.getElementById('study-time-chart');
        if (!ctx) return;
        const data = this.getStudyTimeData();
        if (!data.values || data.values.every(v => v === 0)) {
            ctx.style.display = 'none';
            const parent = ctx.parentElement;
            if (parent && !parent.querySelector('.chart-empty')) {
                const msg = document.createElement('div');
                msg.className = 'chart-empty';
                msg.style.color = '#aaa';
                msg.style.textAlign = 'center';
                msg.style.margin = '2em 0';
                msg.textContent = 'Aucune donnée à afficher';
                parent.appendChild(msg);
            }
            return;
        }
        ctx.style.display = '';
        if (ctx.parentElement.querySelector('.chart-empty')) ctx.parentElement.querySelector('.chart-empty').remove();
        this.charts.studyTime = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [{
                    label: "Temps d'étude (heures)",
                    data: data.values,
                    borderColor: 'rgb(1, 196, 255)',
                    backgroundColor: 'rgba(1, 196, 255, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    }
                }
            }
        });
    },
    createTasksCompletionChart() {
        const ctx = document.getElementById('tasks-completion-chart');
        if (!ctx) return;
        const data = this.getTasksCompletionData();
        if (!data.completed && !data.inProgress && !data.overdue) {
            ctx.style.display = 'none';
            const parent = ctx.parentElement;
            if (parent && !parent.querySelector('.chart-empty')) {
                const msg = document.createElement('div');
                msg.className = 'chart-empty';
                msg.style.color = '#aaa';
                msg.style.textAlign = 'center';
                msg.style.margin = '2em 0';
                msg.textContent = 'Aucune donnée à afficher';
                parent.appendChild(msg);
            }
            return;
        }
        ctx.style.display = '';
        if (ctx.parentElement.querySelector('.chart-empty')) ctx.parentElement.querySelector('.chart-empty').remove();
        this.charts.tasksCompletion = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Complétées', 'En cours', 'En retard'],
                datasets: [{
                    data: [data.completed, data.inProgress, data.overdue],
                    backgroundColor: [
                        'rgba(16, 185, 129, 0.8)',
                        'rgba(59, 130, 246, 0.8)',
                        'rgba(239, 68, 68, 0.8)'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'rgba(255, 255, 255, 0.8)',
                            padding: 15
                        }
                    }
                }
            }
        });
    },
    createSubjectsChart() {
        const ctx = document.getElementById('subjects-chart');
        if (!ctx) return;
        const data = this.getSubjectsData();
        if (!data.values || data.values.every(v => v === 0)) {
            ctx.style.display = 'none';
            const parent = ctx.parentElement;
            if (parent && !parent.querySelector('.chart-empty')) {
                const msg = document.createElement('div');
                msg.className = 'chart-empty';
                msg.style.color = '#aaa';
                msg.style.textAlign = 'center';
                msg.style.margin = '2em 0';
                msg.textContent = 'Aucune donnée à afficher';
                parent.appendChild(msg);
            }
            return;
        }
        ctx.style.display = '';
        if (ctx.parentElement.querySelector('.chart-empty')) ctx.parentElement.querySelector('.chart-empty').remove();
        this.charts.subjects = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'Tâches par matière',
                    data: data.values,
                    backgroundColor: 'rgba(1, 196, 255, 0.6)',
                    borderColor: 'rgb(1, 196, 255)',
                    borderWidth: 2,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)',
                            maxRotation: 45
                        }
                    }
                }
            }
        });
    },
    // Mettre à jour les objectifs
    updateGoals() {
        const weeklyGoal = this.calculateWeeklyGoal();
        const pomodoroEfficiency = this.calculatePomodoroEfficiency();
        
        const goalBars = document.querySelectorAll('.goal-bar');
        if (goalBars[0]) goalBars[0].style.width = `${weeklyGoal}%`;
        if (goalBars[1]) goalBars[1].style.width = `${pomodoroEfficiency}%`;
        
        const goalSpans = document.querySelectorAll('.goal-item span');
        if (goalSpans[0]) goalSpans[0].textContent = `Objectif hebdomadaire: ${weeklyGoal}%`;
        if (goalSpans[1]) goalSpans[1].textContent = `Efficacité Pomodoro: ${pomodoroEfficiency}%`;
    },
    
    // Données pour le temps d'étude (7 derniers jours) - VRAIES DONNÉES
    getStudyTimeData() {
        const labels = [];
        const values = [];
        
        // Récupérer les sessions Pomodoro réelles
        const sessions = EtatApp.historiquePomo || [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0]; // Format YYYY-MM-DD
            
            labels.push(date.toLocaleDateString('fr-FR', { weekday: 'short' }));
            
            // Calculer le temps réel d'étude pour cette date
            const daySessions = sessions.filter(session => {
                const sessionDate = new Date(session.date).toISOString().split('T')[0];
                return sessionDate === dateStr;
            });
            
            const totalMinutes = daySessions.reduce((total, session) => {
                return total + (session.duree || 25); // Durée par session
            }, 0);
            
            const hours = totalMinutes / 60;
            values.push(Math.round(hours * 10) / 10); // Arrondir à 1 décimale
        }
        
        return { labels, values };
    },
    
    // Données pour les tâches complétées
    getTasksCompletionData() {
        if (!EtatApp.taches) return { completed: 0, inProgress: 0, overdue: 0 };
        
        const now = new Date();
        const completed = EtatApp.taches.filter(t => t.completed).length;
        const overdue = EtatApp.taches.filter(t => 
            t.dueDate && !t.completed && new Date(t.dueDate) < now
        ).length;
        const inProgress = EtatApp.taches.length - completed - overdue;
        
        return { completed, inProgress, overdue };
    },
    
    // Données pour la répartition par matière
    getSubjectsData() {
        if (!EtatApp.taches || !EtatApp.matieres) return { labels: [], values: [] };
        
        const subjectStats = {};
        EtatApp.taches.forEach(task => {
            if (task.subjectId) {
                const subjectName = task.subjectId.name;
                subjectStats[subjectName] = (subjectStats[subjectName] || 0) + 1;
            }
        });
        
        return {
            labels: Object.keys(subjectStats),
            values: Object.values(subjectStats)
        };
    },
    
    // Calculer l'objectif hebdomadaire - VRAIES DONNÉES
    calculateWeeklyGoal() {
        const sessions = EtatApp.historiquePomo || [];
        const now = new Date();
        const weekStart = new Date(now.getTime() - (now.getDay() * 24 * 60 * 60 * 1000));
        
        // Sessions de cette semaine
        const weekSessions = sessions.filter(session => {
            const sessionDate = new Date(session.date);
            return sessionDate >= weekStart;
        });
        
        const totalWeekMinutes = weekSessions.reduce((total, session) => {
            return total + (session.duree || 25);
        }, 0);
        
        // Objectif : 20h par semaine (1200 minutes)
        const weeklyGoal = 1200;
        const progress = Math.min(100, (totalWeekMinutes / weeklyGoal) * 100);
        
        return Math.round(progress);
    },
    
    // Calculer l'efficacité Pomodoro - VRAIES DONNÉES
    calculatePomodoroEfficiency() {
        const sessions = EtatApp.historiquePomo || [];
        if (sessions.length === 0) return 0;
        
        // Sessions complétées (non interrompues)
        const completedSessions = sessions.filter(session => session.completed);
        const efficiency = (completedSessions.length / sessions.length) * 100;
        
        return Math.round(efficiency);
    },
    
    // Mettre à jour tous les graphiques
    updateAllCharts() {
        if (this.charts.studyTime) {
            const studyData = this.getStudyTimeData();
            this.charts.studyTime.data.labels = studyData.labels;
            this.charts.studyTime.data.datasets[0].data = studyData.values;
            this.charts.studyTime.update();
        }
        
        if (this.charts.tasksCompletion) {
            const taskData = this.getTasksCompletionData();
            this.charts.tasksCompletion.data.datasets[0].data = [
                taskData.completed, taskData.inProgress, taskData.overdue
            ];
            this.charts.tasksCompletion.update();
        }
        
        if (this.charts.subjects) {
            const subjectData = this.getSubjectsData();
            this.charts.subjects.data.labels = subjectData.labels;
            this.charts.subjects.data.datasets[0].data = subjectData.values;
            this.charts.subjects.update();
        }
        
        this.updateGoals();
    }
};

// Initialisation des graphiques
document.addEventListener('DOMContentLoaded', function() {
    // Charger Chart.js depuis CDN si pas déjà chargé
    if (typeof Chart === 'undefined') {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/chart.js';
        script.onload = () => {
            setTimeout(() => ChartSystem.initCharts(), 100);
        };
        document.head.appendChild(script);
    } else {
        setTimeout(() => ChartSystem.initCharts(), 100);
    }
});

// === Système de récompenses et badges ===
const RewardSystem = {
    userPoints: 0,
    userLevel: 1,
    userXP: 0,
    earnedBadges: [],
    
    // Configuration des badges
    badges: [
        { id: 'first_task', name: 'Première tâche', icon: '✅', description: 'Complète ta première tâche', requirement: 1, type: 'tasks_completed' },
        { id: 'task_master', name: 'Maître des tâches', icon: '🎯', description: 'Complète 10 tâches', requirement: 10, type: 'tasks_completed' },
        { id: 'pomodoro_starter', name: 'Débutant Pomodoro', icon: '⏱️', description: 'Complète ta première session', requirement: 1, type: 'sessions_completed' },
        { id: 'pomodoro_master', name: 'Maître Pomodoro', icon: '🔥', description: 'Complète 20 sessions', requirement: 20, type: 'sessions_completed' },
        { id: 'early_bird', name: 'Lève-tôt', icon: '🌅', description: 'Étudie avant 8h du matin', requirement: 1, type: 'early_study' },
        { id: 'night_owl', name: 'Oiseau de nuit', icon: '🦉', description: 'Étudie après 22h', requirement: 1, type: 'late_study' },
        { id: 'streak_3', name: 'Série de 3', icon: '🔥', description: '3 jours consécutifs d\'étude', requirement: 3, type: 'study_streak' },
        { id: 'streak_7', name: 'Série de 7', icon: '🔥🔥', description: '7 jours consécutifs d\'étude', requirement: 7, type: 'study_streak' },
        { id: 'subject_expert', name: 'Expert matière', icon: '📚', description: '5 tâches dans une même matière', requirement: 5, type: 'subject_tasks' },
        { id: 'high_priority', name: 'Priorité haute', icon: '⚡', description: 'Complète une tâche de priorité 5', requirement: 1, type: 'high_priority_task' }
    ],
    
    // Initialisation
    async init() {
        await this.loadUserProgress();
        this.renderBadges();
        this.updateDisplay();
        this.checkAchievements();
    },
    
    // Charger les progrès utilisateur depuis l'API
    async loadUserProgress() {
        try {
            const token = getAuthToken();
            if (!token) return;
            
            const response = await apiCall('/rewards/profile', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.success) {
                const data = response.data;
                this.userPoints = data.points || 0;
                this.userLevel = data.level || 1;
                this.userXP = data.xp || 0;
                this.earnedBadges = data.earnedBadges || [];
            }
        } catch (error) {
            console.error('Erreur chargement récompenses:', error);
        }
    },
    
    // Ajouter des points via l'API
    async addPoints(points, reason = '') {
        try {
            const token = getAuthToken();
            if (!token) return false;
            
            const response = await apiCall('/rewards/add-points', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ points, reason })
            });
            
            if (response.success) {
                const data = response.data;
                // Sauvegarder les anciennes valeurs avant mise à jour
                const oldXP = this.userXP;
                const oldLevel = this.userLevel;
                this.userPoints = data.points;
                this.userLevel = data.level;
                this.userXP = data.xp;
                this.updateDisplay();
                // Notification
                if (reason) {
                    NotificationSystem.addNotification(
                        `+${points} points : ${reason}`,
                        'success'
                    );
                }
                // Animation des points
                this.animatePointsGain(points);
                // Notification de niveau si passage de niveau
                if (response.levelUp) {
                    NotificationSystem.addNotification(
                        `🎉 Niveau ${this.userLevel} atteint !`,
                        'success'
                    );
                    // Animation avancée de la barre d'XP lors du level up
                    this.animateXPBarLevelUp(oldXP, oldLevel, data.xp, data.level);
                    this.animateLevelUp();
                }
                return response.levelUp;
            }
        } catch (error) {
            console.error('Erreur ajout points:', error);
        }
        return false;
    },
    
    // Obtenir un badge via l'API
    async earnBadge(badge) {
        try {
            const token = getAuthToken();
            if (!token) return;
            
            const response = await apiCall('/rewards/earn-badge', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ badgeId: badge.id })
            });
            
            if (response.success) {
                const data = response.data;
                this.userPoints = data.points;
                this.userLevel = data.level;
                this.userXP = data.xp;
                this.earnedBadges = data.earnedBadges;
                // Notification spéciale
                NotificationSystem.addNotification(
                    `🏅 Nouveau badge : ${badge.name}`,
                    'success'
                );
                // Animation du badge
                this.animateBadgeEarned(badge);
                // Recharger la progression utilisateur pour garantir l'affichage à jour
                await this.loadUserProgress();
                this.renderBadges();
                this.updateDisplay();
            }
        } catch (error) {
            console.error('Erreur badge obtenu:', error);
        }
    },
    
    // Vérifier les achievements
    checkAchievements() {
        this.badges.forEach(badge => {
            if (!this.earnedBadges.includes(badge.id)) {
                if (this.checkBadgeRequirement(badge)) {
                    this.earnBadge(badge);
                }
            }
        });
    },
    
    // Vérifier si un badge peut être obtenu
    checkBadgeRequirement(badge) {
        switch (badge.type) {
            case 'tasks_completed':
                const completedTasks = EtatApp.taches?.filter(t => t.completed).length || 0;
                return completedTasks >= badge.requirement;
                
            case 'sessions_completed':
                const completedSessions = EtatApp.historiquePomo?.filter(s => s.completed).length || 0;
                return completedSessions >= badge.requirement;
                
            case 'high_priority_task':
                const highPriorityCompleted = EtatApp.taches?.filter(t => t.completed && t.priority === 5).length || 0;
                return highPriorityCompleted >= badge.requirement;
                
            case 'subject_tasks':
                // Vérifier si une matière a 5 tâches ou plus
                if (EtatApp.taches && EtatApp.matieres) {
                    for (let subject of EtatApp.matieres) {
                        const subjectTasks = EtatApp.taches.filter(t => 
                            t.subjectId && t.subjectId._id === subject._id && t.completed
                        ).length;
                        if (subjectTasks >= badge.requirement) return true;
                    }
                }
                return false;
                
            default:
                return false;
        }
    },
    
    // Afficher les badges
    renderBadges() {
        const grid = document.getElementById('badges-grid');
        if (!grid) return;
        
        grid.innerHTML = this.badges.map(badge => `
            <div class="badge-item ${this.earnedBadges.includes(badge.id) ? 'earned' : ''}" 
                 title="${badge.description}">
                <div class="badge-icon">${badge.icon}</div>
                <div class="badge-name">${badge.name}</div>
            </div>
        `).join('');
    },
    
    // Mettre à jour l'affichage
    updateDisplay() {
        const pointsEl = document.getElementById('user-points');
        const levelEl = document.getElementById('user-level');
        const xpBarEl = document.getElementById('xp-progress-bar');
        const xpTextEl = document.getElementById('xp-text');
        
        if (pointsEl) pointsEl.textContent = this.userPoints;
        if (levelEl) levelEl.textContent = `Niveau ${this.userLevel}`;
        
        const xpNeeded = this.userLevel * 100;
        const xpProgress = (this.userXP / xpNeeded) * 100;
        
        if (xpBarEl) xpBarEl.style.width = `${xpProgress}%`;
        if (xpTextEl) xpTextEl.textContent = `${this.userXP} / ${xpNeeded} XP`;
    },
    
    // Animations
    animatePointsGain(points) {
        const pointsEl = document.getElementById('user-points');
        if (pointsEl) {
            pointsEl.style.transform = 'scale(1.2)';
            pointsEl.style.color = '#fbbf24';
            // Ajout du '+X' flottant
            const plus = document.createElement('span');
            plus.textContent = `+${points}`;
            plus.className = 'points-float';
            pointsEl.parentNode.appendChild(plus);
            setTimeout(() => {
                plus.style.opacity = '0';
                plus.style.transform = 'translateY(-30px)';
            }, 10);
            setTimeout(() => {
                if (plus.parentNode) plus.parentNode.removeChild(plus);
            }, 800);
            setTimeout(() => {
                pointsEl.style.transform = 'scale(1)';
                pointsEl.style.color = '#fff';
            }, 300);
        }
    },
    
    animateLevelUp() {
        const levelEl = document.getElementById('user-level');
        if (levelEl) {
            levelEl.style.transform = 'scale(1.3)';
            levelEl.style.background = 'linear-gradient(135deg, #fbbf24, #f59e0b)';
            setTimeout(() => {
                levelEl.style.transform = 'scale(1)';
                levelEl.style.background = 'linear-gradient(135deg, #f59e0b, #d97706)';
            }, 500);
        }
    },
    
    // Nouvelle animation XP lors du level up
    animateXPBarLevelUp(oldXP, oldLevel, newXP, newLevel) {
        const xpBar = document.getElementById('xp-progress-bar');
        const xpText = document.getElementById('xp-text');
        if (!xpBar || !xpText) return;
        // 1. Remplir jusqu'à 100%
        xpBar.style.transition = 'width 0.7s cubic-bezier(.68,-0.55,.27,1.55)';
        xpBar.style.width = '100%';
        xpText.textContent = `${oldLevel * 100} / ${oldLevel * 100} XP`;
        setTimeout(() => {
            // 2. Flash/glow
            xpBar.classList.add('xp-bar-glow');
            setTimeout(() => {
                xpBar.classList.remove('xp-bar-glow');
                // 3. Reset à 0%
                xpBar.style.transition = 'none';
                xpBar.style.width = '0%';
                xpText.textContent = `0 / ${newLevel * 100} XP`;
                // 4. Remplir jusqu'à la nouvelle valeur
                setTimeout(() => {
                    xpBar.style.transition = 'width 0.7s cubic-bezier(.68,-0.55,.27,1.55)';
                    const percent = Math.round((newXP / (newLevel * 100)) * 100);
                    xpBar.style.width = percent + '%';
                    xpText.textContent = `${newXP} / ${newLevel * 100} XP`;
                }, 100);
            }, 250);
        }, 700);
    },
    
    animateBadgeEarned(badge) {
        // Animation spéciale pour le badge obtenu
        const badgeEl = document.querySelector(`[title="${badge.description}"]`);
        if (badgeEl) {
            badgeEl.style.transform = 'scale(1.5) rotate(360deg)';
            badgeEl.style.boxShadow = '0 0 30px rgba(1, 196, 255, 0.8)';
            setTimeout(() => {
                badgeEl.style.transform = 'scale(1) rotate(0deg)';
                badgeEl.style.boxShadow = '0 4px 12px rgba(1, 196, 255, 0.2)';
            }, 800);
        }
        // Afficher un toast animé
        showBadgeToast(badge);
    }
};

// Intégration avec les actions existantes
document.addEventListener('DOMContentLoaded', function() {
    RewardSystem.init();
});

// Hooks pour les actions qui donnent des points
const originalToggleTache = toggleTache;
toggleTache = async function(id) {
    const result = await originalToggleTache(id);
    if (result) {
        RewardSystem.addPoints(10, 'Tâche complétée');
        RewardSystem.checkAchievements();
    }
    return result;
};

// === Système de classement en temps réel ===
const LeaderboardSystem = {
    leaderboard: [],
    userPosition: null,
    updateInterval: null,
    
    // Initialisation
    init() {
        this.loadLeaderboard();
        this.startAutoUpdate();
    },
    
    // Charger le classement
    async loadLeaderboard() {
        try {
            const token = getAuthToken();
            if (!token) return;
            
            const response = await apiCall('/rewards/leaderboard', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.success) {
                this.leaderboard = response.data;
                this.calculateUserPosition();
                this.renderLeaderboard();
                this.updateStats();
            }
        } catch (error) {
            console.error('Erreur chargement classement:', error);
            this.showErrorState();
        }
    },
    
    // Calculer la position de l'utilisateur
    calculateUserPosition() {
        const currentUser = EtatApp.utilisateur;
        if (!currentUser) return;
        
        const userIndex = this.leaderboard.findIndex(item => 
            item.userId._id === currentUser._id
        );
        
        this.userPosition = userIndex !== -1 ? userIndex + 1 : null;
    },
    
    // Afficher le classement
    renderLeaderboard() {
        const list = document.getElementById('leaderboard-list');
        const positionBadge = document.getElementById('user-position-badge');
        const positionRank = document.getElementById('user-position-rank');
        
        if (!list) return;
        
        // Afficher la position de l'utilisateur
        if (positionBadge && positionRank) {
            if (this.userPosition) {
                positionBadge.textContent = this.userPosition;
                positionRank.textContent = `${this.userPosition}${this.getOrdinalSuffix(this.userPosition)}`;
                
                // Couleur selon la position
                if (this.userPosition === 1) {
                    positionBadge.style.background = 'linear-gradient(135deg, #fbbf24, #f59e0b)';
                } else if (this.userPosition <= 3) {
                    positionBadge.style.background = 'linear-gradient(135deg, #9ca3af, #6b7280)';
                } else {
                    positionBadge.style.background = 'linear-gradient(135deg, rgb(1, 196, 255), rgba(79, 70, 229, 0.8))';
                }
            } else {
                positionBadge.textContent = '--';
                positionRank.textContent = 'Non classé';
                positionBadge.style.background = 'rgba(255, 255, 255, 0.2)';
            }
        }
        
        // Afficher le top 10
        if (this.leaderboard.length === 0) {
            list.innerHTML = '<div class="loading-leaderboard">Aucun participant pour le moment</div>';
            return;
        }
        
        const currentUser = EtatApp.utilisateur;
        list.innerHTML = this.leaderboard.slice(0, 10).map((item, index) => {
            const rank = index + 1;
            const isCurrentUser = currentUser && item.userId._id === currentUser._id;
            const rankClass = rank === 1 ? 'rank-1' : rank === 2 ? 'rank-2' : rank === 3 ? 'rank-3' : 'rank-other';
            const userClass = isCurrentUser ? 'current-user' : '';
            // Affichage de la photo de profil si elle existe, sinon initiales
            let avatarHtml = '';
            if (item.userId.avatar && (item.userId.avatar.startsWith('data:image') || item.userId.avatar.startsWith('http://') || item.userId.avatar.startsWith('https://'))) {
                avatarHtml = `<img src="${item.userId.avatar}" alt="Photo de profil" class="user-avatar" style="object-fit:cover;" />`;
            } else {
                avatarHtml = `<div class="user-avatar">${this.getUserInitials(item.userId.username)}</div>`;
            }
            return `
                <div class="leaderboard-item ${userClass}">
                    <div class="rank-number ${rankClass}">${rank}</div>
                    ${avatarHtml}
                    <div class="user-info">
                        <div class="user-name">${item.userId.username}</div>
                        <div class="user-level">Niveau ${item.level}</div>
                    </div>
                    <div class="user-points">${item.points} pts</div>
                </div>
            `;
        }).join('');
    },
    
    // Mettre à jour les statistiques
    updateStats() {
        const totalParticipants = document.getElementById('total-participants');
        const avgPoints = document.getElementById('avg-points');
        
        if (totalParticipants) {
            totalParticipants.textContent = this.leaderboard.length;
        }
        
        if (avgPoints && this.leaderboard.length > 0) {
            const totalPoints = this.leaderboard.reduce((sum, item) => sum + item.points, 0);
            const average = Math.round(totalPoints / this.leaderboard.length);
            avgPoints.textContent = average;
        }
    },
    
    // Obtenir les initiales d'un utilisateur
    getUserInitials(username) {
        if (!username) return '?';
        return username.split(' ').map(name => name.charAt(0).toUpperCase()).join('').slice(0, 2);
    },
    
    // Obtenir le suffixe ordinal
    getOrdinalSuffix(num) {
        if (num >= 11 && num <= 13) return 'ème';
        switch (num % 10) {
            case 1: return 'er';
            case 2: return 'ème';
            case 3: return 'ème';
            default: return 'ème';
        }
    },
    
    // Afficher l'état d'erreur
    showErrorState() {
        const list = document.getElementById('leaderboard-list');
        if (list) {
            list.innerHTML = '<div class="loading-leaderboard">Erreur de chargement du classement</div>';
        }
    },
    
    // Démarrer la mise à jour automatique
    startAutoUpdate() {
        // Mettre à jour toutes les 30 secondes
        this.updateInterval = setInterval(() => {
            this.loadLeaderboard();
        }, 30000);
    },
    
    // Arrêter la mise à jour automatique
    stopAutoUpdate() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    },
    
    // Forcer une mise à jour
    forceUpdate() {
        this.loadLeaderboard();
    }
};

// Initialisation du classement
document.addEventListener('DOMContentLoaded', function() {
    LeaderboardSystem.init();
});

// Mettre à jour le classement quand les points changent
const originalAddPoints = RewardSystem.addPoints;
RewardSystem.addPoints = async function(points, reason) {
    const result = await originalAddPoints(points, reason);
    if (result) {
        // Mettre à jour le classement après un gain de points
        setTimeout(() => {
            LeaderboardSystem.forceUpdate();
        }, 1000);
    }
    return result;
};

// --- Pomodoro Modal Logic ---
const pomodoroEncouragements = [
  "C'est parti ! Reste focus, tu vas y arriver !",
  "Chaque minute compte, tu construis ta réussite !",
  "Continue, tu es sur la bonne voie !",
  "Garde le rythme, la victoire est proche !",
  "Plus que quelques minutes, ne lâche rien !",
  "Bravo, tu gagnes en discipline à chaque session !",
  "Visualise ta réussite, tu avances !",
  "Ta concentration est ta super-puissance !",
  "Chaque Pomodoro te rapproche de tes objectifs !"
];
let pomodoroTimer = null;
let pomodoroTotalSeconds = 25 * 60;
let pomodoroSecondsLeft = 25 * 60;
let pomodoroPaused = false;

async function openPomodoroModal() {
  try {
    document.getElementById('pomodoro-modal').style.display = 'flex';
    document.body.classList.add('pomodoro-immersive');
    document.body.style.overflow = 'hidden';
    if (!EtatApp.matieres || !EtatApp.matieres.length) {
      await chargerMatieresDepuisAPI();
    }
    loadPomodoroMatieres();
    const dureeInput = document.getElementById('pomodoro-duree');
    if (dureeInput) dureeInput.value = 25;
    pomodoroTotalSeconds = 25 * 60;
    pomodoroSecondsLeft = pomodoroTotalSeconds;
    pomodoroPaused = false;
    updatePomodoroTimerDisplay();
    document.getElementById('pomodoro-start-btn').style.display = '';
    document.getElementById('pomodoro-pause-btn').style.display = 'none';
    document.getElementById('pomodoro-resume-btn').style.display = 'none';
    document.getElementById('pomodoro-reset-btn').style.display = 'none';
    showPomodoroCheck(false);
  } catch (e) {
    showFeedback('Erreur lors de l\'ouverture du Pomodoro : ' + (e.message || e), 'error', 6000);
    console.error('Erreur Pomodoro:', e);
  }
}

function closePomodoroSection() {
  document.getElementById('pomodoro-modal').style.display = 'none';
  document.body.classList.remove('pomodoro-immersive');
  document.body.style.overflow = 'auto';
  clearInterval(pomodoroTimer);
}

function updatePomodoroEncouragement(anim) {
  const el = document.getElementById('pomodoro-encouragement');
  if (el) {
    el.textContent = pomodoroEncouragements[Math.floor(Math.random() * pomodoroEncouragements.length)];
    if (anim) {
      el.classList.remove('pomodoro-encouragement-anim');
      void el.offsetWidth;
      el.classList.add('pomodoro-encouragement-anim');
    }
  }
}

function loadPomodoroMatieres() {
  const select = document.getElementById('pomodoro-matiere');
  select.innerHTML = '';
  if (EtatApp.matieres && EtatApp.matieres.length) {
    EtatApp.matieres.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m._id;
      opt.textContent = m.name;
      select.appendChild(opt);
    });
  } else {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Aucune matière';
    select.appendChild(opt);
  }
}

function updatePomodoroTimerDisplay() {
  const min = Math.floor(pomodoroSecondsLeft / 60).toString().padStart(2, '0');
  const sec = (pomodoroSecondsLeft % 60).toString().padStart(2, '0');
  document.getElementById('pomodoro-timer-text').textContent = `${min}:${sec}`;
  // Animation cercle SVG
  if (pomodoroTotalSeconds > 0) {
    const percent = 1 - (pomodoroSecondsLeft / pomodoroTotalSeconds);
    updatePomodoroProgressRing(percent);
  }
  // Flash anim
  if (pomodoroSecondsLeft % 60 === 0 && pomodoroSecondsLeft !== pomodoroTotalSeconds) {
    const flash = document.getElementById('pomodoro-anim-flash');
    if (flash) {
      flash.style.opacity = '0.5';
      setTimeout(() => { flash.style.opacity = '0'; }, 400);
    }
    updatePomodoroEncouragement(true);
  }
}

function startPomodoroSession() {
  console.log("DEBUG: startPomodoroSession appelée !");
  // Récupérer durée personnalisée
  const duree = parseInt(document.getElementById('pomodoro-duree').value, 10) || 25;
  console.log("DEBUG: durée saisie:", duree);
  pomodoroTotalSeconds = duree * 60;
  pomodoroSecondsLeft = pomodoroTotalSeconds;
  pomodoroPaused = false;
  document.getElementById('pomodoro-start-btn').style.display = 'none';
  document.getElementById('pomodoro-pause-btn').style.display = '';
  document.getElementById('pomodoro-resume-btn').style.display = 'none';
  document.getElementById('pomodoro-reset-btn').style.display = '';
  updatePomodoroTimerDisplay();
  showPomodoroCheck(false);
  clearInterval(pomodoroTimer);
  // --- Animation subtile top départ ---
  const timerAnim = document.getElementById('pomodoro-timer-anim');
  if (timerAnim) {
    timerAnim.classList.remove('pomodoro-flash-start');
    void timerAnim.offsetWidth;
    timerAnim.classList.add('pomodoro-flash-start');
    setTimeout(() => timerAnim.classList.remove('pomodoro-flash-start'), 600);
  }
  pomodoroTimer = setInterval(() => {
    if (!pomodoroPaused && pomodoroSecondsLeft > 0) {
      pomodoroSecondsLeft--;
      updatePomodoroTimerDisplay();
      if (pomodoroSecondsLeft % 60 === 0) updatePomodoroEncouragement();
      if (pomodoroSecondsLeft === 0) {
        clearInterval(pomodoroTimer);
        onPomodoroSessionEnd();
        if (window.navigator && window.navigator.vibrate) {
          window.navigator.vibrate([200, 100, 200]);
        }
      }
    }
  }, 1000);
}
window.startPomodoroSession = startPomodoroSession;

function pausePomodoroSession() {
  pomodoroPaused = true;
  document.getElementById('pomodoro-pause-btn').style.display = 'none';
  document.getElementById('pomodoro-resume-btn').style.display = '';
}

function resumePomodoroSession() {
  pomodoroPaused = false;
  document.getElementById('pomodoro-pause-btn').style.display = '';
  document.getElementById('pomodoro-resume-btn').style.display = 'none';
}

function resetPomodoroSession() {
  clearInterval(pomodoroTimer);
  pomodoroPaused = false;
  const duree = parseInt(document.getElementById('pomodoro-duree').value, 10) || 25;
  pomodoroTotalSeconds = duree * 60;
  pomodoroSecondsLeft = pomodoroTotalSeconds;
  document.getElementById('pomodoro-start-btn').style.display = '';
  document.getElementById('pomodoro-pause-btn').style.display = 'none';
  document.getElementById('pomodoro-resume-btn').style.display = 'none';
  document.getElementById('pomodoro-reset-btn').style.display = 'none';
  updatePomodoroTimerDisplay();
  updatePomodoroEncouragement();
  showPomodoroCheck(false);
}

function onPomodoroSessionEnd() {
  updatePomodoroProgressRing(1);
  showPomodoroCheck(true);
  enregistrerSessionPomodoroModal();
  showFeedback('Bravo ! Session terminée 🎉', 'success');
  setTimeout(closePomodoroSection, 2000);
}

// Ouvre la modale depuis le dashboard
// Remplace l'appel à demarrerPomodoroAccueil dans le bouton
window.openPomodoroModal = openPomodoroModal;

// Enregistrement de la session Pomodoro personnalisée
async function enregistrerSessionPomodoroModal() {
  const token = getAuthToken();
  const duration = Math.round(pomodoroTotalSeconds / 60);
  const subjectId = document.getElementById('pomodoro-matiere').value || null;
  const notes = document.getElementById('pomodoro-note').value || null;
  try {
    const response = await fetch(`${API_BASE_URL}/pomodoro-sessions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        duration,
        sessionType: 'focus',
        subjectId,
        notes
      })
    });
    const data = await response.json();
    if (data.success) {
      // Afficher le message d'encouragement personnalisé
      showFeedback(data.message || 'Session Pomodoro enregistrée !', 'success', 5000);
      // Animation '+10 points' et shake/flash du timer
      animatePomodoroPoints(10);
      const timerAnim = document.getElementById('pomodoro-timer-anim');
      if (timerAnim) {
        timerAnim.classList.add('pomodoro-timer-shake');
        setTimeout(() => timerAnim.classList.remove('pomodoro-timer-shake'), 600);
        timerAnim.classList.add('pomodoro-timer-flash');
        setTimeout(() => timerAnim.classList.remove('pomodoro-timer-flash'), 600);
      }
      // Mettre à jour les points, niveau, XP, sessions terminées
      if (data.reward) {
        document.getElementById('user-points').textContent = data.reward.points;
        document.getElementById('user-level').textContent = 'Niveau ' + data.reward.level;
        animateXPBar(data.reward.xp, data.reward.level);
      }
      // Rafraîchir les stats et le leaderboard
      if (typeof mettreAJourStatsDashboard === 'function') mettreAJourStatsDashboard();
      if (LeaderboardSystem && typeof LeaderboardSystem.forceUpdate === 'function') LeaderboardSystem.forceUpdate();
    } else {
      showFeedback(data.message || 'Erreur lors de l\'enregistrement', 'error');
    }
  } catch (e) {
    showFeedback('Erreur réseau lors de l\'enregistrement', 'error');
  }
}

// ... existing code ...

function animatePomodoroPoints(points) {
  let anim = document.getElementById('pomodoro-points-anim');
  if (!anim) {
    anim = document.createElement('div');
    anim.id = 'pomodoro-points-anim';
    document.getElementById('pomodoro-timer-anim').appendChild(anim);
  }
  anim.textContent = `+${points}`;
  anim.style.opacity = 1;
  anim.classList.remove('pointsPop');
  void anim.offsetWidth;
  anim.classList.add('pointsPop');
  setTimeout(() => { anim.style.opacity = 0; }, 1200);
}

function animateXPBar(xp, level) {
  const xpBar = document.getElementById('xp-progress-bar');
  if (xpBar) {
    const percent = Math.round((xp / (level * 100)) * 100);
    xpBar.style.transition = 'width 1s cubic-bezier(.68,-0.55,.27,1.55)';
    xpBar.style.width = percent + '%';
    setTimeout(() => { xpBar.style.transition = ''; }, 1200);
  }
}

// Recharge l'historique Pomodoro et les points utilisateur depuis l'API
async function chargerStatsUtilisateur() {
    const token = getAuthToken();
    if (!token) return;
    try {
        // Charger l'historique des sessions Pomodoro
        const resPomo = await fetch(`${API_BASE_URL}/pomodoro-sessions`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const dataPomo = await resPomo.json();
        if (dataPomo.success) {
            EtatApp.historiquePomo = dataPomo.data || [];
        }
        // Charger le profil utilisateur (pour les points, XP, etc.)
        const resUser = await fetch(`${API_BASE_URL}/profile`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const dataUser = await resUser.json();
        if (dataUser.success) {
            EtatApp.utilisateur = dataUser.data;
        }
        mettreAJourStatsDashboard();
    } catch (e) {
        console.error('Erreur de synchronisation stats:', e);
    }
}

// ===== PWA ET FULLSCREEN =====

// Gestionnaire PWA
const PWA = {
    deferredPrompt: null,
    isInstalled: false,
    
    // Initialisation PWA
    init() {
        console.log('🚀 [PWA] Initialisation...');
        
        // Écouter l'événement beforeinstallprompt
        window.addEventListener('beforeinstallprompt', (e) => {
            console.log('📱 [PWA] Prompt d\'installation disponible');
            e.preventDefault();
            this.deferredPrompt = e;
            this.showInstallButton();
        });
        
        // Écouter l'événement appinstalled
        window.addEventListener('appinstalled', (e) => {
            console.log('✅ [PWA] App installée avec succès');
            this.isInstalled = true;
            this.hideInstallButton();
            showFeedback('ApTe installé avec succès ! 🎉', 'success');
        });
        
        // Vérifier si l'app est déjà installée
        if (window.matchMedia('(display-mode: standalone)').matches || 
            window.navigator.standalone === true) {
            console.log('📱 [PWA] App déjà installée');
            this.isInstalled = true;
        }
        
        // Enregistrer le service worker
        this.registerServiceWorker();
    },
    
    // Enregistrer le service worker
    async registerServiceWorker() {
        if ('serviceWorker' in navigator) {
            try {
                const registration = await navigator.serviceWorker.register('/sw.js');
                console.log('✅ [PWA] Service worker enregistré:', registration);
                
                // Écouter les mises à jour
                registration.addEventListener('updatefound', () => {
                    const newWorker = registration.installing;
                    newWorker.addEventListener('statechange', () => {
                        if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                            this.showUpdateNotification();
                        }
                    });
                });
                
            } catch (error) {
                console.error('❌ [PWA] Erreur enregistrement SW:', error);
            }
        }
    },
    
    // Afficher le bouton d'installation
    showInstallButton() {
        const installBtn = document.getElementById('pwa-install-btn');
        if (installBtn) {
            installBtn.style.display = 'block';
            installBtn.addEventListener('click', () => this.installApp());
        }
    },
    
    // Cacher le bouton d'installation
    hideInstallButton() {
        const installBtn = document.getElementById('pwa-install-btn');
        if (installBtn) {
            installBtn.style.display = 'none';
        }
    },
    
    // Installer l'app
    async installApp() {
        if (!this.deferredPrompt) {
            console.log('❌ [PWA] Pas de prompt d\'installation disponible');
            return;
        }
        
        console.log('📱 [PWA] Lancement de l\'installation...');
        this.deferredPrompt.prompt();
        
        const { outcome } = await this.deferredPrompt.userChoice;
        console.log('📱 [PWA] Résultat installation:', outcome);
        
        this.deferredPrompt = null;
        this.hideInstallButton();
    },
    
    // Afficher notification de mise à jour
    showUpdateNotification() {
        const updateBtn = document.createElement('button');
        updateBtn.textContent = '🔄 Mettre à jour ApTe';
        updateBtn.className = 'btn-update-pwa';
        updateBtn.onclick = () => this.updateApp();
        
        document.body.appendChild(updateBtn);
        
        setTimeout(() => {
            if (document.body.contains(updateBtn)) {
                document.body.removeChild(updateBtn);
            }
        }, 10000);
    },
    
    // Mettre à jour l'app
    updateApp() {
        if (navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({ type: 'SKIP_WAITING' });
            window.location.reload();
        }
    }
};

// Gestionnaire Fullscreen
const FullscreenManager = {
    isFullscreen: false,
    
    // Initialisation
    init() {
        console.log('🖥️ [Fullscreen] Initialisation...');
        
        // Écouter les changements de fullscreen
        document.addEventListener('fullscreenchange', () => {
            this.isFullscreen = !!document.fullscreenElement;
            console.log('🖥️ [Fullscreen] État changé:', this.isFullscreen);
            this.updateUI();
        });
        
        // Écouter les erreurs fullscreen
        document.addEventListener('fullscreenerror', (e) => {
            console.error('❌ [Fullscreen] Erreur:', e);
            showFeedback('Impossible d\'activer le plein écran', 'error');
        });
    },
    
    // Demander le plein écran
    async requestFullscreen() {
        try {
            console.log('🖥️ [Fullscreen] Demande de plein écran...');
            
            if (document.documentElement.requestFullscreen) {
                await document.documentElement.requestFullscreen();
            } else if (document.documentElement.webkitRequestFullscreen) {
                await document.documentElement.webkitRequestFullscreen();
            } else if (document.documentElement.msRequestFullscreen) {
                await document.documentElement.msRequestFullscreen();
            }
            
            console.log('✅ [Fullscreen] Plein écran activé');
            showFeedback('Mode plein écran activé 🖥️', 'success');
            
        } catch (error) {
            console.error('❌ [Fullscreen] Erreur:', error);
            showFeedback('Erreur plein écran', 'error');
        }
    },
    
    // Sortir du plein écran
    async exitFullscreen() {
        try {
            console.log('🖥️ [Fullscreen] Sortie du plein écran...');
            
            if (document.exitFullscreen) {
                await document.exitFullscreen();
            } else if (document.webkitExitFullscreen) {
                await document.webkitExitFullscreen();
            } else if (document.msExitFullscreen) {
                await document.msExitFullscreen();
            }
            
            console.log('✅ [Fullscreen] Plein écran désactivé');
            
        } catch (error) {
            console.error('❌ [Fullscreen] Erreur:', error);
        }
    },
    
    // Toggle plein écran
    async toggleFullscreen() {
        if (this.isFullscreen) {
            await this.exitFullscreen();
        } else {
            await this.requestFullscreen();
        }
    },
    
    // Mettre à jour l'interface
    updateUI() {
        const fullscreenBtn = document.getElementById('fullscreen-btn');
        if (fullscreenBtn) {
            fullscreenBtn.textContent = this.isFullscreen ? '⛶' : '⛶';
            fullscreenBtn.title = this.isFullscreen ? 'Quitter le plein écran' : 'Plein écran';
        }
    }
};

// Fonctions globales pour l'interface
window.toggleFullscreen = () => FullscreenManager.toggleFullscreen();
window.installPWA = () => PWA.installApp();
window.updatePWA = () => PWA.updateApp();

// Initialisation au chargement de la page
document.addEventListener('DOMContentLoaded', () => {
    // Initialiser PWA et Fullscreen après le chargement
    setTimeout(() => {
        PWA.init();
        FullscreenManager.init();
    }, 1000);
});

// ===== FIN PWA ET FULLSCREEN =====

// Empêche le submit/reload du formulaire Pomodoro

document.addEventListener('DOMContentLoaded', function() {
  const pomodoroForm = document.querySelector('.pomodoro-form');
  if (pomodoroForm) {
    pomodoroForm.addEventListener('submit', function(e) {
      e.preventDefault();
      return false;
    });
  }
});

// Ajouté : met à jour l'arc de progression du timer SVG Pomodoro
function updatePomodoroProgressRing(percent) {
  const ring = document.getElementById('pomodoro-progress-ring');
  if (!ring) return;
  const radius = ring.r.baseVal.value;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - percent);
  ring.style.strokeDasharray = `${circumference} ${circumference}`;
  ring.style.strokeDashoffset = offset;
}

// Affiche ou masque le check animé dans le timer Pomodoro
function showPomodoroCheck(show) {
  const group = document.getElementById('pomodoro-check-group');
  if (group) {
    group.style.opacity = show ? '1' : '0';
    group.style.transition = 'opacity 0.5s';
  }
}

// Toast animé pour badge
function showBadgeToast(badge) {
    // Supprimer l'ancien toast s'il existe
    const old = document.getElementById('badge-toast');
    if (old) old.remove();
    const toast = document.createElement('div');
    toast.id = 'badge-toast';
    toast.className = 'badge-toast';
    toast.innerHTML = `
        <div class="badge-toast-icon">${badge.icon}</div>
        <div class="badge-toast-content">
            <div class="badge-toast-title">Nouveau badge débloqué !</div>
            <div class="badge-toast-name">${badge.name}</div>
            <div class="badge-toast-desc">${badge.description}</div>
        </div>
    `;
    document.body.appendChild(toast);
    setTimeout(() => { toast.classList.add('show'); }, 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 500);
    }, 4000);
}

// ... existing code ...
window.seDeconnecter = seDeconnecter;
// ... existing code ...