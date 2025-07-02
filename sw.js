const CACHE_NAME = 'apte-v1.0.0';
const urlsToCache = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/libs/chart.umd.min.js',
  '/icons/google.svg',
  '/icons/icon-192x192.png',
  '/icons/icon-512x512.png'
];

// Installation du service worker
self.addEventListener('install', event => {
  console.log('🚀 [SW] Installation du service worker...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('📦 [SW] Cache ouvert');
        return cache.addAll(urlsToCache);
      })
      .then(() => {
        console.log('✅ [SW] Toutes les ressources mises en cache');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('❌ [SW] Erreur lors de l\'installation:', error);
      })
  );
});

// Activation du service worker
self.addEventListener('activate', event => {
  console.log('🔄 [SW] Activation du service worker...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('🗑️ [SW] Suppression de l\'ancien cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      console.log('✅ [SW] Service worker activé');
      return self.clients.claim();
    })
  );
});

// Interception des requêtes réseau
self.addEventListener('fetch', event => {
  // Ignorer les requêtes non-GET
  if (event.request.method !== 'GET') {
    return;
  }

  // Ignorer les requêtes vers l'API backend
  if (event.request.url.includes('/api/') || event.request.url.includes('/auth/')) {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Retourner la réponse du cache si elle existe
        if (response) {
          console.log('📦 [SW] Ressource trouvée en cache:', event.request.url);
          return response;
        }

        // Sinon, faire la requête réseau
        console.log('🌐 [SW] Requête réseau:', event.request.url);
        return fetch(event.request)
          .then(response => {
            // Vérifier que la réponse est valide
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }

            // Cloner la réponse pour la mettre en cache
            const responseToCache = response.clone();
            caches.open(CACHE_NAME)
              .then(cache => {
                cache.put(event.request, responseToCache);
                console.log('💾 [SW] Nouvelle ressource mise en cache:', event.request.url);
              });

            return response;
          })
          .catch(error => {
            console.error('❌ [SW] Erreur réseau:', error);
            
            // Pour les pages HTML, retourner une page d'erreur offline
            if (event.request.destination === 'document') {
              return caches.match('/offline.html');
            }
          });
      })
  );
});

// Gestion des messages du client
self.addEventListener('message', event => {
  console.log('📨 [SW] Message reçu:', event.data);
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'GET_VERSION') {
    event.ports[0].postMessage({ version: CACHE_NAME });
  }
});

// Gestion des notifications push (pour le futur)
self.addEventListener('push', event => {
  console.log('🔔 [SW] Notification push reçue');
  
  const options = {
    body: event.data ? event.data.text() : 'Nouvelle notification ApTe',
    icon: '/icons/icon-192x192.png',
    badge: '/icons/icon-72x72.png',
    vibrate: [100, 50, 100],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    },
    actions: [
      {
        action: 'explore',
        title: 'Voir',
        icon: '/icons/icon-72x72.png'
      },
      {
        action: 'close',
        title: 'Fermer',
        icon: '/icons/icon-72x72.png'
      }
    ]
  };

  event.waitUntil(
    self.registration.showNotification('ApTe ⚡', options)
  );
});

// Gestion des clics sur les notifications
self.addEventListener('notificationclick', event => {
  console.log('👆 [SW] Clic sur notification:', event.action);
  
  event.notification.close();

  if (event.action === 'explore') {
    event.waitUntil(
      clients.openWindow('/')
    );
  }
}); 