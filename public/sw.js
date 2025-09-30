// sw.js
const CACHE_NAME = 'waze-like-app-v1.0.4';
const urlsToCache = [
  '/',
  '/index.html',
  '/icon.png',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css',
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js',
  'https://cdn.socket.io/4.7.5/socket.io.min.js',
  'https://maps.googleapis.com/maps/api/js?key=AIzaSyBSW8iQAE1AjjouEu4df-Cvq1ceUMLBit4&map_ids=2666b5bd496d9c6026f43f82&v=beta&libraries=places,geometry,marker,routes&loading=async'
];

// Install event: Cache essential assets
self.addEventListener('install', event => {
  console.log('[Service Worker] Installing service worker...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[Service Worker] Caching app shell and assets');
        return cache.addAll(urlsToCache);
      })
      .then(() => {
        console.log('[Service Worker] Cache populated successfully');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('[Service Worker] Cache population failed:', error);
      })
  );
});

// Activate event: Clean up old caches
self.addEventListener('activate', event => {
  console.log('[Service Worker] Activating service worker...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('[Service Worker] Deleting outdated cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      console.log('[Service Worker] Claiming clients');
      return self.clients.claim();
    })
  );
});

// Fetch event: Serve cached assets or fetch from network
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  console.log('[Service Worker] Fetching:', url.pathname);

  // Bypass service worker for API calls and WebSocket connections
  if (url.pathname.startsWith('/api/') || url.pathname === '/socket.io/') {
    console.log('[Service Worker] Bypassing cache for:', url.pathname);
    event.respondWith(fetch(event.request).catch(error => {
      console.error('[Service Worker] Fetch failed for API/WebSocket:', error);
      return new Response(JSON.stringify({ error: 'Network unavailable' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }));
    return;
  }

  // Cache-first strategy for static assets
  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      if (cachedResponse) {
        console.log('[Service Worker] Serving from cache:', url.pathname);
        return cachedResponse;
      }
      console.log('[Service Worker] Fetching from network:', url.pathname);
      return fetch(event.request).then(networkResponse => {
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
          return networkResponse;
        }
        const responseToCache = networkResponse.clone();
        caches.open(CACHE_NAME).then(cache => {
          cache.put(event.request, responseToCache);
          console.log('[Service Worker] Cached network response:', url.pathname);
        });
        return networkResponse;
      }).catch(error => {
        console.error('[Service Worker] Fetch failed:', error);
        return new Response('Offline and no cache available', { status: 503 });
      });
    })
  );
});

// Push event: Handle push notifications for alerts
self.addEventListener('push', event => {
  console.log('[Service Worker] Push event received');
  let data = { title: 'Alert', body: 'New alert received' };
  if (event.data) {
    try {
      data = event.data.json();
      console.log('[Service Worker] Push data:', data);
    } catch (error) {
      console.error('[Service Worker] Error parsing push data:', error);
    }
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icon.png',
      badge: '/icon.png',
      data: {
        alertId: data.alertId,
        lat: data.lat,
        lng: data.lng
      }
    }).then(() => {
      console.log('[Service Worker] Notification shown:', data.title);
    }).catch(error => {
      console.error('[Service Worker] Notification error:', error);
    })
  );
});

// Notification click event: Focus or open app with alert details
self.addEventListener('notificationclick', event => {
  console.log('[Service Worker] Notification clicked:', event.notification.data);
  event.notification.close();
  const { alertId, lat, lng } = event.notification.data || {};
  const url = alertId ? `/?alertId=${alertId}&lat=${lat}&lng=${lng}` : '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      console.log('[Service Worker] Clients found:', clientList.length);
      for (const client of clientList) {
        if (client.url.includes('wazelikeapp.onrender.com') && 'focus' in client) {
          console.log('[Service Worker] Focusing existing client:', client.url);
          client.focus();
          client.postMessage({ type: 'NAVIGATE', url });
          return;
        }
      }
      if (clients.openWindow) {
        console.log('[Service Worker] Opening new window:', url);
        return clients.openWindow(url);
      }
    }).catch(error => {
      console.error('[Service Worker] Error handling notification click:', error);
    })
  );
});

// Message event: Handle messages from index.html
self.addEventListener('message', event => {
  console.log('[Service Worker] Message received:', event.data);
  if (event.data.type === 'INIT') {
    console.log('[Service Worker] Initialization message received');
  } else if (event.data.type === 'SHOW_NOTIFICATION') {
    self.registration.showNotification(event.data.title, {
      body: event.data.body,
      icon: '/icon.png',
      badge: '/icon.png',
      data: {
        alertId: event.data.alertId,
        lat: event.data.lat,
        lng: event.data.lng
      }
    }).then(() => {
      console.log('[Service Worker] Client-initiated notification shown:', event.data.title);
    }).catch(error => {
      console.error('[Service Worker] Client-initiated notification error:', error);
    });
  }
});