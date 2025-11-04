const CACHE_VERSION = 'v1.0.21'; // ← Increment this on every deploy
const CACHE_NAME = `waze-gps-${CACHE_VERSION}`;
const CACHE_SIZE_LIMIT = 50; // max entries
const RUNTIME_CACHE = `runtime-${CACHE_VERSION}`;

// ✅ NEW: Separate caches for different asset types
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/manifest.json',
  '/admin.html', // ← Add if you have this page
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css',
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js',
  'https://cdn.socket.io/4.7.5/socket.io.min.js' // ← Already in your HTML
];

// ✅ NEW: URLs to never cache (dynamic APIs)
const NEVER_CACHE = [
  '/api/',
  'socket.io',
  'maps.googleapis.com',
  'firebaseinstallations.googleapis.com', // Push notifications
  'fcm.googleapis.com' // Firebase Cloud Messaging
];

// Limit cache size
async function limitCacheSize(cacheName, maxItems) {
  const cache = await caches.open(cacheName);
  const keys = await cache.keys();
  
  if (keys.length > maxItems) {
    const excess = keys.slice(0, keys.length - maxItems);
    await Promise.all(excess.map(key => cache.delete(key)));
    console.log(`🗑️ Evicted ${excess.length} old cache entries from ${cacheName}`);
  }
}

// ✅ NEW: Check if URL should bypass cache
function shouldBypassCache(url) {
  return NEVER_CACHE.some(pattern => url.includes(pattern));
}

// Install - Cache core assets
self.addEventListener('install', event => {
  console.log('📦 Installing Service Worker', CACHE_VERSION);
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('💾 Caching core assets');
        return cache.addAll(ASSETS_TO_CACHE);
      })
      .then(() => self.skipWaiting()) // Force new SW to activate immediately
      .catch(err => console.error('❌ Install failed:', err))
  );
});

// Activate - Delete old caches
self.addEventListener('activate', event => {
  console.log('✅ Activating Service Worker', CACHE_VERSION);
  event.waitUntil(
    caches.keys()
      .then(keys => {
        const oldCaches = keys.filter(key => 
          key.startsWith('waze-gps-') && key !== CACHE_NAME ||
          key.startsWith('runtime-') && key !== RUNTIME_CACHE
        );
        
        console.log('🗑️ Deleting old caches:', oldCaches);
        return Promise.all(oldCaches.map(key => caches.delete(key)));
      })
      .then(() => {
        console.log('🎯 Service Worker now controlling all clients');
        return self.clients.claim(); // Take control of all clients immediately
      })
  );
});

// ✅ NEW: Improved fetch strategy with better error handling
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  
  // Skip caching for non-GET requests
  if (event.request.method !== 'GET') {
    return;
  }
  
  // Always bypass cache for dynamic APIs
  if (shouldBypassCache(url.href)) {
    event.respondWith(
      fetch(event.request)
        .catch(() => {
          // Return offline indicator for API calls
          if (url.pathname.startsWith('/api/')) {
            return new Response(JSON.stringify({ 
              error: 'Offline', 
              offline: true,
              message: 'No internet connection'
            }), {
              status: 503,
              headers: { 'Content-Type': 'application/json' }
            });
          }
          throw new Error('Network request failed');
        })
    );
    return;
  }

  // Network-first for HTML (always fetch fresh, fallback to cache)
  if (event.request.destination === 'document' || 
      event.request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(
      fetch(event.request, { cache: 'no-cache' }) // Force network check
        .then(async response => {
          if (response.ok) {
            const clone = response.clone();
            const cache = await caches.open(CACHE_NAME);
            await cache.put(event.request, clone);
            console.log('📄 Cached HTML:', url.pathname);
          }
          return response;
        })
        .catch(async () => {
          console.warn('🌐 Offline - serving cached HTML:', url.pathname);
          const cached = await caches.match(event.request);
          return cached || new Response(
            `<!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Offline</title>
              <style>
                body {
                  font-family: Arial, sans-serif;
                  display: flex;
                  flex-direction: column;
                  align-items: center;
                  justify-content: center;
                  height: 100vh;
                  margin: 0;
                  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                  color: white;
                }
                h1 { font-size: 3rem; margin-bottom: 1rem; }
                button {
                  background: white;
                  color: #667eea;
                  border: none;
                  padding: 1rem 2rem;
                  border-radius: 0.5rem;
                  font-size: 1rem;
                  cursor: pointer;
                  margin-top: 2rem;
                }
                button:hover { opacity: 0.9; }
              </style>
            </head>
            <body>
              <h1>📡 You're Offline</h1>
              <p>Check your internet connection to use this app</p>
              <button onclick="location.reload()">🔄 Retry</button>
            </body>
            </html>`,
            { headers: { 'Content-Type': 'text/html' } }
          );
        })
    );
    return;
  }

  // ✅ NEW: Stale-while-revalidate for images/fonts (show cached, update in background)
  if (event.request.destination === 'image' || 
      event.request.destination === 'font') {
    event.respondWith(
      caches.match(event.request)
        .then(cached => {
          const fetchPromise = fetch(event.request)
            .then(async response => {
              if (response.ok) {
                const cache = await caches.open(RUNTIME_CACHE);
                await cache.put(event.request, response.clone());
                await limitCacheSize(RUNTIME_CACHE, CACHE_SIZE_LIMIT);
              }
              return response;
            })
            .catch(err => {
              console.warn('🖼️ Failed to fetch:', url.pathname);
              return cached; // Return cached on error
            });
          
          return cached || fetchPromise; // Return cache immediately if available
        })
    );
    return;
  }

  // Cache-first for static assets (CSS, JS)
  event.respondWith(
    caches.match(event.request)
      .then(async cached => {
        if (cached) {
          console.log('💾 Serving from cache:', url.pathname);
          return cached;
        }
        
        console.log('🌐 Fetching from network:', url.pathname);
        const response = await fetch(event.request);
        
        if (response.ok) {
          const clone = response.clone();
          const cache = await caches.open(RUNTIME_CACHE);
          await cache.put(event.request, clone);
          await limitCacheSize(RUNTIME_CACHE, CACHE_SIZE_LIMIT);
        }
        return response;
      })
      .catch(err => {
        console.error('❌ Fetch failed:', url.pathname, err);
        // Return generic offline response
        return new Response('Resource unavailable offline', {
          status: 503,
          statusText: 'Service Unavailable'
        });
      })
  );
});

// ✅ NEW: Handle background sync (for offline alert posts)
self.addEventListener('sync', event => {
  if (event.tag === 'sync-alerts') {
    event.waitUntil(
      syncAlerts().catch(err => {
        console.error('❌ Background sync failed:', err);
      })
    );
  }
});

async function syncAlerts() {
  // This would sync with your OfflineQueue
  const clients = await self.clients.matchAll();
  clients.forEach(client => {
    client.postMessage({ type: 'SYNC_ALERTS' });
  });
}

// ✅ NEW: Handle push notifications
self.addEventListener('push', event => {
  const data = event.data?.json() || { title: 'New Alert', body: 'Check the app' };
  
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icon-192x192.png', // Add this icon to your project
      badge: '/badge-72x72.png',
      vibrate: [200, 100, 200],
      tag: 'alert-notification',
      requireInteraction: false,
      data: data.url
    })
  );
});

// ✅ NEW: Handle notification clicks
self.addEventListener('notificationclick', event => {
  event.notification.close();
  
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(clientList => {
        // Focus existing window if open
        for (const client of clientList) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            return client.focus();
          }
        }
        // Open new window if none found
        if (clients.openWindow) {
          return clients.openWindow(event.notification.data || '/');
        }
      })
  );
});

// Listen for skipWaiting message from client
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') {
    console.log('⏭️ Skipping waiting phase');
    self.skipWaiting();
  }
  
  // ✅ NEW: Clear old cache manually
  if (event.data?.type === 'CLEAR_OLD_CACHE') {
    event.waitUntil(
      caches.keys()
        .then(keys => {
          const oldCaches = keys.filter(key => 
            !key.includes(CACHE_VERSION)
          );
          return Promise.all(oldCaches.map(key => caches.delete(key)));
        })
        .then(() => {
          console.log('🧹 Old cache cleared manually');
        })
    );
  }
});

// ✅ NEW: Log cache size periodically
setInterval(async () => {
  const cacheNames = await caches.keys();
  for (const name of cacheNames) {
    const cache = await caches.open(name);
    const keys = await cache.keys();
    console.log(`📊 Cache ${name}: ${keys.length} entries`);
  }
}, 60000); // Every minute