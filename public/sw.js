const CACHE_VERSION = 'v1.0.14'; // ← Increment this on every deploy
const CACHE_NAME = `waze-gps-${CACHE_VERSION}`;
const CACHE_SIZE_LIMIT = 50; // max entries
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/manifest.json',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css',
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js'
];

// Limit cache size
async function limitCacheSize(cacheName, maxItems) {
  const cache = await caches.open(cacheName);
  const keys = await cache.keys();
  
  if (keys.length > maxItems) {
    const excess = keys.slice(0, keys.length - maxItems);
    await Promise.all(excess.map(key => cache.delete(key)));
    console.log(`Evicted ${excess.length} old cache entries`);
  }
}

// Install - Cache core assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS_TO_CACHE))
      .then(() => self.skipWaiting()) // ← Force new SW to activate immediately
  );
});

// Activate - Delete old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(key => key !== CACHE_NAME)
          .map(key => {
            console.log('🗑️ Deleting old cache:', key);
            return caches.delete(key);
          })
      ))
      .then(() => self.clients.claim()) // ← Take control of all clients immediately
  );
});

// Fetch - Network-first for HTML/API, cache-first for assets
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  
  // Always bypass cache for API/Socket
  if (url.pathname.startsWith('/api/') || url.pathname.includes('socket.io')) {
    event.respondWith(
      fetch(event.request).catch(() => 
        new Response(JSON.stringify({ error: 'Offline', offline: true }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        })
      )
    );
    return;
  }

  // Network-first for HTML (always fetch fresh, fallback to cache)
  if (event.request.destination === 'document') {
    event.respondWith(
      fetch(event.request)
        .then(async response => {
          if (response.ok) {
            const clone = response.clone();
            const cache = await caches.open(CACHE_NAME);
            await cache.put(event.request, clone);
            await limitCacheSize(CACHE_NAME, CACHE_SIZE_LIMIT);
          }
          return response;
        })
        .catch(async () => {
          const cached = await caches.match(event.request);
          return cached || new Response('<h1>Offline</h1><p>Reconnect to access app</p>', {
            headers: { 'Content-Type': 'text/html' }
          });
        })
    );
    return;
  }

  // Cache-first for static assets
  event.respondWith(
    caches.match(event.request)
      .then(async cached => {
        if (cached) return cached;
        
        const response = await fetch(event.request);
        if (response.ok) {
          const clone = response.clone();
          const cache = await caches.open(CACHE_NAME);
          await cache.put(event.request, clone);
          await limitCacheSize(CACHE_NAME, CACHE_SIZE_LIMIT);
        }
        return response;
      })
  );
});

// Listen for skipWaiting message from client
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});