const CACHE_NAME = 'gps-app-cache-v16';  // Bumped to v16 for enhanced offline image caching & fresh load optimizations

const urlsToCache = [
  '/',
  '/index.html',
  '/manifest.json',  // For PWA offline support
  '/sw.js',
  '/favicon.ico',
  // Static assets
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css?v=1.0.3',
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js?v=1.0.3',
  'https://cdn.socket.io/4.7.5/socket.io.min.js?v=1.0.3',
  // App-specific images for offline resilience
  'https://i.postimg.cc/YS0h0m7R/compass.png',
  'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png'
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Caching assets for v16 (offline images & fresh load optimizations):', urlsToCache);
        return cache.addAll(urlsToCache);
      })
      .catch(error => {
        console.error('Cache installation failed:', error);
      })
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    Promise.all([
      clients.claim(),
      caches.keys().then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            if (cacheName !== CACHE_NAME) {
              console.log('Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
    ])
  );
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  
  // Skip cache for dynamic API & real-time (includes auth endpoints like /auth/refresh)
  if (url.pathname.startsWith('/api/') || url.pathname.includes('socket.io')) {
    event.respondWith(
      fetch(event.request).catch(error => {
        console.error('API fetch failed (check auth/token):', error, 'URL:', event.request.url);
        // Enhanced: Provide a more specific offline message for auth-related paths
        const isAuthPath = url.pathname.startsWith('/api/auth');
        return new Response(JSON.stringify({ 
          error: 'Network unavailable', 
          offline: true, 
          suggest: isAuthPath ? 'Reconnect and refresh token' : 'Check connection' 
        }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // Handle document requests (e.g., index.html) with network-first, cache fallback
  if (event.request.destination === 'document' || url.pathname === '/' || url.pathname.includes('index.html')) {
    event.respondWith(
      fetch(event.request)
        .then(networkResponse => {
          if (networkResponse && networkResponse.status === 200 && networkResponse.headers.get('content-type')?.includes('text/html')) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, responseToCache);
            });
          } else {
            console.warn('Network response invalid for document:', networkResponse ? networkResponse.status : 'No response', 'MIME:', networkResponse?.headers.get('content-type'));
          }
          return networkResponse;
        })
        .catch(() => {
          console.log('Serving cached index.html for offline:', url.pathname);
          return caches.match('/index.html') || new Response(`
            <!DOCTYPE html>
            <html><head><title>Offline</title></head><body>
              <h1>You're offline</h1>
              <p>Reconnect to access the app. Cached content available.</p>
              <script>if ('serviceWorker' in navigator) navigator.serviceWorker.ready.then(() => location.reload());</script>
            </body></html>
          `, { 
            status: 503,
            headers: { 'Content-Type': 'text/html' }
          });
        })
    );
    return;
  }

  // Default: Cache-first with network update
  event.respondWith(
    caches.open(CACHE_NAME).then(cache => {
      return cache.match(event.request).then(cachedResponse => {
        const fetchPromise = fetch(event.request).then(networkResponse => {
          if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
            cache.put(event.request, networkResponse.clone());
          }
          return networkResponse;
        }).catch(() => {
          console.log('Network fetch failed, using cache for:', url.pathname);
          return cachedResponse;
        });
        return cachedResponse || fetchPromise;
      });
    }).catch(error => {
      console.error('Fetch failed:', error, 'URL:', event.request.url);
      return new Response('Resource unavailable', { status: 503 });
    })
  );
});

self.addEventListener('message', event => {
  if (event.data.type === 'CACHE_REGION') {
    const { region } = event.data;
    caches.open(CACHE_NAME).then(cache => {
      cache.put(`/offline-region-${region.name}`, new Response(JSON.stringify(region)));
      console.log('Cached offline region:', region.name);
    });
  }
});

self.addEventListener('push', event => {
  let data = { title: 'Notification', body: 'New alert received' };
  if (event.data) {
    try {
      data = event.data.json();
    } catch (error) {
      console.error('Error parsing push data:', error);
    }
  }
  self.registration.showNotification(data.title || 'Notification', {
    body: data.body || 'You have a new alert',
    icon: '/favicon.ico',
    badge: '/favicon.ico'
  });
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.openWindow('/')
  );
});