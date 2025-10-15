const CACHE_NAME = 'gps-app-cache-v11';  // Bumped to v10 for index.html updates (camera logic, heading smoothing, etc.)

const urlsToCache = [
  '/',
  '/index.html',
  '/manifest.json',  // Added: For PWA offline support
  '/sw.js',
  '/favicon.ico',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css?v=1.0.3',  // Added ?v=1.0.3 to match index.html
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js?v=1.0.3',  // Added ?v=1.0.3 to match index.html
  'https://cdn.socket.io/4.7.5/socket.io.min.js?v=1.0.3'  // Added ?v=1.0.3 to match index.html
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Caching assets for v9 (includes updated index.html & manifest):', urlsToCache);
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
  
  if (url.pathname.startsWith('/api/') || url.pathname.includes('socket.io')) {
    event.respondWith(
      fetch(event.request).catch(error => {
        console.error('API fetch failed:', error, 'URL:', event.request.url);
        return new Response(JSON.stringify({ error: 'Network unavailable' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  if (event.request.destination === 'document' || url.pathname === '/' || url.pathname.includes('index.html')) {
    event.respondWith(
      fetch(event.request)
        .then(networkResponse => {
          // Minor tweak: Add MIME type check for security (optional, but good practice)
          if (networkResponse && networkResponse.status === 200 && networkResponse.headers.get('content-type')?.includes('text/html')) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, responseToCache);
            });
          } else {
            console.warn('Network response invalid for document:', networkResponse ? networkResponse.status : 'No response', 'MIME:', networkResponse?.headers.get('content-type'));  // Enhanced logging
          }
          return networkResponse;
        })
        .catch(() => {
          console.log('Serving cached index.html for:', url.pathname);
          return caches.match('/index.html') || new Response('Offline page unavailable', { status: 503 });
        })
    );
    return;
  }

  event.respondWith(
    caches.open(CACHE_NAME).then(cache => {
      return cache.match(event.request).then(cachedResponse => {
        const fetchPromise = fetch(event.request).then(networkResponse => {
          // Minor tweak: Only cache if basic response and valid status (prevents caching errors)
          if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
            cache.put(event.request, networkResponse.clone());
          }
          return networkResponse;
        }).catch(() => {
          console.log('Network fetch failed for:', url.pathname);
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