const CACHE_NAME = 'waze-app-v1.0.4'; // CHANGED: Bumped version to clear old caches

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll([
        '/',
        '/index.html',
        '/manifest.json?v=1.0.3', // CHANGED: Kept versioned manifest
        // '/icon.png', // FIXED: Commented out until uploaded to /public
        // '/icon-512.png', // FIXED: Commented out until uploaded to /public
        'https://cdn.socket.io/4.7.5/socket.io.min.js?v=1.0.3', // CHANGED: Added Socket.IO CDN
        'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js?v=1.0.3', // CHANGED: Added TWEEN.js
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css?v=1.0.3' // CHANGED: Added Font Awesome
      ]).catch(err => {
        console.error('Cache addAll error:', err);
        throw err; // FIXED: Rethrow to debug cache failures
      });
    })
  );
  self.skipWaiting();
  console.log('Service worker installed:', CACHE_NAME);
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(cacheName => cacheName !== CACHE_NAME)
          .map(cacheName => caches.delete(cacheName))
      );
    }).then(() => self.clients.claim())
      .catch(err => console.error('Cache cleanup error:', err))
  );
  console.log('Service worker activated:', CACHE_NAME);
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      if (response) {
        console.log('Serving from cache:', event.request.url);
        return response;
      }
      return fetch(event.request).then(networkResponse => {
        // CHANGED: Cache dynamic responses for GET requests
        if (networkResponse.ok && event.request.method === 'GET') {
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, networkResponse.clone());
          });
        }
        return networkResponse;
      }).catch(err => {
        console.error('Fetch error:', err, 'URL:', event.request.url);
        // FIXED: Fallback to index.html for navigation requests
        if (event.request.mode === 'navigate') {
          return caches.match('/index.html');
        }
        throw err;
      });
    })
  );
});

self.addEventListener('push', event => {
  let data;
  try {
    data = event.data.json();
  } catch (err) {
    console.error('Push data parse error:', err);
    return;
  }
  const options = {
    body: data.body,
    // icon: '/icon.png', // FIXED: Commented out until icon.png is uploaded
    badge: 'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png' // CHANGED: Fallback to traffic camera icon
  };
  self.registration.showNotification(data.title || 'Waze-Like App', options);
  console.log('Push notification received:', data);
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow('/'));
  console.log('Notification clicked, opening root URL');
});

self.addEventListener('message', event => {
  if (event.data.type === 'INIT') {
    console.log('Service worker initialized');
  }
});