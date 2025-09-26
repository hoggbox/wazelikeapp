const CACHE_NAME = 'waze-app-v1.0.6';

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll([
        '/',
        '/index.html',
        '/manifest.json?v=1.0.3',
        // '/icon.png', // FIXED: Commented out until uploaded to /public
        // '/icon-512.png', // FIXED: Commented out until uploaded to /public
        'https://cdn.socket.io/4.7.5/socket.io.min.js?v=1.0.3',
        'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js?v=1.0.3',
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css?v=1.0.3'
      ]).catch(err => {
        console.error('Cache addAll error:', err);
        throw err;
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
        console.log('Cache hit:', event.request.url);
        return response;
      }
      console.log('Cache miss, fetching:', event.request.url);
      return fetch(event.request).then(networkResponse => {
        if (networkResponse.ok && event.request.method === 'GET' && 
            (event.request.url.includes('/api/markers') || event.request.url.includes('/api/hazards-near-route') || event.request.url.includes('/index.html'))) {
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, networkResponse.clone());
            console.log('Cached API response:', event.request.url);
          });
        }
        return networkResponse;
      }).catch(err => {
        console.error('Fetch error:', err, 'URL:', event.request.url);
        if (event.request.mode === 'navigate') {
          console.log('Serving cached /index.html for navigation request');
          return caches.match('/index.html');
        }
        if (event.request.url.includes('/api/markers')) {
          console.log('Serving cached or empty /api/markers response for offline');
          return caches.match('/api/markers?lat=33.083270&lng=-83.233040&maxDistance=50000') || 
                 new Response(JSON.stringify([]), { status: 200, headers: { 'Content-Type': 'application/json' } });
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
    badge: 'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png'
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