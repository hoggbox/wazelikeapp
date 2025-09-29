const CACHE_NAME = 'waze-app-v1.0.12'; // CHANGED: Bumped to v1.0.12 for updated index.html
const urlsToCache = [
  '/',
  '/index.html',
  '/manifest.json?v=1.0.3',
  // '/icon.png', // Uncomment if icon.png is uploaded to /public
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css?v=1.0.3',
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js?v=1.0.3',
  'https://cdn.socket.io/4.7.5/socket.io.min.js?v=1.0.3'
];

self.addEventListener('install', event => {
  console.log('Service worker installing...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Service worker caching files');
        return cache.addAll(urlsToCache);
      })
      .then(() => {
        console.log('Service worker installed:', CACHE_NAME);
        return self.skipWaiting();
      })
  );
});

self.addEventListener('activate', event => {
  console.log('Service worker activating...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      console.log('Service worker activated:', CACHE_NAME);
      return self.clients.claim();
    })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          console.log('Cache hit:', event.request.url);
          return response;
        }
        console.log('Cache miss, fetching:', event.request.url);
        return fetch(event.request).catch(error => {
          console.error('Fetch failed:', error);
          if (event.request.url.includes('/api/markers')) {
            return new Response(JSON.stringify([]), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            });
          }
          return new Response('Offline', { status: 503 });
        });
      })
  );
});

self.addEventListener('message', event => {
  if (event.data.type === 'INIT') {
    console.log('Service worker initialized via message');
  }
  if (event.data.type === 'SHOW_NOTIFICATION') {
    const { title, body, alertId, lat, lng } = event.data;
    self.registration.showNotification(title, {
      body,
      icon: '/icon.png', // Uncomment if icon.png is uploaded
      badge: '/icon.png', // Uncomment if icon.png is uploaded
      tag: `alert-${alertId}`,
      data: { alertId, lat, lng },
      actions: [
        { action: 'view', title: 'View Alert' }
      ]
    });
    console.log('Notification displayed:', { title, body, alertId, lat, lng });
  }
});

self.addEventListener('push', event => {
  const data = event.data?.json() || {};
  const { title = 'Alert', body = 'New alert reported nearby.', alertId, lat, lng } = data;
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: '/icon.png', // Uncomment if icon.png is uploaded
      badge: '/icon.png', // Uncomment if icon.png is uploaded
      tag: `alert-${alertId}`,
      data: { alertId, lat, lng },
      actions: [
        { action: 'view', title: 'View Alert' }
      ]
    }).then(() => {
      console.log('Push notification displayed:', { title, body, alertId, lat, lng });
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const { action, notification } = event;
  console.log('Notification clicked:', { action, alertId: notification.data?.alertId, lat: notification.data?.lat, lng: notification.data?.lng });
  if (action === 'view') {
    event.waitUntil(
      clients.matchAll({ type: 'window', includeUncontrolled: true })
        .then(clientList => {
          const url = new URL('/', self.location.origin);
          if (notification.data?.alertId && !isNaN(notification.data?.lat) && !isNaN(notification.data?.lng)) {
            url.searchParams.set('alertId', notification.data.alertId);
            url.searchParams.set('lat', notification.data.lat);
            url.searchParams.set('lng', notification.data.lng);
          } else {
            console.warn('Incomplete alert data, opening root URL:', notification.data);
          }
          const client = clientList.find(c => c.url.includes('wazelikeapp') && 'focus' in c);
          if (client) {
            client.focus();
            client.postMessage({
              type: 'NAVIGATE_TO_ALERT',
              alertId: notification.data?.alertId,
              lat: notification.data?.lat,
              lng: notification.data?.lng
            });
            console.log('Client focused for alert:', { alertId: notification.data?.alertId, lat: notification.data?.lat, lng: notification.data?.lng });
            return;
          }
          return clients.openWindow(url.toString()).then(windowClient => {
            if (windowClient) {
              windowClient.postMessage({
                type: 'NAVIGATE_TO_ALERT',
                alertId: notification.data?.alertId,
                lat: notification.data?.lat,
                lng: notification.data?.lng
              });
              console.log('Client opened for alert:', { alertId: notification.data?.alertId, lat: notification.data?.lat, lng: notification.data?.lng });
            }
          });
        })
    );
  }
});