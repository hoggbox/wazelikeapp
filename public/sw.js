self.addEventListener('push', event => {
  const data = event.data.json();
  self.registration.showNotification(data.title, {
    body: data.body,
    icon: '/icon.png'
  });
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow('/'));
});

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open('waze-app-v1').then(cache => {
      return cache.addAll([
        '/',
        '/index.html',
        '/manifest.json',
        '/icon.png',
        '/icon-512.png'
      ]);
    }).catch(err => console.error('Cache addAll error:', err))
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request).catch(err => console.error('Fetch error:', err));
    })
  );
});

self.addEventListener('message', event => {
  if (event.data.type === 'INIT') console.log('Service worker initialized');
});