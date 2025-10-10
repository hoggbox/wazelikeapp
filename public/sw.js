// sw.js
const CACHE_NAME = 'waze-like-app-v1.2'; // Bumped version to clear old caches after app updates
const urlsToCache = [
  '/',
  '/index.html',
  '/icon.png',
  '/manifest.json?v=1.0.3',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css', // Updated to stable v6.6.0 (2025 latest)
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js',
  'https://cdn.socket.io/4.7.5/socket.io.min.js',
  'https://maps.googleapis.com/maps/api/js?key=AIzaSyBSW8iQAE1AjjouEu4df-Cvq1ceUMLBit4&map_ids=2666b5bd496d9c6026f43f82&v=beta&libraries=places,geometry,marker,routes&loading=async&callback=initMap', // Explicit callback for Maps
  'https://i.postimg.cc/YS0h0m7R/compass.png', // Added compass image
  'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png' // Added traffic camera marker image
];

// Install event: Cache essential assets
self.addEventListener('install', event => {
  console.log('[Service Worker] Installing service worker...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[Service Worker] Caching app shell and assets');
        // Check network conditions before caching
        const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (connection && connection.effectiveType === '2g') {
          console.log('[Service Worker] Slow connection detected, caching minimal assets only');
          return cache.addAll(['/', '/index.html', '/icon.png']);
        }
        return cache.addAll(urlsToCache);
      })
      .then(() => {
        console.log('[Service Worker] Cache populated successfully');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('[Service Worker] Cache population failed:', error.message, error.stack);
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
    }).catch(error => {
      console.error('[Service Worker] Activation failed:', error.message, error.stack);
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
    event.respondWith(
      fetch(event.request).catch(error => {
        console.error('[Service Worker] Fetch failed for API/WebSocket:', error.message, error.stack);
        return new Response(JSON.stringify({ error: 'Network unavailable', details: error.message }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // Cache-first strategy for static assets, with network condition check
  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      if (cachedResponse) {
        // Check Cache-Control for freshness (added for 2025 compatibility)
        const cacheControl = cachedResponse.headers.get('Cache-Control');
        if (cacheControl && cacheControl.includes('no-cache')) {
          console.log('[Service Worker] Cache stale (no-cache header), refetching:', url.pathname);
          return fetch(event.request).then(networkResponse => {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, responseToCache);
            });
            return networkResponse;
          }).catch(() => cachedResponse); // Fallback to cache if network fails
        }
        console.log('[Service Worker] Serving from cache:', url.pathname);
        return cachedResponse;
      }
      console.log('[Service Worker] Fetching from network:', url.pathname);
      return fetch(event.request).then(async networkResponse => {
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
          return networkResponse;
        }
        // Check battery level before caching
        const battery = await navigator.getBattery?.();
        if (battery && battery.level < 0.2) {
          console.log('[Service Worker] Low battery, skipping cache update:', url.pathname);
          return networkResponse;
        }
        const responseToCache = networkResponse.clone();
        caches.open(CACHE_NAME).then(cache => {
          cache.put(event.request, responseToCache);
          console.log('[Service Worker] Cached network response:', url.pathname);
        }).catch(error => {
          console.error('[Service Worker] Cache put failed:', error.message, error.stack);
        });
        return networkResponse;
      }).catch(error => {
        console.error('[Service Worker] Fetch failed:', error.message, error.stack);
        return new Response('Offline and no cache available', { status: 503 });
      });
    })
  );
});

// Push event: Handle push notifications for alerts
self.addEventListener('push', event => {
  console.log('[Service Worker] Push event received');
  let data = { title: 'Alert', body: 'New alert received', alertId: null, lat: null, lng: null };
  if (event.data) {
    try {
      data = event.data.json();
      console.log('[Service Worker] Push data:', data);
    } catch (error) {
      console.error('[Service Worker] Error parsing push data:', error.message, error.stack);
    }
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icon.png',
      badge: '/icon.png',
      vibrate: [200, 100, 200],
      data: {
        alertId: data.alertId,
        lat: data.lat,
        lng: data.lng
      },
      actions: [ // Added actions for better UX (2025 standard)
        {
          action: 'view_alert',
          title: 'View Alert',
          icon: '/icon.png'
        }
      ]
    }).then(() => {
      console.log('[Service Worker] Notification shown:', data.title);
    }).catch(error => {
      console.error('[Service Worker] Notification error:', error.message, error.stack);
    })
  );
});

// Notification click event: Focus or open app with alert details
self.addEventListener('notificationclick', event => {
  console.log('[Service Worker] Notification clicked:', event.notification.data);
  event.notification.close();
  const { alertId, lat, lng } = event.notification.data || {};
  const url = alertId && !isNaN(lat) && !isNaN(lng) ? `/?alertId=${alertId}&lat=${lat}&lng=${lng}` : '/';
  
  // Handle action buttons (added for 2025 UX)
  if (event.action === 'view_alert') {
    console.log('[Service Worker] Action button clicked: view_alert');
  }
  
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
      console.error('[Service Worker] Error handling notification click:', error.message, error.stack);
    })
  );
});

// Sync event: Handle background sync for offline location updates
self.addEventListener('sync', event => {
  if (event.tag === 'sync-location') {
    console.log('[Service Worker] Background sync for location triggered');
    event.waitUntil(syncLocationUpdates());
  }
});

// Function to sync offline location updates using IndexedDB
async function syncLocationUpdates() {
  try {
    const db = await openDB('waze-like-app-db', 1, {
      upgrade(db) {
        if (!db.objectStoreNames.contains('location-queue')) {
          db.createObjectStore('location-queue', { autoIncrement: true });
        }
      }
    });

    const tx = db.transaction('location-queue', 'readonly');
    const store = tx.objectStore('location-queue');

    // Get all keys and values to pair them
    const keys = await store.getAllKeys();
    if (keys.length === 0) {
      console.log('[Service Worker] No queued locations to sync');
      return;
    }

    const keyPromises = keys.map(key => store.get(key).then(value => ({ key, value })));
    const items = await Promise.all(keyPromises);
    await tx.done;

    // Request token from main client
    const token = await getStoredToken();
    if (!token) {
      console.error('[Service Worker] No valid token for location sync - cannot proceed');
      // Re-register sync for retry (main app will handle re-registration on load)
      return;
    }

    let retryCount = 0;
    const maxRetries = 3;
    const baseBackoff = 5000;

    // Sync each item
    for (const { key, value } of items) {
      let success = false;
      let localRetryCount = 0;

      while (localRetryCount < maxRetries && !success) {
        try {
          const response = await fetch('/api/location', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(value.data)
          });

          if (response.ok) {
            console.log('[Service Worker] Synced location:', value.data);
            // Delete from DB
            const deleteTx = db.transaction('location-queue', 'readwrite');
            const deleteStore = deleteTx.objectStore('location-queue');
            await deleteStore.delete(key);
            await deleteTx.done;
            success = true;
          } else {
            console.warn('[Service Worker] Failed to sync location:', response.status);
            localRetryCount++;
            if (localRetryCount < maxRetries) {
              const backoff = baseBackoff * Math.pow(2, localRetryCount);
              console.log(`[Service Worker] Retrying location sync in ${backoff}ms`);
              await new Promise(resolve => setTimeout(resolve, backoff));
            }
          }
        } catch (error) {
          console.error('[Service Worker] Location sync failed:', error.message, error.stack);
          localRetryCount++;
          if (localRetryCount < maxRetries) {
            const backoff = baseBackoff * Math.pow(2, localRetryCount);
            console.log(`[Service Worker] Retrying location sync in ${backoff}ms`);
            await new Promise(resolve => setTimeout(resolve, backoff));
          }
        }
      }

      if (!success) {
        console.error('[Service Worker] Max retries reached for location sync:', value);
      }
    }

    console.log(`[Service Worker] Sync completed: ${items.length} items processed`);
  } catch (error) {
    console.error('[Service Worker] Sync failed:', error.message, error.stack);
  }
}

// Helper to open IndexedDB
function openDB(name, version, upgradeCallback) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, version);
    request.onupgradeneeded = event => upgradeCallback(event.target.result);
    request.onsuccess = event => resolve(event.target.result);
    request.onerror = event => reject(event.target.error);
  });
}

// Get token from main client via postMessage
async function getStoredToken() {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Token request timeout'));
    }, 5000);  // 5s timeout to avoid hanging

    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      if (clients.length === 0) {
        clearTimeout(timeout);
        resolve(null);
        return;
      }
      const mainClient = clients[0];  // Assume first client is main app
      mainClient.postMessage({ type: 'GET_TOKEN_FOR_SYNC' });

      const handler = event => {
        if (event.source === mainClient && event.data.type === 'TOKEN_RESPONSE') {
          clearTimeout(timeout);
          self.removeEventListener('message', handler);
          resolve(event.data.token);
        }
      };
      self.addEventListener('message', handler);
    }).catch(err => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

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
      vibrate: [200, 100, 200],
      data: {
        alertId: event.data.alertId,
        lat: event.data.lat,
        lng: event.data.lng
      },
      actions: [ // Added actions for better UX (2025 standard)
        {
          action: 'view_alert',
          title: 'View Alert',
          icon: '/icon.png'
        }
      ]
    }).then(() => {
      console.log('[Service Worker] Client-initiated notification shown:', event.data.title);
    }).catch(error => {
      console.error('[Service Worker] Client-initiated notification error:', error.message, error.stack);
    });
  } else if (event.data.type === 'RELEASE_WAKELOCK') {  // Coordinate wake lock release on app close
    console.log('[Service Worker] Releasing wake lock via message');
    // Forward to clients if needed
  }
});