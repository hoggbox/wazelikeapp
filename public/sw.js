const CACHE_NAME = 'waze-gps-v1.0.7'; // Bumped version for updates
const PRECACHE_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css',
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js',
  'https://cdn.socket.io/4.7.5/socket.io.min.js',
  'https://browser.sentry-cdn.com/7.x.x/bundle.min.js',
  'https://i.postimg.cc/YS0h0m7R/compass.png',
  'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png'
];

const MAX_CACHED_TILES = 500;

// Track cached regions and their metadata
let cachedRegions = new Map(); // Changed to Map to store metadata

// Precache critical assets during install
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(PRECACHE_ASSETS).catch(error => {
        console.error('Precache failed:', error);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'serviceWorkerInstall' } });
        }
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Skip cache for dynamic API & real-time (includes auth & subscription endpoints)
  if (url.pathname.startsWith('/api/') || url.pathname.includes('socket.io')) {
    event.respondWith(
      fetch(event.request).catch(async error => {
        console.error('API/Socket fetch failed:', error, 'URL:', event.request.url);
        if (self.Sentry) {
          self.Sentry.captureException(error, {
            tags: { context: 'fetchAPI', url: event.request.url }
          });
        }
        const isSubscriptionPath = url.pathname.startsWith('/api/subscription');
        const isAuthPath = url.pathname.startsWith('/api/auth');
        let errorMessage = 'Network unavailable';
        let suggest = isSubscriptionPath ? 'Reconnect to verify subscription' : isAuthPath ? 'Reconnect and refresh token' : 'Check connection';
        
        // NEW: Enhanced offline handling for subscription endpoints
        if (isSubscriptionPath && url.pathname.includes('/status')) {
          const cachedStatus = await caches.match('/subscription-status');
          if (cachedStatus) {
            return cachedStatus;
          }
          errorMessage = 'Offline: Cannot verify subscription';
          suggest = 'Reconnect to check subscription status';
        }

        return new Response(JSON.stringify({ 
          error: errorMessage, 
          offline: true, 
          suggest 
        }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // Handle map tile requests with region-aware caching
  if (url.pathname.includes('maps.googleapis.com') || url.pathname.includes('mt0.google.com/vt')) {
    event.respondWith(
      caches.match(event.request).then(cachedResponse => {
        const fetchPromise = fetch(event.request).then(networkResponse => {
          if (networkResponse && networkResponse.status === 200) {
            caches.open(CACHE_NAME).then(cache => {
              // NEW: Store tile with timestamp metadata
              cache.put(event.request, networkResponse.clone());
              cache.put(`${event.request.url}-meta`, new Response(JSON.stringify({ cachedAt: Date.now() })));
              cleanupMapTileCache(cache);
            });
          }
          return networkResponse;
        }).catch(() => {
          console.warn('Map tile fetch failed, using cache:', url.pathname);
          return cachedResponse || new Response('Map tile unavailable', { status: 503 });
        });
        return cachedResponse || fetchPromise;
      })
    );
    return;
  }

  // Handle document requests with network-first, cache fallback
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
        .catch(async () => {
          console.log('Serving cached/offline for document:', url.pathname);
          const isPaymentSuccess = url.searchParams.get('payment') === 'success' || url.searchParams.get('session_id');
          const isPaymentCancelled = url.searchParams.get('payment') === 'cancelled';
          
          const cachedResponse = await caches.match('/index.html');
          if (cachedResponse) {
            let enhancedHTML = await cachedResponse.clone().text();
            if (isPaymentSuccess) {
              enhancedHTML = enhancedHTML.replace(
                '</body>',
                `
                <script>
                  const celeb = document.createElement('div');
                  celeb.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);font-size:5rem;z-index:10003;animation:celebrate 2s ease-out forwards;pointer-events:none';
                  celeb.textContent = '🎉 Premium Unlocked!';
                  document.body.appendChild(celeb);
                  const style = document.createElement('style');
                  style.textContent = '@keyframes celebrate {0%{transform:translate(-50%,-50%) scale(0);opacity:0}50%{transform:translate(-50%,-50%) scale(1.5);opacity:1}100%{transform:translate(-50%,-50%) scale(1) translateY(-100px);opacity:0}}';
                  document.head.appendChild(style);
                  setTimeout(() => {celeb.remove(); style.remove();}, 2000);
                  if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.ready.then(() => {
                      const checkOnline = () => {
                        if (navigator.onLine) {
                          location.reload();
                        } else {
                          setTimeout(checkOnline, 2000);
                        }
                      };
                      checkOnline();
                    });
                  }
                </script>
                </body>`
              );
            } else if (isPaymentCancelled) {
              enhancedHTML = enhancedHTML.replace(
                '</body>',
                `<script>alert('Payment cancelled. You can upgrade anytime from Settings.');</script></body>`
              );
            }
            return new Response(enhancedHTML, {
              headers: cachedResponse.headers
            });
          }
          // NEW: Fallback offline page if index.html not cached
          const offlineHTML = `
            <!DOCTYPE html>
            <html><head><title>Offline</title><style>body{font-family:Arial;text-align:center;padding:2rem;background:#f0f0f0;color:#333;}button{background:#4CAF50;color:white;border:none;padding:1rem;border-radius:0.5rem;cursor:pointer;font-size:1rem;}</style></head><body>
              <h1>You're offline</h1>
              <p>Reconnect to access the app & verify subscription. Cached content unavailable.</p>
              ${isPaymentSuccess ? '<p>🎉 Payment success detected! Reconnecting to unlock Premium...</p>' : ''}
              ${isPaymentCancelled ? '<p>Payment cancelled.</p>' : ''}
              <button onclick="location.reload()">Reconnect & Refresh</button>
              <script>
                const checkOnline = () => {
                  if (navigator.onLine) {
                    location.reload();
                  } else {
                    setTimeout(checkOnline, 5000);
                  }
                };
                if ('serviceWorker' in navigator) {
                  navigator.serviceWorker.ready.then(() => checkOnline());
                } else {
                  checkOnline();
                }
                window.addEventListener('online', () => location.reload());
              </script>
            </body></html>
          `;
          return new Response(offlineHTML, { 
            status: 503,
            headers: { 'Content-Type': 'text/html' }
          });
        })
    );
    return;
  }

  // Default: Cache-first with network update (stale-while-revalidate)
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
      if (self.Sentry) {
        self.Sentry.captureException(error, { tags: { context: 'fetchDefault', url: event.request.url } });
      }
      return new Response('Resource unavailable', { status: 503 });
    })
  );
});

self.addEventListener('activate', event => {
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
      console.log('Service Worker activated, claiming clients');
      return self.clients.claim();
    })
  );
});

// Handle offline map region caching
self.addEventListener('message', async event => {
  if (event.data.type === 'CACHE_REGION' && event.data.region) {
    const { bounds, name } = event.data.region;
    try {
      const cache = await caches.open(CACHE_NAME);
      const tileUrls = generateTileUrls(bounds);
      for (const url of tileUrls) {
        try {
          const response = await fetch(url);
          if (response && response.status === 200) {
            await cache.put(url, response);
            await cache.put(`${url}-meta`, new Response(JSON.stringify({ cachedAt: Date.now() })));
            console.log('Cached map tile:', url);
          }
        } catch (error) {
          console.error('Failed to cache map tile:', url, error);
          if (self.Sentry) {
            self.Sentry.captureException(error, { tags: { context: 'cacheRegion', tileUrl: url } });
          }
        }
      }
      cachedRegions.set(name, { bounds, cachedAt: Date.now() });
      console.log('Cached map tiles for region:', name, bounds);
      self.clients.matchAll().then(clients => {
        clients.forEach(client => {
          client.postMessage({ type: 'REGION_CACHED', region: name });
        });
      });
    } catch (error) {
      console.error('Error caching region:', error);
      if (self.Sentry) {
        self.Sentry.captureException(error, { tags: { context: 'cacheRegion', region: name } });
      }
    }
  } else if (event.data.type === 'CLEAR_OLD_CACHE') {
    const cacheNames = await caches.keys();
    await Promise.all(
      cacheNames.map(cacheName => {
        if (cacheName !== CACHE_NAME) {
          console.log('Clearing old cache on message:', cacheName);
          return caches.delete(cacheName);
        }
      })
    );
  } else if (event.data.type === 'UPDATE_CACHED_REGIONS') {
    // NEW: Sync cachedRegions with main script's offlineRegions
    cachedRegions = new Map(event.data.regions.map(r => [r.name, { bounds: r.bounds, cachedAt: new Date(r.timestamp).getTime() }]));
    console.log('Updated cached regions:', Array.from(cachedRegions.keys()));
    await cleanupMapTileCache();
  }
});

// Handle push notifications
self.addEventListener('push', event => {
  let data = { title: 'New Alert', body: 'A new alert has been posted nearby.' };
  if (event.data) {
    try {
      data = event.data.json();
    } catch (error) {
      console.error('Error parsing push data:', error);
      if (self.Sentry) {
        self.Sentry.captureException(error, { tags: { context: 'pushEvent' } });
      }
    }
  }
  const options = {
    body: data.body,
    icon: 'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png',
    badge: 'https://i.postimg.cc/YS0h0m7R/compass.png',
    data: {
      url: data.url || `${self.location.origin}/?alertId=${data.alertId || ''}&lat=${data.lat || ''}&lng=${data.lng || ''}`
    }
  };
  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
  console.log('Push notification received:', data);
});

// Handle notification clicks
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      const url = event.notification.data.url || self.location.origin;
      for (const client of clientList) {
        if (client.url === url && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(url);
      }
    })
  );
  console.log('Notification clicked, opening:', event.notification.data.url);
});

// Generate tile URLs for a given bounds (aligned with Google Maps API)
function generateTileUrls(bounds) {
  const urls = [];
  const zoomLevels = [16, 17, 18, 19];
  const tileSize = 256;
  const { north, south, east, west } = bounds;

  for (const zoom of zoomLevels) {
    const scale = 1 << zoom;
    const topLeft = latLngToTile({ lat: north, lng: west }, zoom);
    const bottomRight = latLngToTile({ lat: south, lng: east }, zoom);

    for (let x = topLeft.x; x <= bottomRight.x; x++) {
      for (let y = topLeft.y; y <= bottomRight.y; y++) {
        // NEW: Use correct Google Maps tile URL format
        const url = `https://mt0.google.com/vt?x=${x}&y=${y}&z=${zoom}&key=AIzaSyBSW8iQAE1AjjouEu4df-Cvq1ceUMLBit4&map_id=2666b5bd496d9c6026f43f82`;
        urls.push(url);
      }
    }
  }
  return urls.slice(0, MAX_CACHED_TILES);
}

// Convert lat/lng to tile coordinates
function latLngToTile(latLng, zoom) {
  const scale = 1 << zoom;
  const worldCoordinate = project(latLng);
  const tileCoordinate = {
    x: Math.floor(worldCoordinate.x * scale),
    y: Math.floor(worldCoordinate.y * scale)
  };
  return tileCoordinate;
}

// Project lat/lng to world coordinates
function project(latLng) {
  const siny = Math.sin((latLng.lat * Math.PI) / 180);
  const y = 0.5 - Math.log((1 + siny) / (1 - siny)) / (4 * Math.PI);
  return {
    x: (latLng.lng + 180) / 360,
    y: y
  };
}

// Clean up map tile cache to respect MAX_CACHED_TILES
async function cleanupMapTileCache(cache) {
  const cacheInstance = cache || await caches.open(CACHE_NAME);
  const requests = await cacheInstance.keys();
  const tileRequests = requests.filter(req => req.url.includes('mt0.google.com/vt'));
  
  if (tileRequests.length > MAX_CACHED_TILES) {
    // NEW: Sort by cachedAt timestamp
    const tilesWithMetadata = [];
    for (const req of tileRequests) {
      const metaResponse = await cacheInstance.match(`${req.url}-meta`);
      let cachedAt = 0;
      if (metaResponse) {
        const meta = await metaResponse.json();
        cachedAt = meta.cachedAt || 0;
      }
      tilesWithMetadata.push({ request: req, cachedAt });
    }
    tilesWithMetadata.sort((a, b) => a.cachedAt - b.cachedAt); // Oldest first
    const tilesToDelete = tilesWithMetadata.slice(0, tileRequests.length - MAX_CACHED_TILES);
    for (const { request } of tilesToDelete) {
      await cacheInstance.delete(request);
      await cacheInstance.delete(`${request.url}-meta`);
      console.log('Deleted old map tile:', request.url);
    }
  }
}