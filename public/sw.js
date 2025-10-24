const CACHE_NAME = 'waze-gps-v1.0.15'; // Bumped version for new index.html changes
const PRECACHE_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json?v=1.0.3',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css?v=1.0.3',
  'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js?v=1.0.3',
  'https://cdn.socket.io/4.7.5/socket.io.min.js?v=1.0.3',
  'https://browser.sentry-cdn.com/7.x.x/bundle.min.js',
  'https://i.postimg.cc/YS0h0m7R/compass.png',
  'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png'
];

const MAX_CACHED_TILES = 500;
const SUBSCRIPTION_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const API_CACHE_TTL = 15 * 60 * 1000; // 15 minutes
const REGION_STALE_AGE = 30 * 24 * 60 * 60 * 1000; // 30 days
const MAX_REGION_CACHE_SIZE = 50;
const FETCH_RETRIES = 3;
const FETCH_BACKOFF = 1000;

let cachedRegions = new Map();

async function fetchWithRetry(url, options = {}, retries = FETCH_RETRIES, backoff = FETCH_BACKOFF) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'X-CSRF-Token': await getCsrfToken()
        }
      });
      if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get('Retry-After') || '60');
        console.warn(`Rate limited for ${url}. Retrying after ${retryAfter}s`);
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      if (response.ok) {
        return response;
      }
      throw new Error(`HTTP ${response.status} for ${url}`);
    } catch (error) {
      if (i === retries - 1) {
        console.error(`Fetch failed after ${retries} retries for ${url}:`, error);
        if (typeof self.Sentry !== 'undefined') {
          self.Sentry.captureException(error, { tags: { context: 'fetchWithRetry', url } });
        }
        throw error;
      }
      const jitter = Math.random() * 500;
      const delay = backoff * Math.pow(2, i) + jitter;
      console.log(`Retry ${i + 1}/${retries} for ${url} after ${delay}ms`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

async function getCsrfToken() {
  try {
    const response = await fetch('/api/csrf-token', { method: 'GET' });
    const data = await response.json();
    return data.csrfToken || '';
  } catch (error) {
    console.error('Failed to fetch CSRF token:', error);
    return '';
  }
}

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_ASSETS))
      .then(() => console.log('Service worker installed and assets precached'))
      .catch(error => {
        console.error('Install failed:', error);
        if (typeof self.Sentry !== 'undefined') {
          self.Sentry.captureException(error, { tags: { context: 'install' } });
        }
      })
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames
            .filter(name => name !== CACHE_NAME)
            .map(name => caches.delete(name))
        );
      })
      .then(() => {
        console.log('Old caches cleared');
        return self.clients.claim();
      })
      .catch(error => {
        console.error('Activation failed:', error);
        if (typeof self.Sentry !== 'undefined') {
          self.Sentry.captureException(error, { tags: { context: 'activate' } });
        }
      })
  );
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Handle API requests
  if (url.pathname.startsWith('/api/') || url.pathname.includes('socket.io')) {
    event.respondWith(handleApiRequest(event, url));
    return;
  }

  // Handle Google Maps tiles
  if (url.pathname.includes('maps.googleapis.com') || url.pathname.includes('mt0.google.com/vt')) {
    event.respondWith(
      caches.match(event.request)
        .then(async cachedResponse => {
          const fetchPromise = fetchWithRetry(event.request)
            .then(networkResponse => {
              if (networkResponse.status === 200) {
                caches.open(CACHE_NAME).then(cache => {
                  cache.put(event.request, networkResponse.clone());
                  cache.put(`${event.request.url}-meta`, new Response(JSON.stringify({ cachedAt: Date.now() })));
                  cleanupMapTileCache(cache).catch(error => {
                    console.error('Cleanup failed:', error);
                    if (typeof self.Sentry !== 'undefined') {
                      self.Sentry.captureException(error, { tags: { context: 'cleanupMapTileCache' } });
                    }
                  });
                });
              }
              return networkResponse;
            })
            .catch(error => {
              console.warn('Map tile fetch failed, using cache:', url.pathname, error);
              if (typeof self.Sentry !== 'undefined') {
                self.Sentry.captureException(error, { tags: { context: 'mapTileFetch', url: url.pathname } });
              }
              return cachedResponse || new Response('Map tile unavailable. Please check your connection.', { status: 503 });
            });
          return cachedResponse || fetchPromise;
        })
        .catch(error => {
          console.error('Map tile cache match failed:', error);
          if (typeof self.Sentry !== 'undefined') {
            self.Sentry.captureException(error, { tags: { context: 'mapTileCacheMatch' } });
          }
          return new Response('Map tile unavailable. Please check your connection.', { status: 503 });
        })
    );
    return;
  }

  // Handle document requests
  if (event.request.destination === 'document' || url.pathname === '/' || url.pathname.includes('index.html')) {
    event.respondWith(
      fetchWithRetry(event.request)
        .then(networkResponse => {
          if (networkResponse.status === 200 && networkResponse.headers.get('content-type')?.includes('text/html')) {
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, networkResponse.clone());
            });
            return networkResponse;
          }
          throw new Error(`Invalid response: ${networkResponse.status}`);
        })
        .catch(async error => {
          console.log('Serving cached/offline for document:', url.pathname, error);
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
                  const token = localStorage.getItem('token') || sessionStorage.getItem('token');
                  const csrfToken = document.cookie.match(/csrfToken=([^;]+)/)?.[1] || '';
                  const celeb = document.createElement('div');
                  celeb.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);font-size:5rem;z-index:10003;animation:celebrate 2s ease-out forwards;pointer-events:none';
                  celeb.textContent = '🎉 Premium Unlocked!';
                  document.body.appendChild(celeb);
                  const style = document.createElement('style');
                  style.textContent = '@keyframes celebrate {0%{transform:translate(-50%,-50%) scale(0);opacity:0}50%{transform:translate(-50%,-50%) scale(1.5);opacity:1}100%{transform:translate(-50%,-50%) scale(1) translateY(-100px);opacity:0}}';
                  document.head.appendChild(style);
                  setTimeout(() => {celeb.remove(); style.remove();}, 2000);
                  if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.ready.then(reg => {
                      if (token) {
                        reg.active?.postMessage({ type: 'CHECK_SUBSCRIPTION', token, csrfToken });
                      }
                      const checkOnline = async () => {
                        if (navigator.onLine) {
                          try {
                            if (!token) throw new Error('No token found');
                            const res = await fetch('/api/subscription/status', { 
                              headers: { 
                                'Authorization': 'Bearer ' + token,
                                'X-CSRF-Token': csrfToken
                              } 
                            });
                            const data = await res.json();
                            if (data.isPremium) {
                              const cache = await caches.open('${CACHE_NAME}');
                              await cache.put('/api/subscription/status', new Response(JSON.stringify(data), { 
                                headers: { 'Content-Type': 'application/json', 'X-Cached-At': Date.now().toString() } 
                              }));
                              localStorage.setItem('subscriptionStatus', JSON.stringify(data));
                              setTimeout(() => location.reload(), 1000);
                            }
                          } catch (error) {
                            console.error('Subscription check failed:', error);
                            setTimeout(checkOnline, 2000);
                          }
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
              headers: { ...Object.fromEntries(cachedResponse.headers), 'Content-Type': 'text/html' }
            });
          }

          const offlineHTML = `
            <!DOCTYPE html>
            <html>
              <head>
                <title>Offline</title>
                <style>
                  body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 2rem;
                    background: #f0f0f0;
                    color: #333;
                  }
                  button {
                    background: #4CAF50;
                    color: white;
                    border: none;
                    padding: 1rem;
                    border-radius: 0.5rem;
                    cursor: pointer;
                    font-size: 1rem;
                  }
                </style>
              </head>
              <body>
                <h1>You're offline</h1>
                <p>Reconnect to access the app & verify subscription. Cached content unavailable.</p>
                ${isPaymentSuccess ? '<p>🎉 Payment success detected! Reconnecting to unlock Premium...</p>' : ''}
                ${isPaymentCancelled ? '<p>Payment cancelled.</p>' : ''}
                <button onclick="location.reload()">Reconnect & Refresh</button>
                <script>
                  if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.ready.then(reg => {
                      reg.active?.postMessage({ type: 'CHECK_SUBSCRIPTION' });
                    });
                  }
                  const checkOnline = () => {
                    if (navigator.onLine) {
                      location.reload();
                    } else {
                      setTimeout(checkOnline, 5000);
                    }
                  };
                  window.addEventListener('online', () => location.reload());
                  checkOnline();
                </script>
              </body>
            </html>
          `;
          return new Response(offlineHTML, {
            status: 503,
            headers: { 'Content-Type': 'text/html' }
          });
        })
    );
    return;
  }

  // Handle other assets
  event.respondWith(
    caches.match(event.request)
      .then(cachedResponse => {
        return cachedResponse || fetchWithRetry(event.request)
          .then(networkResponse => {
            if (networkResponse.status === 200) {
              caches.open(CACHE_NAME).then(cache => {
                cache.put(event.request, networkResponse.clone());
              });
            }
            return networkResponse;
          })
          .catch(error => {
            console.error('Fetch failed for asset:', url.pathname, error);
            if (typeof self.Sentry !== 'undefined') {
              self.Sentry.captureException(error, { tags: { context: 'assetFetch', url: url.pathname } });
            }
            return new Response('Resource unavailable offline.', { status: 503 });
          });
      })
  );
});

async function handleApiRequest(event, url) {
  if (url.pathname === '/api/subscription/status') {
    const cachedResponse = await caches.match(event.request);
    if (cachedResponse) {
      const cachedData = await cachedResponse.json();
      const cachedAt = parseInt(cachedResponse.headers.get('X-Cached-At') || '0');
      if (Date.now() - cachedAt < SUBSCRIPTION_CACHE_TTL) {
        console.log('Serving cached subscription status');
        return cachedResponse;
      }
    }
  }

  if (!navigator.onLine) {
    const cachedResponse = await caches.match(event.request);
    if (cachedResponse) {
      console.log('Serving cached API response:', url.pathname);
      return cachedResponse;
    }
    console.warn('Offline: API request queued:', url.pathname);
    return new Response(JSON.stringify({ error: 'Offline, request queued' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const networkResponse = await fetchWithRetry(event.request);
    if (networkResponse.status === 200 && url.pathname === '/api/subscription/status') {
      caches.open(CACHE_NAME).then(cache => {
        cache.put(event.request, networkResponse.clone());
        cache.put(event.request.url, new Response(networkResponse.clone().body, {
          headers: {
            'Content-Type': 'application/json',
            'X-Cached-At': Date.now().toString()
          }
        }));
      });
    }
    return networkResponse;
  } catch (error) {
    console.error('API fetch failed:', url.pathname, error);
    if (typeof self.Sentry !== 'undefined') {
      self.Sentry.captureException(error, { tags: { context: 'apiFetch', url: url.pathname } });
    }
    const cachedResponse = await caches.match(event.request);
    if (cachedResponse) {
      console.log('Serving cached API response after failure:', url.pathname);
      return cachedResponse;
    }
    return new Response(JSON.stringify({ error: 'Offline, no cached response available' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function generateTileUrls(bounds) {
  const urls = [];
  const zoomLevels = [16, 17, 18, 19];

  let API_KEY = '';
  let MAP_ID = '';

  try {
    const configResponse = await fetchWithRetry('/api/maps-config');
    if (configResponse.ok) {
      const config = await configResponse.json();
      API_KEY = config.apiKey;
      MAP_ID = config.mapId;
    } else {
      console.error('Failed to fetch maps config');
      return urls;
    }
  } catch (error) {
    console.error('Error fetching maps config:', error);
    if (typeof self.Sentry !== 'undefined') {
      self.Sentry.captureException(error, { tags: { context: 'fetchMapsConfig' } });
    }
    return urls;
  }

  if (!bounds || !isFinite(bounds.north) || !isFinite(bounds.south) ||
      !isFinite(bounds.east) || !isFinite(bounds.west) ||
      bounds.north <= bounds.south || bounds.east <= bounds.west) {
    console.error('Invalid bounds for tile generation:', bounds);
    if (typeof self.Sentry !== 'undefined') {
      self.Sentry.captureException(new Error('Invalid bounds for tile generation'), {
        tags: { context: 'generateTileUrls' },
        extra: { bounds }
      });
    }
    return urls;
  }

  for (const zoom of zoomLevels) {
    const scale = 1 << zoom;
    const maxTile = scale - 1;
    const topLeft = latLngToTile({ lat: bounds.north, lng: bounds.west }, zoom);
    const bottomRight = latLngToTile({ lat: bounds.south, lng: bounds.east }, zoom);

    for (let x = Math.max(0, topLeft.x); x <= Math.min(maxTile, bottomRight.x); x++) {
      for (let y = Math.max(0, topLeft.y); y <= Math.min(maxTile, bottomRight.y); y++) {
        const url = `https://mt0.google.com/vt?x=${x}&y=${y}&z=${zoom}&key=${API_KEY}&map_id=${MAP_ID}`;
        urls.push(url);
      }
    }
  }
  return urls.slice(0, MAX_CACHED_TILES);
}

function latLngToTile(latLng, zoom) {
  const scale = 1 << zoom;
  const worldCoordinate = project(latLng);
  const tileX = Math.floor(worldCoordinate.x * scale / 256);
  const tileY = Math.floor(worldCoordinate.y * scale / 256);
  return { x: tileX, y: tileY };
}

function project(latLng) {
  const siny = Math.sin((latLng.lat * Math.PI) / 180);
  const y = 0.5 - Math.log((1 + siny) / (1 - siny)) / (4 * Math.PI);
  return {
    x: (latLng.lng + 180) / 360,
    y: y
  };
}

async function cleanupMapTileCache(cache) {
  const keys = await cache.keys();
  const tileKeys = keys.filter(key => key.url.includes('mt0.google.com/vt'));
  const metaKeys = keys.filter(key => key.url.includes('-meta'));

  if (tileKeys.length <= MAX_CACHED_TILES) return;

  const tilesWithMeta = await Promise.all(
    tileKeys.map(async key => {
      const metaKey = keys.find(k => k.url === `${key.url}-meta`);
      if (metaKey) {
        const meta = await cache.match(metaKey);
        const metaData = await meta.json();
        return { key, cachedAt: metaData.cachedAt };
      }
      return { key, cachedAt: 0 };
    })
  );

  tilesWithMeta.sort((a, b) => a.cachedAt - b.cachedAt);
  const toDelete = tilesWithMeta.slice(0, tilesWithMeta.length - MAX_CACHED_TILES);

  await Promise.all(
    toDelete.map(async ({ key }) => {
      await cache.delete(key);
      await cache.delete(`${key.url}-meta`);
    })
  );

  console.log(`Cleaned up ${toDelete.length} old map tiles`);
}

self.addEventListener('message', async event => {
  const { type, region, queue, token, csrfToken } = event.data;

  if (type === 'CACHE_REGION') {
    try {
      const cache = await caches.open(CACHE_NAME);
      const tileUrls = await generateTileUrls(region.bounds);
      for (const url of tileUrls) {
        try {
          const response = await fetchWithRetry(url);
          if (response.ok) {
            await cache.put(url, response.clone());
            await cache.put(`${url}-meta`, new Response(JSON.stringify({ cachedAt: Date.now() })));
          }
        } catch (error) {
          console.error('Failed to cache tile:', url, error);
          if (typeof self.Sentry !== 'undefined') {
            self.Sentry.captureException(error, { tags: { context: 'cacheRegion', url } });
          }
        }
      }
      cachedRegions.set(region.name, { ...region, cachedAt: Date.now() });
      if (cachedRegions.size > MAX_REGION_CACHE_SIZE) {
        const oldest = [...cachedRegions.entries()].sort((a, b) => a[1].cachedAt - b[1].cachedAt)[0];
        cachedRegions.delete(oldest[0]);
      }
      console.log('Region cached:', region.name, 'Total regions:', cachedRegions.size);
      self.clients.matchAll().then(clients => {
        clients.forEach(client => client.postMessage({ type: 'REGION_CACHED', region: region.name }));
      });
    } catch (error) {
      console.error('Failed to cache region:', error);
      if (typeof self.Sentry !== 'undefined') {
        self.Sentry.captureException(error, { tags: { context: 'cacheRegion' } });
      }
    }
  }

  if (type === 'SYNC_REGIONS') {
    cachedRegions = new Map();
    for (const region of queue) {
      cachedRegions.set(region.name, { ...region, cachedAt: Date.now() });
    }
    console.log('Regions synced:', cachedRegions.size);
  }

  if (type === 'CHECK_SUBSCRIPTION' && token && navigator.onLine) {
    try {
      const response = await fetchWithRetry('/api/subscription/status', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-CSRF-Token': csrfToken
        }
      });
      if (response.ok) {
        const data = await response.json();
        const cache = await caches.open(CACHE_NAME);
        await cache.put('/api/subscription/status', new Response(JSON.stringify(data), {
          headers: { 'Content-Type': 'application/json', 'X-Cached-At': Date.now().toString() }
        }));
        self.clients.matchAll().then(clients => {
          clients.forEach(client => client.postMessage({ type: 'SUBSCRIPTION_UPDATED', data }));
        });
        console.log('Subscription status updated and cached');
      }
    } catch (error) {
      console.error('Failed to check subscription:', error);
      if (typeof self.Sentry !== 'undefined') {
        self.Sentry.captureException(error, { tags: { context: 'checkSubscription' } });
      }
    }
  }

  if (type === 'CLEAR_OLD_CACHE') {
    try {
      const cache = await caches.open(CACHE_NAME);
      const keys = await cache.keys();
      const now = Date.now();
      const toDelete = keys.filter(async key => {
        if (key.url.includes('-meta')) {
          const meta = await cache.match(key);
          const metaData = await meta.json();
          return now - metaData.cachedAt > REGION_STALE_AGE;
        }
        return false;
      });
      await Promise.all(toDelete.map(key => cache.delete(key)));
      console.log(`Cleared ${toDelete.length} stale cache entries`);
    } catch (error) {
      console.error('Failed to clear old cache:', error);
      if (typeof self.Sentry !== 'undefined') {
        self.Sentry.captureException(error, { tags: { context: 'clearOldCache' } });
      }
    }
  }

  if (type === 'OFFLINE_QUEUE') {
    if (navigator.onLine) {
      for (const action of queue) {
        try {
          switch (action.type) {
            case 'postAlert':
              await fetchWithRetry('/api/alerts', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${action.token}`,
                  'X-CSRF-Token': await getCsrfToken()
                },
                body: JSON.stringify(action.data)
              });
              break;
            case 'updateLocation':
              await fetchWithRetry('/api/location', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${action.token}`,
                  'X-CSRF-Token': await getCsrfToken()
                },
                body: JSON.stringify(action.data)
              });
              break;
            case 'subscriptionCheckout':
              const checkoutResponse = await fetchWithRetry('/api/subscription/create-checkout', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${action.token}`,
                  'X-CSRF-Token': await getCsrfToken()
                },
                body: JSON.stringify(action.data)
              });
              if (checkoutResponse.ok) {
                const { url } = await checkoutResponse.json();
                self.clients.matchAll().then(clients => {
                  clients.forEach(client => client.postMessage({ type: 'REDIRECT_CHECKOUT', url }));
                });
              }
              break;
            case 'subscriptionCancel':
              await fetchWithRetry('/api/subscription/cancel', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${action.token}`,
                  'X-CSRF-Token': await getCsrfToken()
                },
                body: JSON.stringify(action.data)
              });
              break;
          }
          console.log(`Processed offline action: ${action.type}`);
        } catch (error) {
          console.error(`Failed to process offline action ${action.type}:`, error);
          if (typeof self.Sentry !== 'undefined') {
            self.Sentry.captureException(error, { tags: { context: 'offlineQueue', actionType: action.type } });
          }
        }
      }
      self.clients.matchAll().then(clients => {
        clients.forEach(client => client.postMessage({ type: 'OFFLINE_QUEUE_PROCESSED', queue }));
      });
    }
  }
});