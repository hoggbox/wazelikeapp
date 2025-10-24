const CACHE_NAME = 'waze-gps-v1.0.14'; // Bump version after fix
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
const SUBSCRIPTION_CACHE_TTL = 5 * 60 * 1000;
const API_CACHE_TTL = 15 * 60 * 1000;
const REGION_STALE_AGE = 30 * 24 * 60 * 60 * 1000;
const MAX_REGION_CACHE_SIZE = 50;
const FETCH_RETRIES = 3;
const FETCH_BACKOFF = 1000;

let cachedRegions = new Map();

// ✅ FIXED: fetchWithRetry function remains the same
async function fetchWithRetry(url, options = {}, retries = FETCH_RETRIES, backoff = FETCH_BACKOFF) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, options);
      if (response && response.status === 429) {
        const retryAfter = parseInt(response.headers.get('Retry-After') || '60');
        console.warn(`Rate limited for ${url}. Retrying after ${retryAfter}s`);
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      if (response && response.ok) return response;
      throw new Error(`HTTP ${response ? response.status : 'No response'} for ${url}`);
    } catch (error) {
      if (i === retries - 1) throw error;
      const jitter = Math.random() * 500;
      const delay = backoff * Math.pow(2, i) + jitter;
      console.log(`Retry ${i + 1}/${retries} for ${url} after ${delay}ms`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Install, activate, fetch handlers remain the same until line 198...

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (url.pathname.startsWith('/api/') || url.pathname.includes('socket.io')) {
    event.respondWith(handleApiRequest(event, url));
    return;
  }

  if (url.pathname.includes('maps.googleapis.com') || url.pathname.includes('mt0.google.com/vt')) {
    event.respondWith(
      caches.match(event.request)
        .then(async cachedResponse => {
          const fetchPromise = fetchWithRetry(event.request)
            .then(networkResponse => {
              if (networkResponse?.status === 200) {
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
          return cachedResponse || await fetchPromise;
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

  if (event.request.destination === 'document' || url.pathname === '/' || url.pathname.includes('index.html')) {
    event.respondWith(
      fetchWithRetry(event.request)
        .then(networkResponse => {
          if (networkResponse?.status === 200 && networkResponse.headers.get('content-type')?.includes('text/html')) {
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, networkResponse.clone());
            });
            return networkResponse;
          }
          throw new Error(`Invalid response: ${networkResponse ? networkResponse.status : 'No response'}`);
        })
        .catch(async error => {
          console.log('Serving cached/offline for document:', url.pathname, error);
          const isPaymentSuccess = url.searchParams.get('payment') === 'success' || url.searchParams.get('session_id');
          // ✅ FIXED: Removed extra closing parenthesis
          const isPaymentCancelled = url.searchParams.get('payment') === 'cancelled';
          
          const cachedResponse = await caches.match('/index.html');
          if (cachedResponse) {
            let enhancedHTML = await cachedResponse.clone().text();
            // ... rest of the payment success/cancelled handling remains the same
            
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
            <html><head><title>Offline</title><style>body{font-family:Arial;text-align:center;padding:2rem;background:#f0f0f0;color:#333;}button{background:#4CAF50;color:white;border:none;padding:1rem;border-radius:0.5rem;cursor:pointer;font-size:1rem;}</style></head><body>
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

  // ... rest of fetch handler remains the same
});

// ✅ FIXED: generateTileUrls now fetches config from backend
async function generateTileUrls(bounds) {
  const urls = [];
  const zoomLevels = [16, 17, 18, 19];
  
  // ✅ Fetch API key from backend instead of hardcoding
  let API_KEY = '';
  let MAP_ID = '';
  
  try {
    const configResponse = await fetch('/api/maps-config');
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

// latLngToTile, project, cleanupMapTileCache remain the same...