const CACHE_NAME = 'waze-gps-v1.0.5'; // Keep version unless other changes warrant a bump

// Precache critical assets during install
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll([
        '/',
        '/index.html',
        '/manifest.json',
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css',
        'https://unpkg.com/@tweenjs/tween.js@23.1.3/dist/tween.umd.js',
        'https://cdn.socket.io/4.7.5/socket.io.min.js',
        'https://browser.sentry-cdn.com/7.x.x/bundle.min.js',
        'https://i.postimg.cc/YS0h0m7R/compass.png',
        'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png' // Traffic camera icon
      ]).catch(error => {
        console.error('Precache failed:', error);
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
      fetch(event.request).catch(error => {
        console.error('API fetch failed (check auth/token/subscription):', error, 'URL:', event.request.url);
        const isSubscriptionPath = url.pathname.startsWith('/api/subscription');
        const isAuthPath = url.pathname.startsWith('/api/auth');
        return new Response(JSON.stringify({ 
          error: 'Network unavailable', 
          offline: true, 
          suggest: isSubscriptionPath ? 'Reconnect to verify subscription' : isAuthPath ? 'Reconnect and refresh token' : 'Check connection' 
        }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // Handle map tile requests
  if (url.pathname.includes('maps.googleapis.com/maps/api')) {
    event.respondWith(
      caches.match(event.request).then(cachedResponse => {
        const fetchPromise = fetch(event.request).then(networkResponse => {
          if (networkResponse && networkResponse.status === 200) {
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, networkResponse.clone());
            });
          }
          return networkResponse;
        }).catch(() => cachedResponse || new Response('Map tile unavailable', { status: 503 }));
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
        .catch(() => {
          console.log('Serving cached/offline for document:', url.pathname);
          const isPaymentSuccess = url.searchParams.get('payment') === 'success' || url.searchParams.get('session_id');
          const isPaymentCancelled = url.searchParams.get('payment') === 'cancelled';
          
          return caches.match('/index.html').then(cachedResponse => {
            if (cachedResponse) {
              let enhancedHTML = cachedResponse.clone().text();
              if (isPaymentSuccess) {
                enhancedHTML = enhancedHTML.then(html => html.replace(
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
                ));
              } else if (isPaymentCancelled) {
                enhancedHTML = enhancedHTML.then(html => html.replace(
                  '</body>',
                  `<script>alert('Payment cancelled. You can upgrade anytime from Settings.');</script></body>`
                ));
              }
              return new Response(enhancedHTML, {
                headers: cachedResponse.headers
              });
            }
            const offlineHTML = `
              <!DOCTYPE html>
              <html><head><title>Offline</title><style>body{font-family:Arial;text-align:center;padding:2rem;background:#f0f0f0;color:#333;}button{background:#4CAF50;color:white;border:none;padding:1rem;border-radius:0.5rem;cursor:pointer;font-size:1rem;}</style></head><body>
                <h1>You're offline</h1>
                <p>Reconnect to access the app & verify subscription. Cached content available.</p>
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
    })
  );
  event.waitUntil(clients.claim());
});

// Handle offline map region caching
self.addEventListener('message', async event => {
  if (event.data.type === 'CACHE_REGION' && event.data.region) {
    const { bounds } = event.data.region;
    try {
      const cache = await caches.open(CACHE_NAME);
      // Generate tile URLs for the region (simplified example)
      const tileUrls = generateTileUrls(bounds);
      for (const url of tileUrls) {
        try {
          const response = await fetch(url);
          if (response && response.status === 200) {
            await cache.put(url, response);
            console.log('Cached map tile:', url);
          }
        } catch (error) {
          console.error('Failed to cache map tile:', url, error);
        }
      }
      console.log('Cached map tiles for region:', bounds);
    } catch (error) {
      console.error('Error caching region:', error);
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
  }
});

// Generate tile URLs for a given bounds (simplified)
function generateTileUrls(bounds) {
  const urls = [];
  const zoomLevels = [15, 16, 17, 18, 19]; // Adjust based on app's zoom config
  const tileSize = 256;
  const { north, south, east, west } = bounds;

  for (const zoom of zoomLevels) {
    const scale = 1 << zoom;
    const topLeft = latLngToTile({ lat: north, lng: west }, zoom);
    const bottomRight = latLngToTile({ lat: south, lng: east }, zoom);

    for (let x = topLeft.x; x <= bottomRight.x; x++) {
      for (let y = topLeft.y; y <= bottomRight.y; y++) {
        const url = `https://maps.googleapis.com/maps/api/staticmap?center=${(north + south) / 2},${(east + west) / 2}&zoom=${zoom}&size=${tileSize}x${tileSize}&maptype=roadmap&key=AIzaSyBSW8iQAE1AjjouEu4df-Cvq1ceUMLBit4`;
        urls.push(url);
      }
    }
  }
  return urls;
}

// Convert lat/lng to tile coordinates
function latLngToTile(latLng, zoom) {
  const scale = 1 << zoom;
  const worldCoordinate = project(latLng);
  const tileCoordinate = {
    x: Math.floor(worldCoordinate.x * scale / 256),
    y: Math.floor(worldCoordinate.y * scale / 256)
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