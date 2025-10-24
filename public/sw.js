const CACHE_NAME = 'waze-gps-v1.0.10';
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

let cachedRegions = new Map();

self.addEventListener('install', event => {
  console.log('Service Worker installing:', CACHE_NAME);
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_ASSETS))
      .catch(error => {
        console.error('Precache failed:', error);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'serviceWorkerInstall' } });
        }
        throw error;
      })
      .then(() => {
        console.log('Service Worker installed, forcing activation');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('Install failed:', error);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'install' } });
        }
      })
  );
});

self.addEventListener('activate', event => {
  console.log('Service Worker activating:', CACHE_NAME);
  event.waitUntil(
    caches.keys()
      .then(cacheNames => Promise.all(
        cacheNames
          .filter(cacheName => cacheName !== CACHE_NAME)
          .map(cacheName => {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          })
      ))
      .then(() => {
        cachedRegions = new Map();
        console.log('Service Worker activated, claiming clients, reset cachedRegions');
        return self.clients.claim();
      })
      .catch(error => {
        console.error('Activation failed:', error);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'activate' } });
        }
      })
  );
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (url.pathname.startsWith('/api/') || url.pathname.includes('socket.io')) {
    event.respondWith(handleApiRequest(event, url));
    return;
  }

  if (url.pathname.includes('maps.googleapis.com') || url.pathname.includes('mt0.google.com/vt')) {
    event.respondWith(
      caches.match(event.request)
        .then(cachedResponse => {
          const fetchPromise = fetch(event.request)
            .then(networkResponse => {
              if (networkResponse?.status === 200) {
                caches.open(CACHE_NAME).then(cache => {
                  cache.put(event.request, networkResponse.clone());
                  cache.put(`${event.request.url}-meta`, new Response(JSON.stringify({ cachedAt: Date.now() })));
                  cleanupMapTileCache(cache).catch(error => {
                    console.error('Cleanup failed:', error);
                    if (self.Sentry) {
                      self.Sentry.captureException(error, { tags: { context: 'cleanupMapTileCache' } });
                    }
                  });
                });
              }
              return networkResponse;
            })
            .catch(error => {
              console.warn('Map tile fetch failed, using cache:', url.pathname, error);
              if (self.Sentry) {
                self.Sentry.captureException(error, { tags: { context: 'mapTileFetch', url: url.pathname } });
              }
              return cachedResponse || new Response('Map tile unavailable', { status: 503 });
            });
          return cachedResponse || fetchPromise;
        })
        .catch(error => {
          console.error('Map tile cache match failed:', error);
          if (self.Sentry) {
            self.Sentry.captureException(error, { tags: { context: 'mapTileCacheMatch' } });
          }
          return new Response('Map tile unavailable', { status: 503 });
        })
    );
    return;
  }

  if (event.request.destination === 'document' || url.pathname === '/' || url.pathname.includes('index.html')) {
    event.respondWith(
      fetch(event.request)
        .then(networkResponse => {
          if (networkResponse?.status === 200 && networkResponse.headers.get('content-type')?.includes('text/html')) {
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, networkResponse.clone());
            });
            return networkResponse;
          }
          throw new Error(`Invalid response: ${networkResponse?.status || 'No response'}`);
        })
        .catch(async error => {
          console.log('Serving Cached/offline for document:', url.pathname, error);
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
                  const token = localStorage.getItem('token');
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
                              location.reload();
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

  event.respondWith(
    caches.open(CACHE_NAME)
      .then(cache => cache.match(event.request)
        .then(cachedResponse => {
          const fetchPromise = fetch(event.request)
            .then(networkResponse => {
              if (networkResponse?.status === 200 && networkResponse.type === 'basic') {
                cache.put(event.request, networkResponse.clone());
              }
              return networkResponse;
            })
            .catch(error => {
              console.log('Network fetch failed, using cache for:', url.pathname, error);
              if (self.Sentry) {
                self.Sentry.captureException(error, { tags: { context: 'fetchDefault', url: event.request.url } });
              }
              return cachedResponse || new Response('Resource unavailable', { status: 503 });
            });
          return cachedResponse || fetchPromise;
        })
      )
      .catch(error => {
        console.error('Fetch failed:', error, 'URL:', event.request.url);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'fetchDefault', url: event.request.url } });
        }
        return new Response('Resource unavailable', { status: 503 });
      })
  );
});

async function handleApiRequest(event, url) {
  const isSubscriptionPath = url.pathname === '/api/subscription/status' && event.request.method === 'GET';
  const isFamilyPath = url.pathname === '/api/users/family' && event.request.method === 'GET';
  const isAuthPath = url.pathname.startsWith('/api/auth');
  const isAlertPath = url.pathname.startsWith('/api/alerts');

  try {
    if (isSubscriptionPath) {
      return await fetch(event.request)
        .then(async networkResponse => {
          if (networkResponse?.status === 200) {
            const cache = await caches.open(CACHE_NAME);
            const responseWithTTL = new Response(await networkResponse.clone().text(), {
              headers: {
                ...Object.fromEntries(networkResponse.headers),
                'X-Cached-At': Date.now().toString()
              }
            });
            await cache.put('/api/subscription/status', responseWithTTL);
            console.log('Cached subscription status response');
            return networkResponse;
          }
          throw new Error(`Invalid subscription status response: ${networkResponse?.status}`);
        })
        .catch(async error => {
          console.warn('Subscription fetch failed:', error);
          const cachedStatus = await caches.match('/api/subscription/status');
          if (cachedStatus) {
            const cachedAt = parseInt(cachedStatus.headers.get('X-Cached-At') || '0');
            if (Date.now() - cachedAt < SUBSCRIPTION_CACHE_TTL) {
              console.log('Serving cached subscription status');
              return cachedStatus;
            }
            console.log('Cached subscription status expired');
          }
          return new Response(JSON.stringify({
            error: 'Offline: Cannot verify subscription',
            offline: true,
            suggest: 'Reconnect to check subscription status'
          }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' }
          });
        });
    }

    if (isFamilyPath) {
      return await fetch(event.request)
        .then(async networkResponse => {
          if (networkResponse?.status === 200) {
            const cache = await caches.open(CACHE_NAME);
            const responseWithTTL = new Response(await networkResponse.clone().text(), {
              headers: {
                ...Object.fromEntries(networkResponse.headers),
                'X-Cached-At': Date.now().toString()
              }
            });
            await cache.put(event.request, responseWithTTL);
            console.log('Cached family members response');
            return networkResponse;
          }
          throw new Error(`Invalid family members response: ${networkResponse?.status}`);
        })
        .catch(async error => {
          console.warn('Family fetch failed:', error);
          const cachedResponse = await caches.match(event.request);
          if (cachedResponse) {
            const cachedAt = parseInt(cachedResponse.headers.get('X-Cached-At') || '0');
            if (Date.now() - cachedAt < API_CACHE_TTL) {
              console.log('Serving cached family members');
              return cachedResponse;
            }
            console.log('Cached family members expired');
          }
          return new Response(JSON.stringify({
            error: 'Offline: Cannot fetch family members',
            offline: true,
            suggest: 'Reconnect to view family members'
          }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' }
          });
        });
    }

    if (isAlertPath) {
      return await fetch(event.request)
        .then(async networkResponse => {
          if (networkResponse?.status === 200) {
            const cache = await caches.open(CACHE_NAME);
            const responseWithTTL = new Response(await networkResponse.clone().text(), {
              headers: {
                ...Object.fromEntries(networkResponse.headers),
                'X-Cached-At': Date.now().toString()
              }
            });
            await cache.put(event.request, responseWithTTL);
            console.log('Cached alerts response:', event.request.url);
            return networkResponse;
          }
          throw new Error(`Invalid alerts response: ${networkResponse?.status}`);
        })
        .catch(async error => {
          console.warn('Alerts fetch failed:', error);
          const cachedResponse = await caches.match(event.request);
          if (cachedResponse) {
            const cachedAt = parseInt(cachedResponse.headers.get('X-Cached-At') || '0');
            if (Date.now() - cachedAt < API_CACHE_TTL) {
              console.log('Serving cached alerts:', event.request.url);
              return cachedResponse;
            }
            console.log('Cached alerts expired');
          }
          return new Response(JSON.stringify({
            error: 'Offline: Cannot fetch alerts',
            offline: true,
            suggest: 'Reconnect to view alerts'
          }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' }
          });
        });
    }

    return await fetch(event.request)
      .catch(error => {
        console.error('API/Socket fetch failed:', error, 'URL:', event.request.url);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'fetchAPI', url: event.request.url } });
        }
        const suggest = isSubscriptionPath ? 'Reconnect to verify subscription' :
                        isAuthPath ? 'Reconnect and refresh token' :
                        isFamilyPath ? 'Reconnect to sync family data' :
                        isAlertPath ? 'Reconnect to sync alerts' :
                        'Check connection';
        return new Response(JSON.stringify({ 
          error: 'Network unavailable', 
          offline: true, 
          suggest 
        }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      });
  } catch (error) {
    console.error('API request handling failed:', error);
    if (self.Sentry) {
      self.Sentry.captureException(error, { tags: { context: 'handleApiRequest', url: event.request.url } });
    }
    return new Response(JSON.stringify({ 
      error: 'Service Worker error', 
      offline: true, 
      suggest: 'Try again later'
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

self.addEventListener('message', async event => {
  try {
    if (event.data?.type === 'CACHE_REGION' && event.data.region) {
      const { bounds, name, timestamp } = event.data.region;
      if (!bounds || !isFinite(bounds.north) || !isFinite(bounds.south) || 
          !isFinite(bounds.east) || !isFinite(bounds.west)) {
        console.error('Invalid region bounds:', bounds);
        if (self.Sentry) {
          self.Sentry.captureException(new Error('Invalid region bounds'), { 
            tags: { context: 'cacheRegion' }, 
            extra: { bounds } 
          });
        }
        return;
      }
      const cache = await caches.open(CACHE_NAME);
      const tileUrls = generateTileUrls(bounds);
      for (const url of tileUrls) {
        try {
          const response = await fetch(url);
          if (response?.status === 200) {
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
      cachedRegions.set(name, { bounds, cachedAt: new Date(timestamp).getTime() });
      console.log('Cached map tiles for region:', name, bounds);
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({ type: 'REGION_CACHED', region: name });
      });
      await cleanupMapTileCache(cache);
    } else if (event.data?.type === 'SYNC_REGIONS' && event.data.regions) {
      const cache = await caches.open(CACHE_NAME);
      const clientRegions = new Map(event.data.regions.map(r => 
        [r.name, { bounds: r.bounds, cachedAt: new Date(r.timestamp).getTime() }]
      ));
      for (const [name, region] of cachedRegions) {
        if (!clientRegions.has(name)) {
          const tileUrls = generateTileUrls(region.bounds);
          for (const url of tileUrls) {
            await cache.delete(url);
            await cache.delete(`${url}-meta`);
            console.log('Deleted tiles for removed region:', name, url);
          }
          cachedRegions.delete(name);
        }
      }
      cachedRegions = clientRegions;
      console.log('Synced cached regions:', Array.from(cachedRegions.keys()));
      await cleanupMapTileCache(cache);
    } else if (event.data?.type === 'CHECK_SUBSCRIPTION') {
      const cache = await caches.open(CACHE_NAME);
      try {
        const token = event.data.token;
        const csrfToken = event.data.csrfToken || '';
        if (!token) throw new Error('No token provided for subscription check');
        const response = await fetch('/api/subscription/status', {
          headers: { 
            'Authorization': `Bearer ${token}`,
            'X-CSRF-Token': csrfToken
          }
        });
        if (response?.status === 200) {
          const responseWithTTL = new Response(await response.clone().text(), {
            headers: {
              ...Object.fromEntries(response.headers),
              'X-Cached-At': Date.now().toString()
            }
          });
          await cache.put('/api/subscription/status', responseWithTTL);
          console.log('Subscription status cached after payment');
          const clients = await self.clients.matchAll();
          clients.forEach(client => {
            client.postMessage({ type: 'SUBSCRIPTION_UPDATED' });
          });
        }
      } catch (error) {
        console.error('Error checking subscription in SW:', error);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'checkSubscription' } });
        }
      }
    } else if (event.data?.type === 'OFFLINE_QUEUE' && event.data.queue) {
      const cache = await caches.open(CACHE_NAME);
      for (const action of event.data.queue) {
        try {
          let url, method = 'POST', body = JSON.stringify(action.data || {});
          const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${action.token || ''}`,
            'X-CSRF-Token': action.csrfToken || ''
          };
          switch (action.type) {
            case 'postAlert':
              url = '/api/alerts';
              break;
            case 'updateLocation':
              url = '/api/location';
              break;
            case 'subscriptionCheckout':
              url = '/api/subscription/create-checkout';
              break;
            case 'subscriptionCancel':
              url = '/api/subscription/cancel';
              break;
            default:
              console.warn('Unknown offline action type:', action.type);
              continue;
          }
          const response = await fetch(url, { method, headers, body });
          if (response.ok && action.type === 'subscriptionCheckout') {
            const { url: redirectUrl } = await response.json();
            const clients = await self.clients.matchAll();
            clients.forEach(client => {
              client.postMessage({ type: 'REDIRECT_CHECKOUT', url: redirectUrl });
            });
          }
          if (response.ok && action.type === 'subscriptionCancel') {
            await cache.put('/api/subscription/status', new Response(JSON.stringify({ 
              isPremium: false, 
              isTrialActive: false 
            }), {
              headers: { 
                'Content-Type': 'application/json',
                'X-Cached-At': Date.now().toString()
              }
            }));
          }
          console.log('Processed offline action:', action.type);
        } catch (error) {
          console.error('Failed to process offline action:', action.type, error);
          if (self.Sentry) {
            self.Sentry.captureException(error, { tags: { context: 'offlineQueue', action: action.type } });
          }
          const clients = await self.clients.matchAll();
          clients.forEach(client => {
            client.postMessage({ type: 'REQUEUE_ACTION', action });
          });
        }
      }
    } else if (event.data?.type === 'CLEAR_OLD_CACHE') {
      const cacheNames = await caches.keys();
      await Promise.all(
        cacheNames
          .filter(cacheName => cacheName !== CACHE_NAME)
          .map(cacheName => {
            console.log('Clearing old cache on message:', cacheName);
            return caches.delete(cacheName);
          })
      );
    }
  } catch (error) {
    console.error('Message event handling failed:', error);
    if (self.Sentry) {
      self.Sentry.captureException(error, { tags: { context: 'messageEvent' } });
    }
  }
});

self.addEventListener('push', event => {
  const origin = new URL(self.registration.scope).origin;
  let data;
  try {
    data = event.data?.json() || { title: 'New Alert', body: 'A new alert has been posted nearby.' };
    if (!data.title || !data.body) {
      throw new Error('Invalid notification payload');
    }
  } catch (error) {
    console.error('Error parsing push data:', error);
    if (self.Sentry) {
      self.Sentry.captureException(error, { tags: { context: 'pushEvent' } });
    }
    data = { title: 'New Alert', body: 'A new alert has been posted nearby.' };
  }

  const options = {
    body: data.body,
    icon: 'https://i.postimg.cc/jjN0JrPZ/New-Project-5.png',
    badge: 'https://i.postimg.cc/YS0h0m7R/compass.png',
    data: {
      url: data.url || (data.type === 'subscription' ? 
        `${origin}/?payment=${data.status || ''}&session_id=${data.sessionId || ''}` : 
        data.type === 'familyAlert' ?
        `${origin}/?alertId=${data.alertId || ''}&lat=${data.lat || ''}&lng=${data.lng || ''}&familyEmail=${data.email || ''}` :
        `${origin}/?alertId=${data.alertId || ''}&lat=${data.lat || ''}&lng=${data.lng || ''}`)
    }
  };

  if (data.type === 'subscription') {
    options.title = data.status === 'success' ? '🎉 Premium Unlocked!' :
                    data.status === 'trial_ending' ? '⏰ Trial Ending Soon' :
                    'Subscription Update';
    options.body = data.status === 'success' ? 'Your premium subscription is active. Enjoy all features!' :
                   data.status === 'trial_ending' ? `Your trial ends in ${data.daysRemaining || 'unknown'} days. Upgrade now!` :
                   data.body || 'Check your subscription status.';
  } else if (data.type === 'familyAlert') {
    options.title = `Family Alert from ${data.email || 'Unknown'}`;
    options.body = `A ${data.alertType || 'hazard'} alert was posted by a family member.`;
  }

  event.waitUntil(
    self.registration.showNotification(options.title, options)
      .catch(error => {
        console.error('Notification display failed:', error);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'pushNotification' } });
        }
      })
  );
  console.log('Push notification received:', data);
});

self.addEventListener('notificationclick', event => {
  const origin = new URL(self.registration.scope).origin;
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(clientList => {
        const url = event.notification.data?.url || origin;
        for (const client of clientList) {
          if (client.url === url && 'focus' in client) {
            return client.focus();
          }
        }
        if (clients.openWindow) {
          return clients.openWindow(url);
        }
      })
      .catch(error => {
        console.error('Notification click handling failed:', error);
        if (self.Sentry) {
          self.Sentry.captureException(error, { tags: { context: 'notificationClick' } });
        }
      })
  );
  console.log('Notification clicked, opening:', event.notification.data?.url);
});

function generateTileUrls(bounds) {
  const urls = [];
  const zoomLevels = [16, 17, 18, 19];
  const tileSize = 256;
  const { north, south, east, west } = bounds;
  const API_KEY = 'AIzaSyBSW8iQAE1AjjouEu4df-Cvq1ceUMLBit4';
  const MAP_ID = '2666b5bd496d9c6026f43f82';

  if (!isFinite(north) || !isFinite(south) || !isFinite(east) || !isFinite(west) || 
      north <= south || east <= west) {
    console.error('Invalid bounds for tile generation:', bounds);
    if (self.Sentry) {
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
    const topLeft = latLngToTile({ lat: north, lng: west }, zoom);
    const bottomRight = latLngToTile({ lat: south, lng: east }, zoom);

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
  if (!latLng?.lat || !latLng?.lng || !isFinite(latLng.lat) || !isFinite(latLng.lng)) {
    console.error('Invalid latLng for tile conversion:', latLng);
    if (self.Sentry) {
      self.Sentry.captureException(new Error('Invalid latLng for tile conversion'), { 
        tags: { context: 'latLngToTile' }, 
        extra: { latLng } 
      });
    }
    return { x: 0, y: 0 };
  }
  const scale = 1 << zoom;
  const worldCoordinate = project(latLng);
  return {
    x: Math.floor(worldCoordinate.x * scale),
    y: Math.floor(worldCoordinate.y * scale)
  };
}

function project(latLng) {
  const siny = Math.sin((latLng.lat * Math.PI) / 180);
  const y = 0.5 - Math.log((1 + siny) / (1 - siny)) / (4 * Math.PI);
  return {
    x: Math.max(0, Math.min(1, (latLng.lng + 180) / 360)),
    y: Math.max(0, Math.min(1, y))
  };
}

async function cleanupMapTileCache(cache) {
  try {
    const cacheInstance = cache || await caches.open(CACHE_NAME);
    const requests = await cacheInstance.keys();
    const tileRequests = requests.filter(req => req.url.includes('mt0.google.com/vt'));
    const now = Date.now();

    const tilesWithMetadata = [];
    for (const req of tileRequests) {
      const metaResponse = await cacheInstance.match(`${req.url}-meta`);
      let cachedAt = 0;
      if (metaResponse) {
        try {
          const meta = await metaResponse.json();
          cachedAt = meta.cachedAt || 0;
        } catch (error) {
          console.error('Failed to parse tile metadata:', req.url, error);
          if (self.Sentry) {
            self.Sentry.captureException(error, { tags: { context: 'parseTileMetadata', url: req.url } });
          }
        }
      }
      tilesWithMetadata.push({ request: req, cachedAt });
    }

    tilesWithMetadata.sort((a, b) => a.cachedAt - b.cachedAt);
    for (const [name, region] of cachedRegions) {
      if (now - region.cachedAt > REGION_STALE_AGE) {
        const tileUrls = generateTileUrls(region.bounds);
        for (const url of tileUrls) {
          await cacheInstance.delete(url);
          await cacheInstance.delete(`${url}-meta`);
          console.log('Deleted tiles for stale region:', name, url);
        }
        cachedRegions.delete(name);
      }
    }

    for (const { request, cachedAt } of tilesWithMetadata) {
      let isInRegion = false;
      for (const [, region] of cachedRegions) {
        const zoom = parseInt(new URL(request.url).searchParams.get('z') || '16');
        const x = parseInt(new URL(request.url).searchParams.get('x') || '0');
        const y = parseInt(new URL(request.url).searchParams.get('y') || '0');
        const regionTopLeft = latLngToTile({ lat: region.bounds.north, lng: region.bounds.west }, zoom);
        const regionBottomRight = latLngToTile({ lat: region.bounds.south, lng: region.bounds.east }, zoom);
        if (x >= regionTopLeft.x && x <= regionBottomRight.x && y >= regionTopLeft.y && y <= regionBottomRight.y) {
          isInRegion = true;
          break;
        }
      }
      if (!isInRegion || now - cachedAt > REGION_STALE_AGE) {
        await cacheInstance.delete(request);
        await cacheInstance.delete(`${request.url}-meta`);
        console.log('Deleted stale or excess map tile:', request.url);
      }
    }

    const updatedRequests = await cacheInstance.keys();
    const updatedTileRequests = updatedRequests.filter(req => req.url.includes('mt0.google.com/vt'));
    if (updatedTileRequests.length > MAX_CACHED_TILES) {
      const allTilesWithMeta = [];
      for (const req of updatedTileRequests) {
        const metaResp = await cacheInstance.match(`${req.url}-meta`);
        let cachedAt = 0;
        if (metaResp) {
          try {
            const meta = await metaResp.json();
            cachedAt = meta.cachedAt || 0;
          } catch {}
        }
        allTilesWithMeta.push({ request: req, cachedAt });
      }
      allTilesWithMeta.sort((a, b) => a.cachedAt - b.cachedAt);
      const toDeleteCount = allTilesWithMeta.length - MAX_CACHED_TILES;
      for (let i = 0; i < toDeleteCount; i++) {
        const tile = allTilesWithMeta[i];
        await cacheInstance.delete(tile.request);
        await cacheInstance.delete(`${tile.request.url}-meta`);
        console.log('Deleted oldest tile to enforce limit:', tile.request.url);
      }
    }

    if (navigator.storage?.estimate) {
      const { quota, usage } = await navigator.storage.estimate();
      console.log('Storage usage:', { usage: (usage / 1024 / 1024).toFixed(2) + 'MB', quota: (quota / 1024 / 1024).toFixed(2) + 'MB' });
      if (usage / quota > 0.8) {
        console.warn('Storage quota nearly exceeded, forcing cleanup');
        const currentRequests = await cacheInstance.keys();
        const currentTileRequests = currentRequests.filter(req => req.url.includes('mt0.google.com/vt'));
        const halfCount = Math.floor(currentTileRequests.length / 2);
        for (let i = 0; i < halfCount; i++) {
          const req = currentTileRequests[i];
          await cacheInstance.delete(req);
          await cacheInstance.delete(`${req.url}-meta`);
          console.log('Deleted tile to free up storage:', req.url);
        }
      }
    }
  } catch (error) {
    console.error('Map tile cleanup failed:', error);
    if (self.Sentry) {
      self.Sentry.captureException(error, { tags: { context: 'cleanupMapTileCache' } });
    }
  }
}