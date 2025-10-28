const CACHE_NAME = 'waze-gps-v' + Date.now(); // Force bust on every deploy

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
          // Check for payment callback params
          const isPaymentSuccess = url.searchParams.get('payment') === 'success' || url.searchParams.get('session_id');
          const isPaymentCancelled = url.searchParams.get('payment') === 'cancelled';
          
          return caches.match('/index.html').then(cachedResponse => {
            if (cachedResponse) {
              let enhancedHTML = cachedResponse.clone().text();
              if (isPaymentSuccess) {
                // Inject celebration and force subscription check/reload on online
                enhancedHTML = enhancedHTML.then(html => html.replace(
                  '</body>',
                  `
                  <script>
                    // Mini celebration (mimic app)
                    const celeb = document.createElement('div');
                    celeb.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);font-size:5rem;z-index:10003;animation:celebrate 2s ease-out forwards;pointer-events:none';
                    celeb.textContent = '🎉 Premium Unlocked!';
                    document.body.appendChild(celeb);
                    const style = document.createElement('style');
                    style.textContent = '@keyframes celebrate {0%{transform:translate(-50%,-50%) scale(0);opacity:0}50%{transform:translate(-50%,-50%) scale(1.5);opacity:1}100%{transform:translate(-50%,-50%) scale(1) translateY(-100px);opacity:0}}';
                    document.head.appendChild(style);
                    setTimeout(() => {celeb.remove(); style.remove();}, 2000);
                    
                    // Force subscription check and reload on reconnect
                    if ('serviceWorker' in navigator) {
                      navigator.serviceWorker.ready.then(() => {
                        // Poll for online and reload
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
            // Enhanced offline HTML with reconnect logic and payment awareness
            const offlineHTML = `
              <!DOCTYPE html>
              <html><head><title>Offline</title><style>body{font-family:Arial;text-align:center;padding:2rem;background:#f0f0f0;color:#333;}button{background:#4CAF50;color:white;border:none;padding:1rem;border-radius:0.5rem;cursor:pointer;font-size:1rem;}</style></head><body>
                <h1>You're offline</h1>
                <p>Reconnect to access the app & verify subscription. Cached content available.</p>
                ${isPaymentSuccess ? '<p>🎉 Payment success detected! Reconnecting to unlock Premium...</p>' : ''}
                ${isPaymentCancelled ? '<p>Payment cancelled.</p>' : ''}
                <button onclick="location.reload()">Reconnect & Refresh</button>
                <script>
                  // Auto-poll and reload on online
                  const checkOnline = () => {
                    if (navigator.onLine) {
                      location.reload();
                    } else {
                      setTimeout(checkOnline, 5000); // Poll every 5s
                    }
                  };
                  if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.ready.then(() => checkOnline());
                  } else {
                    checkOnline();
                  }
                  // Listen globally
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
        cacheNames.filter(name => name !== CACHE_NAME)
          .map(name => caches.delete(name))
      );
    }).then(() => self.clients.claim())
  );
});