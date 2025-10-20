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
          console.log('Serving cached index.html for offline (subscription modal intact):', url.pathname);
          return caches.match('/index.html').then(cachedResponse => {
            if (cachedResponse) {
              const isPaymentCallback = url.searchParams.get('payment') || url.searchParams.get('session_id');
              if (isPaymentCallback) {
                return new Response(cachedResponse.clone().text().then(html => {
                  return html.replace(
                    '</body>',
                    `<script>if (window.location.search.includes('payment=success')) { alert('Payment success! (Offline mode - reconnect to verify)'); } else if (window.location.search.includes('payment=cancelled')) { alert('Payment cancelled.'); }</script></body>`
                  );
                }), {
                  headers: cachedResponse.headers
                });
              }
              return cachedResponse;
            }
            return new Response(`
              <!DOCTYPE html>
              <html><head><title>Offline</title></head><body>
                <h1>You're offline</h1>
                <p>Reconnect to access the app & verify subscription. Cached content available.</p>
                <script>if ('serviceWorker' in navigator) navigator.serviceWorker.ready.then(() => location.reload());</script>
              </body></html>
            `, { 
              status: 503,
              headers: { 'Content-Type': 'text/html' }
            });
          });
        })
    );
    return;
  }

  // Default: Cache-first with network update
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