/* Nombramientos Adventistas public-assets-only service worker. */
const CACHE_NAME = "nombramientos-public-v2";
const PUBLIC_PATHS = new Set([
  "/favicon.svg",
  "/fonts/noto-sans-latin-variable.woff2",
  "/fonts/report-sans-regular.ttf",
  "/fonts/report-sans-bold.ttf",
]);

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll([...PUBLIC_PATHS])).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Documents, API responses, reports, invitations and tenant files always use the network.
  if (request.mode === "navigate" || url.pathname.startsWith("/v1/") || url.pathname.startsWith("/api/")) return;

  const isPublicAsset = PUBLIC_PATHS.has(url.pathname) || url.pathname.startsWith("/_next/static/");
  if (!isPublicAsset) return;

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((response) => {
        if (!response.ok || response.type !== "basic") return response;
        const copy = response.clone();
        void caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        return response;
      });
    }),
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type !== "PURGE_LOCAL_CACHES") return;
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.map((key) => caches.delete(key)))));
});
