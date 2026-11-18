// Arrabona Pass Mobil - offline mukodes. A sajat fajljain kivul semmit nem tolt le.
// Halozat elsobbseg (igy a frissites azonnal megjelenik), halozat nelkul a tarolt peldany.
const CACHE = "apm-1.1.0";
const FILES = ["./", "index.html", "app.js", "argon2.js", "app.css", "manifest.webmanifest",
               "icon-180.png", "icon-192.png", "icon-512.png", "logo-64.png"];

self.addEventListener("install", ev => {
  ev.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", ev => {
  ev.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener("fetch", ev => {
  const url = new URL(ev.request.url);
  if (ev.request.method !== "GET" || url.origin !== location.origin) return;
  ev.respondWith(
    fetch(ev.request, { cache: "no-cache" })
      .then(r => { if (r.ok) { const cp = r.clone(); caches.open(CACHE).then(c => c.put(ev.request, cp)); } return r; })
      .catch(() => caches.match(ev.request, { ignoreSearch: true }))
  );
});
