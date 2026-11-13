/*
 * Morrow watch notifications. Registered from /watching with scope /ui/; it handles push messages
 * only (no fetch handler, so it never sits between the page and the network).
 * A message is {title, body, url, tag}, encrypted to this browser by the server (RFC 8291).
 */
self.addEventListener("push", function (event) {
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = { body: event.data ? event.data.text() : "" }; }
  event.waitUntil(self.registration.showNotification(data.title || "Morrow", {
    body: data.body || "A domain you watch changed.",
    tag: data.tag || "morrow-watch",
    data: { url: data.url || "/watching" }
  }));
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var target = (event.notification.data && event.notification.data.url) || "/watching";
  try { if (new URL(target, self.location.origin).origin !== self.location.origin) target = "/watching"; } catch (e) { target = "/watching"; }
  event.waitUntil(self.clients.openWindow(target));
});
