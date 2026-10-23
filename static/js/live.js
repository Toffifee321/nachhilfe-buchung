// Aktualisiert Zähler im Menü und (falls vorhanden) die Liste #live alle 15 Sekunden.
(function () {
  var url = document.body.dataset.pollUrl;
  if (!url) return;
  var badge = document.getElementById("zaehler");
  var live = document.getElementById("live");
  var tmp = document.createElement("div");

  // Nicht ersetzen, solange der Nutzer gerade in der Liste tippt (z. B. Ablehnungsgrund).
  function wirdBearbeitet() {
    if (live.contains(document.activeElement) &&
        document.activeElement.tagName === "INPUT") return true;
    return Array.prototype.some.call(live.querySelectorAll("input[name=grund]"),
      function (i) { return i.value !== ""; });
  }

  function tick() {
    if (document.hidden) return;
    fetch(url + (live ? "?html=1" : ""), {
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        if (badge) {
          badge.textContent = d.count;
          badge.hidden = d.count === 0;
        }
        if (live && d.html !== null) {
          tmp.innerHTML = d.html;
          if (tmp.innerHTML !== live.innerHTML && !wirdBearbeitet()) {
            live.innerHTML = d.html;
          }
        }
      })
      .catch(function () { /* offline oder abgemeldet: beim nächsten Takt erneut */ });
  }

  setInterval(tick, 15000);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) tick();
  });
})();
