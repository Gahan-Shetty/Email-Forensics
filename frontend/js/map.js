/* Leaflet map module.   OWNER: M6 (Integration).   M5: call these, don't edit.
 *
 * Contract rule this module enforces: EVERY marker's popup and tooltip carries
 * its confidence label. An unlabelled pin is a contract violation, so the label
 * is baked in here rather than left to the caller to remember.
 */
(function () {
  "use strict";
  window.EFR = window.EFR || {};

  let map = null;
  let layer = null;

  const COLOUR = { high: "#1a7f37", medium: "#9a6700", low: "#b3261e" };

  function dot(confidence, isOrigin) {
    const c = COLOUR[confidence] || COLOUR.low;
    return L.divIcon({
      className: "hop-pin",
      html: '<span style="background:' + c + ';' +
            'width:' + (isOrigin ? 18 : 12) + 'px;height:' + (isOrigin ? 18 : 12) + 'px;' +
            'display:block;border-radius:50%;border:3px solid #fff;' +
            'box-shadow:0 0 0 1px rgba(0,0,0,.35)"></span>',
      iconSize: [isOrigin ? 18 : 12, isOrigin ? 18 : 12],
      iconAnchor: [isOrigin ? 9 : 6, isOrigin ? 9 : 6]
    });
  }

  window.EFR.map = {
    /* TODO(M6): call once, after the container is visible in the DOM.
     * Leaflet mis-sizes itself if the container is display:none at init -
     * if the map renders as a grey sliver, that is why; call map.invalidateSize()
     * after the panel becomes visible. */
    init: function (containerEl) {
      if (map) return map;
      map = L.map(containerEl, { scrollWheelZoom: false, worldCopyJump: true })
             .setView([20, 0], 2);
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 18,
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
      }).addTo(map);
      layer = L.layerGroup().addTo(map);
      return map;
    },

    /* mapHops = analysis.map_hops, origin = analysis.origin */
    plot: function (mapHops, origin) {
      if (!map || !layer) return;
      layer.clearLayers();

      const pts = [];
      (mapHops || []).forEach(function (h) {
        if (typeof h.lat !== "number" || typeof h.lon !== "number") return;
        const conf = h.confidence || "low";
        const label =
          '<strong>Hop ' + h.hop_index + (h.is_selected_origin ? " · selected origin" : "") + '</strong><br>' +
          (h.label || "") + '<br><code>' + h.ip + '</code><br>' +
          '<span class="pill pill-' + conf + '">confidence: ' + conf + '</span>';

        L.marker([h.lat, h.lon], { icon: dot(conf, !!h.is_selected_origin) })
          .bindPopup(label)
          .bindTooltip(h.ip + " · " + conf, { direction: "top" })
          .addTo(layer);
        pts.push([h.lat, h.lon]);
      });

      if (pts.length > 1) {
        L.polyline(pts, { color: "#6b7280", weight: 2, dashArray: "5,6" }).addTo(layer);
      }

      if (pts.length) {
        map.fitBounds(L.latLngBounds(pts).pad(0.35), { maxZoom: 6 });
        const sel = (mapHops || []).find(function (h) { return h.is_selected_origin; });
        if (sel) L.popup().setLatLng([sel.lat, sel.lon])
                  .setContent('<strong>Observed sending infrastructure</strong><br>' +
                              ((origin && origin.statement) || ""))
                  .openOn(map);
      } else {
        map.setView([20, 0], 2);
      }
      map.invalidateSize();
    },

    clear: function () { if (layer) layer.clearLayers(); }
  };
})();
