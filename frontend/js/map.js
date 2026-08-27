/**
 * Email Forensic Analyzer (EFA) — Map Module
 * Leaflet GeoIP Hop Plotter in Kage Kyoto Noir Palette
 */

(function (window) {
  "use strict";

  window.EFR = window.EFR || {};

  var mapInstance = null;
  var markerGroup = null;
  var lineGroup = null;

  function init(element) {
    if (!element) return null;

    if (mapInstance) {
      try {
        mapInstance.remove();
      } catch (e) {
        console.warn("Leaflet map cleanup error", e);
      }
      mapInstance = null;
    }

    if (typeof L === "undefined") {
      console.warn("Leaflet library (L) is not loaded");
      return null;
    }

    mapInstance = L.map(element, {
      center: [20, 0],
      zoom: 2,
      minZoom: 1,
      maxZoom: 18,
      zoomControl: true,
      attributionControl: false
    });

    // DarkMatter tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      subdomains: 'abcd',
      maxZoom: 19
    }).addTo(mapInstance);

    markerGroup = L.layerGroup().addTo(mapInstance);
    lineGroup = L.layerGroup().addTo(mapInstance);

    return mapInstance;
  }

  function plot(mapHops, origin) {
    if (!mapInstance || !markerGroup || !lineGroup) return;

    markerGroup.clearLayers();
    lineGroup.clearLayers();

    var hops = mapHops || [];
    var validPoints = [];
    var latLngs = [];

    for (var i = 0; i < hops.length; i++) {
      var h = hops[i];
      if (h && typeof h.lat === "number" && typeof h.lon === "number" && !isNaN(h.lat) && !isNaN(h.lon)) {
        validPoints.push(h);
        latLngs.push([h.lat, h.lon]);
      }
    }

    if (validPoints.length === 0) {
      mapInstance.setView([20, 0], 2);
      mapInstance.invalidateSize();
      return;
    }

    // Draw route polyline with Kage vermilion dash
    if (latLngs.length > 1) {
      L.polyline(latLngs, {
        color: '#f47b5c',
        weight: 2,
        opacity: 0.85,
        dashArray: '4, 6',
        lineCap: 'round'
      }).addTo(lineGroup);
    }

    // Kage Marker Icon
    function createMarkerIcon(hopIndex, isOrigin) {
      var color = isOrigin ? '#f47b5c' : '#f9c74f';
      var html =
        '<div style="position:relative; width:22px; height:22px; display:flex; align-items:center; justify-content:center;">' +
          '<div style="position:absolute; width:100%; height:100%; border-radius:50%; background:' + color + '; opacity:0.35;"></div>' +
          '<div style="width:16px; height:16px; border-radius:50%; background:' + color + '; border:1.5px solid #05070a; display:flex; align-items:center; justify-content:center; color:#05070a; font-weight:700; font-size:9px; font-family:JetBrains Mono, monospace;">' +
            hopIndex +
          '</div>' +
        '</div>';

      return L.divIcon({
        html: html,
        className: 'kage-map-marker',
        iconSize: [22, 22],
        iconAnchor: [11, 11],
        popupAnchor: [0, -12]
      });
    }

    for (var j = 0; j < validPoints.length; j++) {
      var pt = validPoints[j];
      var isOrigin = (origin && origin.selected_ip === pt.ip) || (pt.hop_index === 1);
      var icon = createMarkerIcon(pt.hop_index || (j + 1), isOrigin);

      var marker = L.marker([pt.lat, pt.lon], { icon: icon }).addTo(markerGroup);

      var confClass = pt.confidence ? ('pill-conf-' + pt.confidence) : 'pill-conf-medium';
      var originBadge = isOrigin ? '<span style="font-size:9px; font-weight:600; color:#f47b5c; text-transform:uppercase; margin-left:6px;">[Origin]</span>' : '';

      var popupContent =
        '<div style="font-family:JetBrains Mono, monospace; color:#f7f8f8; background:#0e1117; padding:10px 12px; border-radius:6px; border:0.5px solid rgba(255,255,255,0.12); min-width:160px; font-size:11px;">' +
          '<div style="font-weight:600; margin-bottom:3px;">' +
            'Hop ' + (pt.hop_index || (j + 1)) + originBadge +
          '</div>' +
          '<div style="color:#8a8f98; margin-bottom:5px; font-size:10.5px;">' +
            (pt.city ? (pt.city + ', ') : '') + (pt.country || 'Unknown Location') +
          '</div>' +
          '<div style="color:#f9c74f; margin-bottom:6px; font-size:10.5px;">' +
            (pt.ip || '—') +
          '</div>' +
          '<div>' +
            '<span class="pill ' + confClass + '" style="font-size:9px; padding:1px 5px;">' + (pt.confidence || 'confidence: medium') + '</span>' +
          '</div>' +
        '</div>';

      marker.bindPopup(popupContent, {
        className: 'kage-dark-popup',
        closeButton: false
      });
    }

    if (latLngs.length === 1) {
      mapInstance.setView(latLngs[0], 5);
    } else {
      var bounds = L.latLngBounds(latLngs);
      mapInstance.fitBounds(bounds, { padding: [35, 35], maxZoom: 8 });
    }

    setTimeout(function () {
      if (mapInstance) {
        mapInstance.invalidateSize();
      }
    }, 100);
  }

  window.EFR.map = {
    init: init,
    plot: plot
  };

})(window);
