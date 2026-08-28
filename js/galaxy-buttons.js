/**
 * Cosmic 3D Purple Galaxy Button Engine — Email Forensic Analyzer
 * Enriches all buttons with 3D orbiting stars, border-running cosmic spark,
 * static nebula particles, and radiant purple luminescence.
 */

(function (window, document) {
  "use strict";

  var RANDOM = function (min, max) {
    return Math.floor(Math.random() * (max - min + 1) + min);
  };

  var buttonSelectors = [
    ".btn",
    ".btn-primary",
    ".btn-secondary",
    ".btn-outline",
    ".hud-btn",
    ".tab-btn",
    "button:not(.leaflet-control-zoom-in):not(.leaflet-control-zoom-out)"
  ].join(", ");

  function enhanceButtonWithGalaxy(button) {
    if (!button || button._hasGalaxyEffect) return;
    button._hasGalaxyEffect = true;
    button.classList.add("galaxy-button-wrap");

    // Check if galaxy structure already exists
    if (button.querySelector(".galaxy")) return;

    // Wrap existing content to preserve styling and icons
    var contentWrapper = document.createElement("span");
    contentWrapper.className = "btn-text";

    while (button.firstChild) {
      contentWrapper.appendChild(button.firstChild);
    }

    // 1. Cosmic border spark
    var spark = document.createElement("span");
    spark.className = "spark";
    spark.setAttribute("aria-hidden", "true");

    // 2. Cosmic purple nebula backdrop
    var backdrop = document.createElement("span");
    backdrop.className = "backdrop";
    backdrop.setAttribute("aria-hidden", "true");

    // 3. Static drifting stars container
    var staticContainer = document.createElement("span");
    staticContainer.className = "galaxy__container";
    staticContainer.setAttribute("aria-hidden", "true");

    for (var s = 0; s < 4; s++) {
      var staticStar = document.createElement("span");
      staticStar.className = "star star--static";
      staticStar.style.setProperty("--duration", RANDOM(5, 14) + "s");
      staticStar.style.setProperty("--delay", (RANDOM(1, 8) * -1) + "s");
      staticContainer.appendChild(staticStar);
    }

    // 4. 3D Orbiting Galaxy Ring
    var galaxy = document.createElement("span");
    galaxy.className = "galaxy";
    galaxy.setAttribute("aria-hidden", "true");

    var galaxyRing = document.createElement("span");
    galaxyRing.className = "galaxy__ring";

    var starCount = 20;
    for (var i = 0; i < starCount; i++) {
      var star = document.createElement("span");
      star.className = "star";
      star.style.setProperty("--angle", RANDOM(0, 360) + "deg");
      star.style.setProperty("--duration", RANDOM(6, 18) + "s");
      star.style.setProperty("--delay", (RANDOM(1, 10) * -1) + "s");
      star.style.setProperty("--alpha", (RANDOM(45, 95) / 100).toString());
      star.style.setProperty("--size", RANDOM(2, 4) + "px");
      star.style.setProperty("--distance", RANDOM(30, 90) + "px");
      galaxyRing.appendChild(star);
    }

    galaxy.appendChild(galaxyRing);

    // Assemble button elements in correct z-index layering
    button.appendChild(spark);
    button.appendChild(backdrop);
    button.appendChild(staticContainer);
    button.appendChild(galaxy);
    button.appendChild(contentWrapper);

    // Dynamic mouse hover coordinates & 3D tilt tracking
    button.addEventListener("mousemove", function (e) {
      var rect = button.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return;
      var x = e.clientX - rect.left;
      var y = e.clientY - rect.top;
      var normX = ((x / rect.width) * 100).toFixed(1);
      var normY = ((y / rect.height) * 100).toFixed(1);
      button.style.setProperty("--mouse-x", normX + "%");
      button.style.setProperty("--mouse-y", normY + "%");
    });
  }

  function initAllGalaxyButtons() {
    var elements = document.querySelectorAll(buttonSelectors);
    for (var i = 0; i < elements.length; i++) {
      enhanceButtonWithGalaxy(elements[i]);
    }
  }

  // MutationObserver for dynamically added elements (like result reports)
  function initGalaxyObserver() {
    var observer = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var m = mutations[i];
        if (m.addedNodes && m.addedNodes.length > 0) {
          for (var j = 0; j < m.addedNodes.length; j++) {
            var node = m.addedNodes[j];
            if (node.nodeType === 1) {
              if (node.matches && node.matches(buttonSelectors)) {
                enhanceButtonWithGalaxy(node);
              }
              var nested = node.querySelectorAll ? node.querySelectorAll(buttonSelectors) : [];
              for (var k = 0; k < nested.length; k++) {
                enhanceButtonWithGalaxy(nested[k]);
              }
            }
          }
        }
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      initAllGalaxyButtons();
      initGalaxyObserver();
    });
  } else {
    initAllGalaxyButtons();
    initGalaxyObserver();
  }

  window.EFR = window.EFR || {};
  window.EFR.enhanceButtonWithGalaxy = enhanceButtonWithGalaxy;

})(window, document);
