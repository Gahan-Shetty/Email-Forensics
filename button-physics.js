/**
 * Fluid Water Movement & Jelly Physics Engine for Buttons — Email Forensic Analyzer
 * Features:
 * - Dynamic liquid water meniscus light refraction following mouse coordinates
 * - Elastic jelly squash & stretch spring physics deformation
 * - Liquid water ripples spreading across button surface on movement and click
 * - Auto-binds to all buttons (.btn, .hud-btn, .tab-btn, .chapter-dot, .quick-nav-item, dynamic result buttons)
 */

(function (window, document) {
  "use strict";

  // Check for reduced motion
  var prefersReducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var buttonSelectors = [
    ".btn",
    ".btn-primary",
    ".btn-secondary",
    ".btn-outline",
    ".hud-btn",
    ".tab-btn",
    ".chapter-dot",
    ".quick-nav-item",
    "button",
    ".dropzone"
  ].join(", ");

  function attachJellyPhysics(element) {
    if (!element || element._hasJellyPhysics) return;
    element._hasJellyPhysics = true;
    element.classList.add("jelly-btn");

    var isHovered = false;
    var lastX = 0, lastY = 0;
    var wobbleTimeout = null;

    element.addEventListener("mouseenter", function (e) {
      if (prefersReducedMotion) return;
      isHovered = true;
      element.classList.remove("jelly-wobble-anim");
      // Trigger reflow to restart CSS animation
      void element.offsetWidth;
      element.classList.add("jelly-wobble-anim");

      clearTimeout(wobbleTimeout);
      wobbleTimeout = setTimeout(function () {
        element.classList.remove("jelly-wobble-anim");
      }, 700);

      updateWaterCoordinates(e, element);
    });

    element.addEventListener("mousemove", function (e) {
      if (prefersReducedMotion) return;
      updateWaterCoordinates(e, element);
    });

    element.addEventListener("mouseleave", function () {
      isHovered = false;
      element.style.setProperty("--water-intensity", "0");
      element.style.setProperty("--jelly-tilt-x", "0deg");
      element.style.setProperty("--jelly-tilt-y", "0deg");
      element.classList.remove("jelly-pressed");
    });

    element.addEventListener("mousedown", function (e) {
      if (prefersReducedMotion) return;
      element.classList.add("jelly-pressed");
      createWaterRipple(e, element);
    });

    element.addEventListener("mouseup", function () {
      element.classList.remove("jelly-pressed");
      if (isHovered && !prefersReducedMotion) {
        element.classList.remove("jelly-rebound-anim");
        void element.offsetWidth;
        element.classList.add("jelly-rebound-anim");
        setTimeout(function () {
          element.classList.remove("jelly-rebound-anim");
        }, 500);
      }
    });
  }

  function updateWaterCoordinates(e, el) {
    var rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;

    var x = e.clientX - rect.left;
    var y = e.clientY - rect.top;

    var normX = Math.max(0, Math.min(100, (x / rect.width) * 100));
    var normY = Math.max(0, Math.min(100, (y / rect.height) * 100));

    // Calculate normalized delta from center (-1 to 1) for 3D jelly tilt & water bulge
    var dx = ((x - rect.width / 2) / (rect.width / 2));
    var dy = ((y - rect.height / 2) / (rect.height / 2));

    var tiltX = (-dy * 6).toFixed(2); // degrees
    var tiltY = (dx * 6).toFixed(2);  // degrees

    el.style.setProperty("--mouse-x", normX.toFixed(1) + "%");
    el.style.setProperty("--mouse-y", normY.toFixed(1) + "%");
    el.style.setProperty("--mouse-px-x", x.toFixed(0) + "px");
    el.style.setProperty("--mouse-px-y", y.toFixed(0) + "px");
    el.style.setProperty("--water-intensity", "1");
    el.style.setProperty("--jelly-tilt-x", tiltX + "deg");
    el.style.setProperty("--jelly-tilt-y", tiltY + "deg");
  }

  function createWaterRipple(e, el) {
    var rect = el.getBoundingClientRect();
    var x = e.clientX - rect.left;
    var y = e.clientY - rect.top;

    var ripple = document.createElement("span");
    ripple.className = "btn-water-ripple";
    var size = Math.max(rect.width, rect.height) * 2.2;
    ripple.style.width = size + "px";
    ripple.style.height = size + "px";
    ripple.style.left = (x - size / 2) + "px";
    ripple.style.top = (y - size / 2) + "px";

    el.appendChild(ripple);

    setTimeout(function () {
      if (ripple.parentNode) {
        ripple.parentNode.removeChild(ripple);
      }
    }, 650);
  }

  function initAllButtons() {
    var elements = document.querySelectorAll(buttonSelectors);
    for (var i = 0; i < elements.length; i++) {
      attachJellyPhysics(elements[i]);
    }
  }

  // Observe dynamically inserted buttons (such as in #results)
  function initDynamicObserver() {
    var observer = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var m = mutations[i];
        if (m.addedNodes && m.addedNodes.length > 0) {
          for (var j = 0; j < m.addedNodes.length; j++) {
            var node = m.addedNodes[j];
            if (node.nodeType === 1) { // ELEMENT_NODE
              if (node.matches && node.matches(buttonSelectors)) {
                attachJellyPhysics(node);
              }
              var nested = node.querySelectorAll ? node.querySelectorAll(buttonSelectors) : [];
              for (var k = 0; k < nested.length; k++) {
                attachJellyPhysics(nested[k]);
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
      initAllButtons();
      initDynamicObserver();
    });
  } else {
    initAllButtons();
    initDynamicObserver();
  }

  window.EFR = window.EFR || {};
  window.EFR.attachJellyPhysics = attachJellyPhysics;

})(window, document);
