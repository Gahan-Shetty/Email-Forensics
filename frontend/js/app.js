/**
 * Email Forensic Analyzer (EFA) / TraceMail.AI — Application Controller
 * ThreeUI Kage Landing Page Edition with 3D WebGL, Chapter Rail, Audio Synthesizer,
 * and 6-Panel Forensic State Machine.
 */

(function (window, document) {
  "use strict";

  var currentAnalysis = null;
  var currentTab = "raw";
  var audioContext = null;
  var ambientOscillator = null;
  var isAudioPlaying = false;
  var isTampered = false;

  function initApp() {
    // 1. Initialize Three.js 3D Background
    if (window.initThreeScene) {
      try {
        window.initThreeScene();
      } catch (e) {
        console.warn("Three.js initialization notice:", e);
      }
    }

    var rawTextarea = document.getElementById("raw-email-input");
    var analyzeBtn = document.getElementById("btn-analyze");
    var demoBtn = document.getElementById("btn-demo");
    var heroDemoBtn = document.getElementById("hero-quick-demo-btn");
    var sampleSelect = document.getElementById("sample-select");
    var offlineCheckbox = document.getElementById("offline-mode-toggle");
    var dropzone = document.getElementById("eml-dropzone");
    var fileInput = document.getElementById("eml-file-input");
    var resultsContainer = document.getElementById("results");
    var tabRawBtn = document.getElementById("tab-btn-raw");
    var tabUploadBtn = document.getElementById("tab-btn-upload");
    var tabRawContent = document.getElementById("tab-content-raw");
    var tabUploadContent = document.getElementById("tab-content-upload");
    var quickNav = document.getElementById("quick-nav");
    var audioBtn = document.getElementById("audio-toggle-btn");
    var tamperBtn = document.getElementById("tamper-simulate-btn");

    // 2. Health telemetry
    updateHealthStatus();

    // 3. Pre-fill default sample
    if (rawTextarea && window.EFR.api) {
      rawTextarea.value = window.EFR.api.getRawSample("sample1_phishing");
    }

    // 4. Tab switching with dynamic slide animation
    function switchTab(tab) {
      currentTab = tab;
      if (tab === "raw") {
        if (tabRawBtn) tabRawBtn.classList.add("active");
        if (tabUploadBtn) tabUploadBtn.classList.remove("active");
        if (tabRawContent) {
          tabRawContent.style.display = "block";
          tabRawContent.classList.remove("tab-slide-enter");
          void tabRawContent.offsetWidth;
          tabRawContent.classList.add("tab-slide-enter");
        }
        if (tabUploadContent) tabUploadContent.style.display = "none";
      } else {
        if (tabUploadBtn) tabUploadBtn.classList.add("active");
        if (tabRawBtn) tabRawBtn.classList.remove("active");
        if (tabRawContent) tabRawContent.style.display = "none";
        if (tabUploadContent) {
          tabUploadContent.style.display = "block";
          tabUploadContent.classList.remove("tab-slide-enter");
          void tabUploadContent.offsetWidth;
          tabUploadContent.classList.add("tab-slide-enter");
        }
      }
    }

    if (tabRawBtn) tabRawBtn.addEventListener("click", function () { switchTab("raw"); });
    if (tabUploadBtn) tabUploadBtn.addEventListener("click", function () { switchTab("upload"); });

    // 5. Sample Preset Selector
    if (sampleSelect) {
      sampleSelect.addEventListener("change", function () {
        var key = sampleSelect.value;
        if (window.EFR.api && rawTextarea) {
          rawTextarea.value = window.EFR.api.getRawSample(key);
        }
      });
    }

    // 6. File Drag & Drop
    if (dropzone && fileInput) {
      dropzone.addEventListener("click", function () { fileInput.click(); });
      dropzone.addEventListener("dragover", function (e) { e.preventDefault(); dropzone.classList.add("dragover"); });
      dropzone.addEventListener("dragleave", function () { dropzone.classList.remove("dragover"); });
      dropzone.addEventListener("drop", function (e) {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          handleFile(e.dataTransfer.files[0]);
        }
      });
      fileInput.addEventListener("change", function () {
        if (fileInput.files && fileInput.files.length > 0) {
          handleFile(fileInput.files[0]);
        }
      });
    }

    function handleFile(file) {
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function (e) {
        var content = e.target.result;
        if (rawTextarea) {
          rawTextarea.value = content;
        }
        triggerAnalysis(null, file);
      };
      reader.readAsText(file);
    }

    // 7. Execution Trigger (Analyze / Demo)
    function triggerAnalysis(forcePresetKey, fileObj) {
      var rawEmail = rawTextarea ? rawTextarea.value : "";
      var isOffline = offlineCheckbox ? offlineCheckbox.checked : false;
      var presetKey = forcePresetKey || (sampleSelect && !rawEmail && !fileObj ? sampleSelect.value : null);

      setLoadingState(true);

      var inputPayload = fileObj || rawEmail;

      window.EFR.api.analyze(inputPayload, {
        offlineMode: isOffline,
        sampleKey: presetKey
      })
      .then(function (data) {
        currentAnalysis = data;
        renderAnalysisResults(data);
        setLoadingState(false);
      })
      .catch(function (err) {
        console.error("Forensic analysis failed", err);
        renderAnalysisError(err);
        setLoadingState(false);
      });
    }

    if (analyzeBtn) {
      analyzeBtn.addEventListener("click", function () {
        triggerAnalysis();
      });
    }

    if (demoBtn) {
      demoBtn.addEventListener("click", function () {
        var key = sampleSelect ? sampleSelect.value : "sample1_phishing";
        triggerAnalysis(key);
      });
    }

    if (heroDemoBtn) {
      heroDemoBtn.addEventListener("click", function () {
        var analyzerSec = document.getElementById("chapter-analyzer");
        if (analyzerSec) {
          var yOffset = -70;
          var y = analyzerSec.getBoundingClientRect().top + window.pageYOffset + yOffset;
          window.scrollTo({ top: y, behavior: "smooth" });
        }
        setTimeout(function () {
          triggerAnalysis("sample1_phishing");
        }, 300);
      });
    }

    // 8. Loading UI State Transitions
    function setLoadingState(isLoading) {
      if (analyzeBtn) analyzeBtn.disabled = isLoading;
      if (demoBtn) demoBtn.disabled = isLoading;

      if (isLoading && resultsContainer) {
        resultsContainer.innerHTML = "";
        var loadingEl = window.EFR.render.loading("Analyzing message headers, SPF/DKIM alignment & routing infrastructure…");
        resultsContainer.appendChild(loadingEl);
        if (quickNav) quickNav.style.display = "none";
      }
    }

    // 9. Results Rendering & Map Initialization (State C / E)
    function renderAnalysisResults(analysis) {
      if (!resultsContainer) return;

      resultsContainer.innerHTML = "";
      var resultsDom = window.EFR.render.results(analysis);
      resultsContainer.appendChild(resultsDom);

      // Show quick navigation
      if (quickNav) {
        quickNav.style.display = "block";
        setupReportScrollSpy();
      }

      // Initialize Leaflet Map AFTER DOM appending
      var mapEl = document.getElementById("map");
      if (mapEl && window.EFR.map) {
        window.EFR.map.init(mapEl);
        window.EFR.map.plot(analysis.map_hops, analysis.origin);
      }

      // Smooth scroll to top of results
      setTimeout(function () {
        var firstSec = document.getElementById("sec-verdict") || resultsContainer;
        if (firstSec) {
          var yOffset = -120;
          var y = firstSec.getBoundingClientRect().top + window.pageYOffset + yOffset;
          window.scrollTo({ top: y, behavior: "smooth" });
        }
      }, 120);
    }

    // 10. Error Rendering (State D)
    function renderAnalysisError(err) {
      if (!resultsContainer) return;
      resultsContainer.innerHTML = "";
      var errDom = window.EFR.render.error(err);
      resultsContainer.appendChild(errDom);
      if (quickNav) quickNav.style.display = "none";
    }

    // 11. Header Telemetry Chips
    function updateHealthStatus() {
      if (!window.EFR.api) return;
      window.EFR.api.health().then(function (health) {
        var mods = health.modules || {};
        updateChip("chip-parsing", mods.parsing || "live");
        updateChip("chip-auth", mods.auth || "live");
        updateChip("chip-geoip", mods.geoip || "live");
        updateChip("chip-report", mods.report || "live");
      }).catch(function () {
        updateChip("chip-parsing", "live");
        updateChip("chip-auth", "live");
        updateChip("chip-geoip", "live");
        updateChip("chip-report", "live");
      });
    }

    function updateChip(elementId, status) {
      var el = document.getElementById(elementId);
      if (!el) return;
      el.className = "chip";
      if (status === "live") {
        el.classList.add("chip-live");
      } else if (status === "stub") {
        el.classList.add("chip-stub");
      } else if (status === "error") {
        el.classList.add("chip-error");
      }
    }

    // 12. Quick Nav Section Scroll Spy
    function setupReportScrollSpy() {
      var items = document.querySelectorAll(".quick-nav-item");
      if (!items || items.length === 0) return;

      var sections = [
        document.getElementById("sec-verdict"),
        document.getElementById("sec-auth"),
        document.getElementById("sec-origin"),
        document.getElementById("sec-routing"),
        document.getElementById("sec-signals"),
        document.getElementById("sec-evidence")
      ].filter(Boolean);

      function onReportScroll() {
        var scrollPos = window.pageYOffset + 200;
        var currentIdx = 0;

        for (var i = 0; i < sections.length; i++) {
          if (sections[i].offsetTop <= scrollPos) {
            currentIdx = i;
          }
        }

        items.forEach(function (it, idx) {
          if (idx === currentIdx) {
            it.classList.add("active");
          } else {
            it.classList.remove("active");
          }
        });
      }

      window.addEventListener("scroll", onReportScroll);
      onReportScroll();
    }

    // 13. Web Audio Cyber Synthesizer
    if (audioBtn) {
      audioBtn.addEventListener("click", function () {
        var audioIcon = document.getElementById("audio-icon");
        var audioText = document.getElementById("audio-text");

        if (!isAudioPlaying) {
          try {
            var AudioContextClass = window.AudioContext || window.webkitAudioContext;
            if (AudioContextClass) {
              if (!audioContext) audioContext = new AudioContextClass();
              if (audioContext.state === "suspended") audioContext.resume();

              var osc = audioContext.createOscillator();
              var gain = audioContext.createGain();
              var filter = audioContext.createBiquadFilter();

              osc.type = "sine";
              osc.frequency.setValueAtTime(55, audioContext.currentTime);

              filter.type = "lowpass";
              filter.frequency.setValueAtTime(180, audioContext.currentTime);

              gain.gain.setValueAtTime(0.04, audioContext.currentTime);

              osc.connect(filter);
              filter.connect(gain);
              gain.connect(audioContext.destination);

              osc.start();
              ambientOscillator = { osc: osc, gain: gain };
              isAudioPlaying = true;
              audioBtn.classList.add("active");
              if (audioIcon) audioIcon.textContent = "🔊";
              if (audioText) audioText.textContent = "Audio Live";
            }
          } catch (err) {
            console.warn("Audio synthesis unavailable:", err);
          }
        } else {
          if (ambientOscillator) {
            try {
              ambientOscillator.gain.gain.exponentialRampToValueAtTime(0.0001, audioContext.currentTime + 0.5);
              setTimeout(function () { ambientOscillator.osc.stop(); }, 500);
            } catch (e) {}
            ambientOscillator = null;
          }
          isAudioPlaying = false;
          audioBtn.classList.remove("active");
          if (audioIcon) audioIcon.textContent = "🔈";
          if (audioText) audioText.textContent = "Audio Off";
        }
      });
    }

    // 14. Custody Vault Tamper Simulator
    if (tamperBtn) {
      tamperBtn.addEventListener("click", function () {
        var badge = document.getElementById("vault-live-badge");
        if (!badge) return;

        isTampered = !isTampered;
        if (isTampered) {
          badge.className = "custody-badge-broken";
          badge.textContent = "chain broken at entry #17 ✕";
          tamperBtn.innerHTML = "<span>↺</span> Reset Chain";
        } else {
          badge.className = "custody-badge-intact";
          badge.textContent = "chain intact ✓";
          tamperBtn.innerHTML = "<span>🧪</span> Simulate Tamper Verification";
        }
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initApp);
  } else {
    initApp();
  }

})(window, document);
