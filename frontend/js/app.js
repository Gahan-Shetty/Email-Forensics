/* Event wiring.   OWNER: M5 (Frontend UI).
 *
 * The ONLY file that connects DOM events to EFR.api / EFR.render / EFR.map.
 * Keeping that in one place is why two people can work on the frontend without
 * touching the same lines.
 */
(function () {
  "use strict";

  const results = document.getElementById("results");
  const statusStrip = document.getElementById("module-status");
  const rawInput = document.getElementById("raw-input");
  const fileInput = document.getElementById("file-input");
  const dropzone = document.getElementById("dropzone");
  const fileChosen = document.getElementById("file-chosen");
  const skipGeo = document.getElementById("opt-skip-geoip");

  let mode = "paste";
  let chosenFile = null;

  /* ---- tab switching ---- */
  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
      mode = tab.dataset.mode;
      document.querySelectorAll(".tab").forEach(function (t) { t.classList.toggle("is-active", t === tab); });
      document.querySelectorAll(".tab-body").forEach(function (b) {
        b.classList.toggle("is-hidden", b.dataset.body !== mode);
      });
    });
  });

  /* ---- file selection ---- */
  dropzone.addEventListener("click", function () { fileInput.click(); });
  dropzone.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });
  ["dragover", "dragenter"].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.add("is-hover"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dropzone.addEventListener(ev, function () { dropzone.classList.remove("is-hover"); });
  });
  dropzone.addEventListener("drop", function (e) {
    e.preventDefault();
    if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", function () {
    if (fileInput.files.length) setFile(fileInput.files[0]);
  });
  function setFile(f) {
    chosenFile = f;
    fileChosen.textContent = f.name + " · " + Math.round(f.size / 1024) + " KB";
  }

  /* ---- the one place results get rendered ---- */
  function show(analysis) {
    EFR.render.results(results, analysis);
    EFR.render.moduleStatus(statusStrip, analysis.module_status);
    /* map container only exists after render, and must be visible before init */
    const mapEl = document.getElementById("map");
    if (mapEl) {
      EFR.map.init(mapEl);
      EFR.map.plot(analysis.map_hops, analysis.origin);
    }
  }

  function run(promise) {
    EFR.render.loading(results, true);
    promise.then(show).catch(function (err) { EFR.render.error(results, err); });
  }

  document.getElementById("btn-analyze").addEventListener("click", function () {
    if (mode === "file") {
      if (!chosenFile) {
        return EFR.render.error(results, { code: "EMPTY_INPUT", userMessage: "Choose a .eml file first." });
      }
      return run(EFR.api.analyzeFile(chosenFile));
    }
    const raw = rawInput.value;
    if (!raw.trim()) {
      return EFR.render.error(results, {
        code: "EMPTY_INPUT",
        userMessage: "Paste the raw email source first, including the Received and From headers."
      });
    }
    run(EFR.api.analyzeText(raw, { skip_geoip: skipGeo.checked }));
  });

  /* Demo response - works before any backend logic exists. */
  document.getElementById("btn-sample").addEventListener("click", function () {
    run(EFR.api.mock());
  });

  /* Surface stub/live state on load so the team can see build progress. */
  EFR.api.health()
    .then(function (h) { EFR.render.moduleStatus(statusStrip, h.module_status); })
    .catch(function () {
      statusStrip.innerHTML = '<span class="chip chip-error">backend offline</span>';
    });
})();
