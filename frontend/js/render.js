/* Results rendering.   OWNER: M5 (Frontend UI).  This file is yours alone.
 *
 * You render; you do not fetch. All data arrives as the `analysis` argument,
 * already contract-shaped. Build the whole dashboard against
 * EFR.api.mock() on Day 1 and you are finished before the backend is.
 *
 * Every key in the contract is guaranteed present (null / [] when empty), so
 * you can index confidently - but still use the esc() helper on anything
 * user-controlled: phishing subject lines contain HTML and will break the page
 * or inject markup if you interpolate them raw.
 */
(function () {
  "use strict";
  window.EFR = window.EFR || {};

  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function el(html) { const d = document.createElement("div"); d.innerHTML = html.trim(); return d.firstChild; }
  function pill(text, kind) { return '<span class="pill pill-' + kind + '">' + esc(text) + "</span>"; }

  /* ---------- panel builders -------------------------------------------
   * TODO(M5): implement these six. Suggested build order - each one is
   * independently demoable, so you always have something to show:
   *   1. verdict   (biggest visual payoff, do it first)
   *   2. auth      (simple badges, quick win)
   *   3. origin    (the differentiator - confidence label must be adjacent)
   *   4. chain     (the timeline)
   *   5. signals   (score breakdown)
   *   6. evidence  (hash + download links)
   */

  function panelVerdict(a) {
    /* TODO(M5): risk score as a big number, coloured by a.risk.band
     * (use the pill-low/medium/high/critical classes already in styles.css),
     * a.risk.verdict humanised, and the subject + From line.
     * Put a.origin.statement here too, in full - it is the headline finding. */
    return el('<section class="panel"><h2>Verdict</h2><p class="muted">TODO(M5): verdict panel</p></section>');
  }

  function panelAuth(a) {
    /* TODO(M5): SPF / DKIM / DMARC as pass/fail badges.
     * Show a.authentication.verified_by ("verified by mx.google.com").
     * If a.authentication.self_asserted_only is true, show a loud warning -
     * it means the message claims authentication that nobody trustworthy
     * confirmed, and it is one of the strongest things this tool surfaces. */
    return el('<section class="panel"><h2>Authentication</h2><p class="muted">TODO(M5): auth badges</p></section>');
  }

  function panelOrigin(a) {
    /* TODO(M5): the map container + the origin card.
     * HARD REQUIREMENT (API_CONTRACT.md section 6): the confidence label must
     * sit directly beside the location string, and every confidence_reason
     * must be listed. Never show a location without its confidence.
     * Create <div id="map"></div> here, then app.js calls EFR.map.init/plot. */
    return el('<section class="panel"><h2>Origin</h2><div id="map" class="map"></div>' +
              '<p class="muted">TODO(M5): origin card + confidence label</p></section>');
  }

  function panelChain(a) {
    /* TODO(M5): a.received_chain as a vertical timeline, hop 1 at the TOP
     * labelled "closest to sender". Per hop: timestamp, from_host, from_ip,
     * by_host, TLS indicator. Grey out hops whose IP was excluded (cross-
     * reference a.ip_candidates by ip) and show the exclusion_reason - showing
     * the working is more convincing than showing only the answer. */
    return el('<section class="panel"><h2>Routing chain</h2><p class="muted">TODO(M5): hop timeline</p></section>');
  }

  function panelSignals(a) {
    /* TODO(M5): all five a.risk.signals as rows: label, points, evidence.
     * Render untriggered ones greyed with a check mark - what was checked and
     * passed is as informative as what failed. */
    return el('<section class="panel"><h2>Risk signals</h2><p class="muted">TODO(M5): signal table</p></section>');
  }

  function panelEvidence(a) {
    /* TODO(M5): a.report.evidence_sha256 in monospace, custody entry number,
     * and download buttons using EFR.api.reportUrl(a.analysis_id, "pdf"|"json").
     * If a.report is null the module is still stubbed - show a disabled state,
     * not an error. */
    return el('<section class="panel"><h2>Evidence &amp; custody</h2><p class="muted">TODO(M5): hash + downloads</p></section>');
  }

  window.EFR.render = {
    esc: esc,
    pill: pill,

    results: function (rootEl, a) {
      rootEl.innerHTML = "";
      if (a.warnings && a.warnings.length) {
        rootEl.appendChild(el('<div class="banner banner-warn"><strong>Notes</strong><ul>' +
          a.warnings.map(function (w) { return "<li>" + esc(w) + "</li>"; }).join("") +
          "</ul></div>"));
      }
      [panelVerdict, panelAuth, panelOrigin, panelChain, panelSignals, panelEvidence]
        .forEach(function (fn) { rootEl.appendChild(fn(a)); });
    },

    error: function (rootEl, err) {
      rootEl.innerHTML = "";
      rootEl.appendChild(el(
        '<div class="banner banner-error"><strong>' + esc(err.code || "Error") + "</strong>" +
        "<p>" + esc(err.userMessage || err.message || "Something went wrong.") + "</p></div>"));
    },

    loading: function (rootEl, isLoading) {
      if (isLoading) {
        rootEl.innerHTML = '<div class="panel loading"><span class="spinner"></span> Analyzing message…</div>';
      }
    },

    /* Renders the stub/live badges in the header from analysis.module_status. */
    moduleStatus: function (stripEl, status) {
      if (!status) return;
      stripEl.innerHTML = Object.keys(status).map(function (k) {
        return '<span class="chip chip-' + esc(status[k]) + '">' + esc(k) + "</span>";
      }).join("");
    }
  };
})();
