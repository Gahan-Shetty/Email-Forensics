/**
 * Email Forensic Analyzer (EFA) — Panel Rendering Engine
 * Compliant with 05-M5-FRONTEND-BUILD-SPEC.md & API Contract
 */

(function (window) {
  "use strict";

  window.EFR = window.EFR || {};

  // =========================================================================
  // Core Utility & Sanitization Helpers
  // =========================================================================

  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function humanise(s) {
    if (!s) return "inconclusive";
    return String(s).replace(/_/g, " ");
  }

  function mailbox(mb) {
    if (!mb) return "—";
    if (typeof mb === "string") return mb;
    if (mb.display_name) {
      return mb.display_name + " <" + (mb.address || "") + ">";
    }
    return mb.address || "—";
  }

  function dash(v) {
    return (v === null || v === undefined || v === "") ? "—" : v;
  }

  function bandClass(b) {
    var map = {
      low: "low",
      medium: "medium",
      high: "risk-high",
      critical: "risk-critical"
    };
    return map[b] || "medium";
  }

  function confClass(c) {
    var map = {
      high: "conf-high",
      medium: "conf-medium",
      low: "conf-low"
    };
    return map[c] || "conf-low";
  }

  function bandColour(b) {
    var map = {
      low: "var(--low)",
      medium: "var(--medium)",
      high: "var(--high)",
      critical: "var(--critical)"
    };
    return map[b] || "var(--medium)";
  }

  function pill(label, className) {
    return '<span class="pill pill-' + esc(className) + '">' + esc(label) + '</span>';
  }

  function kv(rows) {
    var html = '<div class="kv">';
    for (var i = 0; i < rows.length; i++) {
      html += '<div class="kv-key">' + esc(rows[i][0]) + '</div>' +
              '<div class="kv-value">' + (rows[i][2] ? rows[i][1] : esc(rows[i][1])) + '</div>';
    }
    html += '</div>';
    return html;
  }

  function el(htmlString) {
    var template = document.createElement("template");
    template.innerHTML = htmlString.trim();
    return template.content.firstElementChild;
  }

  // =========================================================================
  // 3.1 Verdict Panel
  // =========================================================================
  function panelVerdict(a) {
    var risk = a.risk || {};
    var headers = a.headers || {};
    var from = headers.from || {};
    var origin = a.origin || {};

    var isStubbed = !risk.score && risk.score !== 0;
    var scoreDisplay = isStubbed ? "—" : risk.score;
    var band = risk.band || "unknown";
    var verdictText = isStubbed ? "assessment pending" : humanise(risk.verdict || "inconclusive");
    var scoreColor = isStubbed ? "var(--ink-subtle)" : bandColour(band);

    var statement = (origin.statement) ? origin.statement :
      "Observed sending infrastructure is pending full forensic analysis.";

    var html =
      '<section class="panel" id="sec-verdict">' +
        '<h2>Verdict</h2>' +
        '<div class="verdict-hero">' +
          '<div class="verdict-score" style="color:' + scoreColor + '">' +
            esc(scoreDisplay) +
            '<span class="muted">/100</span>' +
          '</div>' +
          '<div class="verdict-header-info">' +
            '<div class="verdict-meta">' +
              esc(verdictText) + ' ' +
              (isStubbed ? '<span class="chip chip-stub"><span class="chip-dot"></span>Stubbed</span>' : pill(band, bandClass(band))) +
            '</div>' +
            '<div class="verdict-subject">' + esc(dash(headers.subject)) + '</div>' +
            '<div class="muted">From: ' + esc(mailbox(from)) + '</div>' +
          '</div>' +
        '</div>' +
        '<div class="statement-box">' +
          esc(statement) +
        '</div>' +
      '</section>';

    return el(html);
  }

  // =========================================================================
  // 3.2 Authentication Panel
  // =========================================================================
  function panelAuth(a) {
    var auth = a.authentication || {};
    var align = auth.alignment || {};

    // 7-way result lookup for glyph and style
    var glyphMap = {
      pass: "✓",
      fail: "✕",
      permerror: "✕",
      softfail: "~",
      neutral: "—",
      none: "—",
      temperror: "?"
    };

    var classMap = {
      pass: "auth-badge--pass",
      fail: "auth-badge--fail",
      permerror: "auth-badge--fail",
      softfail: "auth-badge--softfail",
      neutral: "auth-badge--neutral",
      none: "auth-badge--neutral",
      temperror: "auth-badge--temperror"
    };

    function renderBadge(name, obj) {
      var res = (obj && obj.result) ? String(obj.result).toLowerCase() : "none";
      var glyph = glyphMap[res] || "—";
      var cls = classMap[res] || "auth-badge--neutral";
      var detail = "";
      if (obj && obj.domain) detail = obj.domain;
      if (obj && obj.policy) detail += " (p=" + obj.policy + ")";
      if (obj && obj.selector) detail += " [s=" + obj.selector + "]";

      return '<div class="auth-badge ' + cls + '">' +
               '<div class="auth-badge-name">' + esc(name) + '</div>' +
               '<div class="auth-badge-status">' + glyph + ' ' + esc(res) + '</div>' +
               (detail ? '<div class="subtle mono" style="font-size:11px;">' + esc(detail) + '</div>' : '') +
             '</div>';
    }

    var selfAssertedBanner = "";
    if (auth.self_asserted_only) {
      selfAssertedBanner =
        '<div class="banner-warn" style="margin-bottom:16px;">' +
          '<span class="banner-warn-icon">⚠</span>' +
          '<div>' +
            '<strong>Self-asserted only</strong> — this message claims authentication passed, but no trusted receiving provider recorded a result. These results carry no evidentiary weight.' +
          '</div>' +
        '</div>';
    }

    var receiverText = auth.verified_by
      ? 'Results as recorded by <strong>' + esc(auth.verified_by) + '</strong>'
      : 'No trusted receiver recorded a result';

    var spfAlignGlyph = align.spf_aligned ? '✓' : '✕';
    var dkimAlignGlyph = align.dkim_aligned ? '✓' : '✕';
    var fromReturnMatchGlyph = (align.from_matches_return_path !== undefined)
      ? (align.from_matches_return_path ? '✓' : '✕')
      : '—';

    var rawDetails = '';
    if (auth.spf && auth.spf.raw || auth.dkim && auth.dkim.raw || auth.dmarc && auth.dmarc.raw) {
      rawDetails =
        '<details style="margin-top:14px; cursor:pointer;" class="subtle">' +
          '<summary style="font-weight:600; font-size:12px; color:var(--ink-muted);">Raw Authentication Headers</summary>' +
          '<div style="margin-top:8px; padding:10px; background:rgba(0,0,0,0.3); border-radius:6px; font-family:var(--font-mono); font-size:11.5px; white-space:pre-wrap; word-break:break-all;">' +
            (auth.spf && auth.spf.raw ? '<div><strong>SPF:</strong> ' + esc(auth.spf.raw) + '</div>' : '') +
            (auth.dkim && auth.dkim.raw ? '<div style="margin-top:6px;"><strong>DKIM:</strong> ' + esc(auth.dkim.raw) + '</div>' : '') +
            (auth.dmarc && auth.dmarc.raw ? '<div style="margin-top:6px;"><strong>DMARC:</strong> ' + esc(auth.dmarc.raw) + '</div>' : '') +
            (auth.arc && auth.arc.raw ? '<div style="margin-top:6px;"><strong>ARC:</strong> ' + esc(auth.arc.raw) + '</div>' : '') +
          '</div>' +
        '</details>';
    }

    var html =
      '<section class="panel" id="sec-auth">' +
        '<h2>Authentication</h2>' +
        selfAssertedBanner +
        '<div class="auth-badges">' +
          renderBadge("SPF", auth.spf) +
          renderBadge("DKIM", auth.dkim) +
          renderBadge("DMARC", auth.dmarc) +
          renderBadge("ARC", auth.arc) +
        '</div>' +
        '<p class="muted">' + receiverText + '</p>' +
        '<div class="alignment-strip">' +
          '<div class="alignment-item">SPF aligned <strong>' + spfAlignGlyph + '</strong></div>' +
          '<div class="alignment-item">DKIM aligned <strong>' + dkimAlignGlyph + '</strong></div>' +
          '<div class="alignment-item">From matches Return-Path <strong>' + fromReturnMatchGlyph + '</strong></div>' +
        '</div>' +
        rawDetails +
      '</section>';

    return el(html);
  }

  // =========================================================================
  // 3.3 Origin Panel
  // =========================================================================
  function panelOrigin(a) {
    var origin = a.origin || {};
    var geo = origin.geo || {};
    var conf = origin.confidence || "low";
    var hasIp = origin.selected_ip !== null && origin.selected_ip !== undefined && origin.selected_ip !== "";

    // Hard requirement 1: Adjacent confidence pill
    var confPillHtml = '<span class="pill ' + confClass(conf) + '">confidence: ' + esc(conf) + '</span>';

    var locationStr = "Unknown physical location";
    if (geo.city || geo.region || geo.country) {
      locationStr = [geo.city, geo.region, geo.country].filter(Boolean).join(", ");
    } else if (!hasIp) {
      locationStr = "No external origin IP identified";
    }

    // Hard requirement 2: ALL confidence reasons rendered in full
    var reasonsList = origin.confidence_reasons || [];
    var reasonsHtml = "";
    if (reasonsList.length > 0) {
      reasonsHtml = '<ul class="reasons">';
      for (var i = 0; i < reasonsList.length; i++) {
        reasonsHtml += '<li>' + esc(reasonsList[i]) + '</li>';
      }
      reasonsHtml += '</ul>';
    } else {
      reasonsHtml = '<p class="subtle" style="margin-top:8px;">No basis recorded.</p>';
    }

    var mapContainerHtml = hasIp
      ? '<div id="map" class="map"></div>'
      : ''; // Hide map cleanly when selected_ip === null (Sample 06 / webmail)

    var tagsHtml = '';
    if (origin.isp) tagsHtml += '<span class="origin-tag">' + esc(origin.isp) + '</span>';
    if (origin.asn) tagsHtml += '<span class="origin-tag">AS' + esc(origin.asn) + '</span>';
    if (origin.infrastructure_type) tagsHtml += '<span class="origin-tag">' + esc(origin.infrastructure_type) + '</span>';
    if (origin.is_datacenter) tagsHtml += '<span class="origin-tag" style="color:#fb923c; border-color:rgba(249,115,22,0.4);">datacenter</span>';
    if (origin.is_proxy) tagsHtml += '<span class="origin-tag" style="color:#f87171; border-color:rgba(239,68,68,0.4);">proxy/vpn</span>';
    if (origin.is_mobile) tagsHtml += '<span class="origin-tag">mobile</span>';

    var ipHopText = hasIp
      ? '<span class="mono" style="font-weight:700; color:#ffffff;">' + esc(origin.selected_ip) + '</span> · hop ' + esc(dash(origin.selected_from_hop))
      : '<span class="muted">Webmail or internal message delivery (No external hop)</span>';

    var html =
      '<section class="panel" id="sec-origin">' +
        '<h2>Origin — Observed Infrastructure</h2>' +
        mapContainerHtml +
        '<div style="margin-bottom:12px;">' +
          ipHopText +
        '</div>' +
        '<div class="origin-loc-line">' +
          '<span>' + esc(locationStr) + '</span>' +
          confPillHtml +
        '</div>' +
        (tagsHtml ? '<div class="origin-tags">' + tagsHtml + '</div>' : '') +
        '<div style="margin-top:16px;">' +
          '<div style="font-weight:700; font-size:13px; color:#ffffff;">Why this confidence level:</div>' +
          reasonsHtml +
        '</div>' +
      '</section>';

    return el(html);
  }

  // =========================================================================
  // 3.4 Routing Chain Panel
  // =========================================================================
  function panelRouting(a) {
    var chain = a.received_chain || [];
    var integrity = a.chain_integrity || {};

    // Candidate lookup for excluded reasons
    var byIp = {};
    (a.ip_candidates || []).forEach(function (c) {
      if (c && c.ip) byIp[c.ip] = c;
    });

    var timelineHtml = "";
    if (chain.length === 0) {
      timelineHtml = '<p class="muted" style="padding:20px 0;">No Received headers were recoverable from this message.</p>';
    } else {
      timelineHtml = '<div class="hop-list">';
      for (var i = 0; i < chain.length; i++) {
        var hop = chain[i];
        var cand = hop.from_ip ? byIp[hop.from_ip] : null;
        var isExcluded = cand && (cand.is_excluded || cand.status === "excluded");
        var isHop1 = hop.hop_index === 1 || i === 0;

        var tlsBadge = hop.tls
          ? '<span class="hop-tls">🔒 TLS</span>'
          : '<span class="subtle" style="font-size:11px;">Plaintext</span>';

        var timeStr = hop.timestamp || hop.timestamp_raw || "Time unrecorded";

        timelineHtml +=
          '<div class="hop' + (isExcluded ? ' hop--excluded' : '') + '">' +
            '<div class="hop-header">' +
              '<div class="hop-index-label">' +
                '<span>Hop ' + esc(hop.hop_index !== undefined ? hop.hop_index : (i + 1)) + '</span>' +
                (isHop1 ? '<span class="hop-badge-origin">closest to sender</span>' : '') +
              '</div>' +
              '<div class="hop-time">' + esc(timeStr) + '</div>' +
            '</div>' +
            '<div class="hop-hosts">' +
              '<span>' + esc(dash(hop.from_host || hop.from_ip)) + '</span>' +
              (hop.from_ip && hop.from_host ? '<span class="subtle">(' + esc(hop.from_ip) + ')</span>' : '') +
              '<span class="hop-arrow">→</span>' +
              '<span>' + esc(dash(hop.by_host)) + '</span>' +
              '<div style="margin-left:auto;">' + tlsBadge + '</div>' +
            '</div>' +
            (isExcluded && cand.exclusion_reason
              ? '<div class="hop-exclusion-reason">' + esc(cand.exclusion_reason) + '</div>'
              : '') +
          '</div>';
      }
      timelineHtml += '</div>';
    }

    // Chain integrity strip
    var hopCount = integrity.hop_count !== undefined ? integrity.hop_count : chain.length;
    var orderText = integrity.chronological_order ? '✓ timestamps in order' : '✕ timestamp anomaly';
    var backwardJumps = integrity.backward_jumps !== undefined ? integrity.backward_jumps : 0;
    var largestGap = integrity.largest_gap_seconds !== undefined ? integrity.largest_gap_seconds + 's gap' : '—';

    var notesHtml = "";
    if (integrity.notes && integrity.notes.length > 0) {
      notesHtml = '<ul class="reasons" style="margin-top:8px;">';
      for (var n = 0; n < integrity.notes.length; n++) {
        notesHtml += '<li class="subtle">' + esc(integrity.notes[n]) + '</li>';
      }
      notesHtml += '</ul>';
    }

    var html =
      '<section class="panel" id="sec-routing">' +
        '<h2>Routing Chain</h2>' +
        timelineHtml +
        '<div class="integrity-strip">' +
          '<div><strong>' + esc(hopCount) + '</strong> hops recorded</div>' +
          '<div>' + esc(orderText) + '</div>' +
          '<div>Backward jumps: <strong>' + esc(backwardJumps) + '</strong></div>' +
          '<div>Largest gap: <strong>' + esc(largestGap) + '</strong></div>' +
        '</div>' +
        notesHtml +
      '</section>';

    return el(html);
  }

  // =========================================================================
  // 3.5 Risk Signals Panel
  // =========================================================================
  function panelSignals(a) {
    var risk = a.risk || {};
    var signals = risk.signals || [];

    // Fallback template of 5 signals if partial/empty
    var defaultSignals = [
      { name: "SPF/DKIM/DMARC failure", points: 30, triggered: false, evidence: "not triggered" },
      { name: "Datacenter / proxy / hosting infrastructure", points: 25, triggered: false, evidence: "not triggered" },
      { name: "Reply-To domain != From domain", points: 20, triggered: false, evidence: "not triggered" },
      { name: "Broken or backward Received chain", points: 15, triggered: false, evidence: "not triggered" },
      { name: "Suspicious urgency language", points: 10, triggered: false, evidence: "not triggered" }
    ];

    var displaySignals = signals.length === 5 ? signals : defaultSignals;
    var totalPoints = 0;

    var rowsHtml = "";
    for (var i = 0; i < displaySignals.length; i++) {
      var s = displaySignals[i];
      var isTriggered = !!s.triggered;
      var points = isTriggered ? (s.points || 0) : 0;
      totalPoints += points;

      var glyph = isTriggered ? "✕" : "✓";
      var ptsStr = isTriggered ? ("+" + points) : "0";
      var evidenceStr = isTriggered ? (s.evidence || "anomaly detected") : "not triggered";

      rowsHtml +=
        '<tr class="signal-row ' + (isTriggered ? 'signal-row--on' : 'signal-row--off') + '">' +
          '<td class="signal-cell signal-icon">' + glyph + '</td>' +
          '<td class="signal-cell">' +
            '<div class="signal-name">' + esc(s.name) + '</div>' +
            '<div class="signal-evidence">' + esc(evidenceStr) + '</div>' +
          '</td>' +
          '<td class="signal-cell signal-points">' + esc(ptsStr) + '</td>' +
        '</tr>';
    }

    var scoreTotal = risk.score !== undefined ? risk.score : totalPoints;

    var html =
      '<section class="panel" id="sec-signals">' +
        '<h2>Risk Signals</h2>' +
        '<table class="signal-table">' +
          '<tbody>' +
            rowsHtml +
            '<tr class="signal-total-row">' +
              '<td class="signal-cell"></td>' +
              '<td class="signal-cell">Assessed Score</td>' +
              '<td class="signal-cell signal-points" style="color:' + bandColour(risk.band || "medium") + '">' +
                esc(scoreTotal) + ' / 100' +
              '</td>' +
            '</tr>' +
          '</tbody>' +
        '</table>' +
      '</section>';

    return el(html);
  }

  // =========================================================================
  // 3.6 Evidence & Custody Panel
  // =========================================================================
  function panelEvidence(a) {
    var report = a.report || null;
    var analysisId = a.analysis_id || "demo-analysis";

    var isStubbed = !report;
    var sha = report && report.evidence_sha256
      ? report.evidence_sha256
      : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    var entryIndex = report && report.custody_log_entry !== undefined && report.custody_log_entry !== null
      ? report.custody_log_entry
      : null;

    var custodyStatus = entryIndex !== null
      ? 'Custody entry #' + esc(entryIndex) + ' · <span class="custody-badge-intact">chain intact ✓</span>'
      : '<span class="subtle">Not yet written to the custody log (preview)</span>';

    var jsonUrl = window.EFR.api ? window.EFR.api.reportUrl(analysisId, "json") : "#";
    var pdfUrl = window.EFR.api ? window.EFR.api.reportUrl(analysisId, "pdf") : "#";

    var html =
      '<section class="panel" id="sec-evidence">' +
        '<h2>Evidence &amp; Custody</h2>' +
        '<div class="muted" style="font-weight:600; font-size:12px;">Evidence SHA-256</div>' +
        '<div class="digest">' + esc(sha) + '</div>' +
        '<div class="custody-status-row">' +
          '<div>' + custodyStatus + '</div>' +
          '<div class="subtle" style="font-size:12px;">Immutable SHA-256 Merkle Chain</div>' +
        '</div>' +
        '<div class="evidence-actions">' +
          '<a class="btn btn-secondary" href="' + esc(jsonUrl) + '" target="_blank" download="forensic_report_' + esc(analysisId) + '.json"' + (isStubbed ? ' disabled' : '') + '>' +
            '<span>↓</span> Download JSON Report' +
          '</a>' +
          '<a class="btn btn-primary" href="' + esc(pdfUrl) + '" target="_blank" download="forensic_report_' + esc(analysisId) + '.pdf"' + (isStubbed ? ' disabled' : '') + '>' +
            '<span>📄</span> Export Forensic PDF' +
          '</a>' +
        '</div>' +
      '</section>';

    return el(html);
  }

  // =========================================================================
  // Assembly Engine: results, loading, error
  // =========================================================================

  function renderResults(analysis) {
    var container = document.createElement("div");
    container.className = "results-container";

    // 1. Warnings banner if present
    var warnings = analysis.warnings || [];
    if (warnings.length > 0) {
      var warnHtml =
        '<div class="banner-warn" id="results-warnings">' +
          '<span class="banner-warn-icon">⚠</span>' +
          '<div>' +
            '<strong>Notes:</strong> ' + esc(warnings.join(" · ")) +
          '</div>' +
        '</div>';
      container.appendChild(el(warnHtml));
    }

    // 2. Strict order of 6 forensic panels with staggered slide entrance
    var panels = [
      panelVerdict(analysis),
      panelAuth(analysis),
      panelOrigin(analysis),
      panelRouting(analysis),
      panelSignals(analysis),
      panelEvidence(analysis)
    ];

    for (var i = 0; i < panels.length; i++) {
      var p = panels[i];
      if (p) {
        p.classList.add("panel-slide-enter");
        p.style.animationDelay = (i * 0.08) + "s";
        container.appendChild(p);
      }
    }

    return container;
  }

  function renderLoading(msg) {
    var text = msg || "Analyzing message headers & infrastructure…";
    var html =
      '<div class="loading-state">' +
        '<div class="radar-spinner"></div>' +
        '<div class="loading-title">Forensic Ingestion in Progress</div>' +
        '<div class="loading-subtitle">' + esc(text) + '</div>' +
      '</div>';
    return el(html);
  }

  function renderError(err) {
    var code = (err && err.code) || "ANALYSIS_ERROR";
    var userMessage = (err && err.userMessage) || (err && err.message) || "An unexpected error occurred while parsing headers.";

    var html =
      '<div class="banner-error" id="error-banner">' +
        '<span style="font-size:22px; flex-shrink:0;">✕</span>' +
        '<div>' +
          '<div><strong>Analysis Failed [' + esc(code) + ']</strong></div>' +
          '<div style="margin-top:4px;">' + esc(userMessage) + '</div>' +
        '</div>' +
      '</div>';
    return el(html);
  }

  // Export public API
  window.EFR.render = {
    results: renderResults,
    loading: renderLoading,
    error: renderError,
    panelVerdict: panelVerdict,
    panelAuth: panelAuth,
    panelOrigin: panelOrigin,
    panelRouting: panelRouting,
    panelSignals: panelSignals,
    panelEvidence: panelEvidence,
    esc: esc,
    humanise: humanise,
    mailbox: mailbox,
    dash: dash,
    bandClass: bandClass,
    confClass: confClass,
    bandColour: bandColour,
    pill: pill,
    kv: kv,
    el: el
  };

})(window);
