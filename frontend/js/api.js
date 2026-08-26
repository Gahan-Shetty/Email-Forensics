/* API client.   OWNER: M6 (Integration).   M5: call these, don't edit them.
 *
 * Every function resolves with a contract-shaped analysis object, or rejects
 * with an Error carrying .code and .userMessage so render.error() can show
 * something useful instead of "[object Object]".
 */
(function () {
  "use strict";
  window.EFR = window.EFR || {};

  // Change this one line if you move the backend off localhost.
  const BASE = "http://127.0.0.1:8000";

  function apiError(code, userMessage, detail) {
    const e = new Error(userMessage);
    e.code = code;
    e.userMessage = userMessage;
    e.detail = detail || null;
    return e;
  }

  async function handle(res) {
    let body = null;
    try { body = await res.json(); } catch (_) { /* non-JSON error page */ }

    if (!res.ok) {
      const err = body && body.error;
      throw apiError(
        (err && err.code) || "HTTP_" + res.status,
        (err && err.message) || "The server returned an error (" + res.status + ").",
        err && err.detail
      );
    }
    if (!body || !body.schema_version) {
      throw apiError("BAD_RESPONSE", "The server returned an unexpected response shape.");
    }
    return body;
  }

  function wrapNetwork(promise) {
    return promise.catch(function (e) {
      if (e.code) throw e;             // already one of ours
      throw apiError("NETWORK",
        "Could not reach the analyzer API at " + BASE +
        ". Is the backend running? (scripts/run_backend.sh)");
    });
  }

  window.EFR.api = {
    analyzeText: function (rawEmail, options) {
      return wrapNetwork(
        fetch(BASE + "/api/v1/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            raw_email: rawEmail,
            options: Object.assign({ skip_geoip: false, include_body_heuristics: true }, options || {})
          })
        }).then(handle)
      );
    },

    analyzeFile: function (file) {
      const fd = new FormData();
      fd.append("file", file);
      return wrapNetwork(
        fetch(BASE + "/api/v1/analyze", { method: "POST", body: fd }).then(handle)
      );
    },

    /* The frozen fixture. Works with zero backend logic implemented - this is
     * what M5 builds the entire dashboard against on Day 1. */
    mock: function () {
      return wrapNetwork(fetch(BASE + "/api/v1/mock/analyze").then(handle));
    },

    health: function () {
      return wrapNetwork(fetch(BASE + "/api/v1/health").then(function (r) { return r.json(); }));
    },

    reportUrl: function (analysisId, kind) {
      return BASE + "/api/v1/report/" + encodeURIComponent(analysisId) + "." + (kind === "pdf" ? "pdf" : "json");
    },

    custodyLog: function () {
      return wrapNetwork(fetch(BASE + "/api/v1/custody-log").then(handle));
    }
  };
})();
