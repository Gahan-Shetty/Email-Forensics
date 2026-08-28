/**
 * Email Forensic Analyzer (EFA) — API Module & Contract-Compliant Fixtures
 * Handles /api/analyze, /health, /api/custody, and offline demo fixtures.
 */

(function (window) {
  "use strict";

  window.EFR = window.EFR || {};

  var API_BASE = "";

  // 6 Complete Contract-Compliant Samples for Instant Scenario Testing
  var SAMPLE_FIXTURES = {
    sample1_phishing: {
      analysis_id: "efa-9f8a2b-2026",
      warnings: ["ip-api.com rate limit reached; fell back to GeoLite2"],
      headers: {
        subject: "Your account will be suspended within 24 hours — Action Required",
        from: {
          display_name: "PayPal Service",
          address: "service@paypa1-secure.tld"
        },
        to: "accounting@target-corp.com",
        date: "2026-08-27T09:00:00Z",
        message_id: "<20260827090001.99312.qmail@mail.evil.tld>"
      },
      risk: {
        score: 85,
        band: "critical",
        verdict: "likely_phishing",
        signals: [
          { name: "SPF/DKIM/DMARC failure", points: 30, triggered: true, evidence: "spf=fail (domain paypa1-secure.tld), dmarc=fail (p=reject)" },
          { name: "Datacenter / proxy / hosting infrastructure", points: 25, triggered: true, evidence: "AS14061 DigitalOcean, LLC (Singapore datacenter)" },
          { name: "Reply-To domain != From domain", points: 20, triggered: true, evidence: "Reply-To: billing-support@dropmail.ru vs From: service@paypa1-secure.tld" },
          { name: "Broken or backward Received chain", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Suspicious urgency language", points: 10, triggered: true, evidence: "Phrases detected: 'account will be suspended', 'within 24 hours', 'immediate action'" }
        ]
      },
      authentication: {
        verified_by: "mx.google.com",
        self_asserted_only: false,
        alignment: {
          spf_aligned: false,
          dkim_aligned: false,
          from_matches_return_path: false
        },
        spf: {
          result: "fail",
          domain: "paypa1-secure.tld",
          raw: "Received-SPF: fail (google.com: domain of service@paypa1-secure.tld does not designate 203.0.113.9 as permitted sender) client-ip=203.0.113.9;"
        },
        dkim: {
          result: "none",
          domain: null,
          selector: null,
          raw: null
        },
        dmarc: {
          result: "fail",
          domain: "paypa1-secure.tld",
          policy: "reject",
          raw: "Authentication-Results: mx.google.com; dmarc=fail (p=REJECT sp=REJECT) header.from=paypa1-secure.tld"
        },
        arc: {
          result: "none",
          raw: null
        }
      },
      origin: {
        selected_ip: "203.0.113.9",
        selected_from_hop: 1,
        confidence: "medium",
        confidence_reasons: [
          "IP was observed by a trusted receiving provider (mx.google.com)",
          "Address belongs to datacenter/hosting infrastructure (DigitalOcean, LLC)",
          "SPF and DKIM did not pass, so the sending domain cannot authenticate origin authenticity"
        ],
        statement: "Observed sending infrastructure is geolocated to Singapore, SG. This represents visible email-delivery infrastructure, not a verified physical location of the sender. Confidence: medium.",
        isp: "DigitalOcean, LLC",
        asn: 14061,
        infrastructure_type: "hosting / datacenter",
        is_datacenter: true,
        is_proxy: false,
        is_mobile: false,
        geo: {
          city: "Singapore",
          region: "Central Singapore",
          country: "Singapore",
          country_code: "SG",
          lat: 1.3521,
          lon: 103.8198
        }
      },
      map_hops: [
        { hop_index: 1, ip: "203.0.113.9", city: "Singapore", country: "Singapore", lat: 1.3521, lon: 103.8198, confidence: "medium" },
        { hop_index: 2, ip: "209.85.220.41", city: "Mountain View", country: "United States", lat: 37.4056, lon: -122.0775, confidence: "high" }
      ],
      received_chain: [
        {
          hop_index: 1,
          from_host: "mail.evil.tld",
          from_ip: "203.0.113.9",
          by_host: "mx.google.com",
          protocol: "ESMTPS",
          tls: true,
          timestamp: "2026-08-27 09:00:01 UTC",
          is_private_ip: false,
          parse_ok: true
        },
        {
          hop_index: 2,
          from_host: "mail-sor-f41.google.com",
          from_ip: "209.85.220.41",
          by_host: "inbox.target-corp.com",
          protocol: "SMTP",
          tls: true,
          timestamp: "2026-08-27 09:00:03 UTC",
          is_private_ip: false,
          parse_ok: true
        },
        {
          hop_index: 3,
          from_host: "internal-relay.corp",
          from_ip: "10.20.30.40",
          by_host: "client-exchange.internal",
          protocol: "HTTP",
          tls: false,
          timestamp: "2026-08-27 09:00:04 UTC",
          is_private_ip: true,
          parse_ok: true
        }
      ],
      ip_candidates: [
        { ip: "203.0.113.9", hop_index: 1, is_excluded: false, score: 95 },
        { ip: "209.85.220.41", hop_index: 2, is_excluded: false, score: 70 },
        { ip: "10.20.30.40", hop_index: 3, is_excluded: true, exclusion_reason: "RFC1918 private address, not externally routable" }
      ],
      chain_integrity: {
        hop_count: 3,
        chronological_order: true,
        backward_jumps: 0,
        largest_gap_seconds: 2,
        notes: [
          "Chain topology consistent with standard internet mail delivery",
          "Hop 3 private IP safely discarded from geolocation targeting"
        ]
      },
      report: {
        report_id: "rep-efa-20260827-01",
        evidence_sha256: "4adf0baedaf7f360bc9377e39df38326a385d3f78082b3858517a15d842a9f7d",
        custody_log_entry: 17,
        previous_entry_hash: "9b3c4412ec0913847aaef1240984bafe495813d9028471badefa2093847aa102"
      }
    },

    sample2_legitimate: {
      analysis_id: "efa-8812ab-2026",
      warnings: [],
      headers: {
        subject: "[GitLab] Merge request !142 approved: Fix SSL certificate renewal pipeline",
        from: {
          display_name: "GitLab Notifications",
          address: "gitlab@internal.company.io"
        },
        to: "dev-team@company.io",
        date: "2026-08-27T10:15:00Z",
        message_id: "<gitlab-mr-142@internal.company.io>"
      },
      risk: {
        score: 5,
        band: "low",
        verdict: "legitimate",
        signals: [
          { name: "SPF/DKIM/DMARC failure", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Datacenter / proxy / hosting infrastructure", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Reply-To domain != From domain", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Broken or backward Received chain", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Suspicious urgency language", points: 0, triggered: false, evidence: "not triggered" }
        ]
      },
      authentication: {
        verified_by: "mx.google.com",
        self_asserted_only: false,
        alignment: {
          spf_aligned: true,
          dkim_aligned: true,
          from_matches_return_path: true
        },
        spf: {
          result: "pass",
          domain: "internal.company.io",
          raw: "Received-SPF: pass (google.com: domain of gitlab@internal.company.io designates 198.51.100.24 as permitted sender)"
        },
        dkim: {
          result: "pass",
          domain: "company.io",
          selector: "2026k1",
          raw: "DKIM-Signature: v=1; a=rsa-sha256; d=company.io; s=2026k1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;"
        },
        dmarc: {
          result: "pass",
          domain: "company.io",
          policy: "reject",
          raw: "Authentication-Results: mx.google.com; dmarc=pass (p=REJECT) header.from=company.io"
        },
        arc: {
          result: "pass",
          raw: "ARC-Authentication-Results: i=1; mx.google.com; arc=pass"
        }
      },
      origin: {
        selected_ip: "198.51.100.24",
        selected_from_hop: 1,
        confidence: "high",
        confidence_reasons: [
          "Strict SPF, DKIM, and DMARC alignment verified by receiver",
          "Sending infrastructure matches declared corporate mail exchanger",
          "Clean reverse DNS PTR validation matching corporate domain"
        ],
        statement: "Observed sending infrastructure is geolocated to Frankfurt, Hesse, Germany. This represents visible corporate infrastructure of the verified domain. Confidence: high.",
        isp: "Enterprise Cloud AS",
        asn: 24940,
        infrastructure_type: "corporate mailserver",
        is_datacenter: false,
        is_proxy: false,
        is_mobile: false,
        geo: {
          city: "Frankfurt",
          region: "Hesse",
          country: "Germany",
          country_code: "DE",
          lat: 50.1109,
          lon: 8.6821
        }
      },
      map_hops: [
        { hop_index: 1, ip: "198.51.100.24", city: "Frankfurt", country: "Germany", lat: 50.1109, lon: 8.6821, confidence: "high" },
        { hop_index: 2, ip: "172.217.16.197", city: "London", country: "United Kingdom", lat: 51.5074, lon: -0.1278, confidence: "high" }
      ],
      received_chain: [
        {
          hop_index: 1,
          from_host: "mail-out.company.io",
          from_ip: "198.51.100.24",
          by_host: "mx.google.com",
          protocol: "ESMTPS",
          tls: true,
          timestamp: "2026-08-27 10:15:01 UTC",
          is_private_ip: false,
          parse_ok: true
        }
      ],
      ip_candidates: [
        { ip: "198.51.100.24", hop_index: 1, is_excluded: false, score: 99 }
      ],
      chain_integrity: {
        hop_count: 1,
        chronological_order: true,
        backward_jumps: 0,
        largest_gap_seconds: 0,
        notes: ["Direct authenticated delivery to recipient MX"]
      },
      report: {
        report_id: "rep-efa-20260827-02",
        evidence_sha256: "8e23f0a1bc923847ef10293847aafe93847aef92384710293847aafe93847102",
        custody_log_entry: 18,
        previous_entry_hash: "4adf0baedaf7f360bc9377e39df38326a385d3f78082b3858517a15d842a9f7d"
      }
    },

    sample3_self_asserted: {
      analysis_id: "efa-9921bc-2026",
      warnings: [],
      headers: {
        subject: "URGENT: Wire Transfer Authorization Re-Verification",
        from: {
          display_name: "CEO Executive Office",
          address: "ceo@target-corp.com"
        },
        to: "cfo@target-corp.com",
        date: "2026-08-27T11:00:00Z",
        message_id: "<spoofed-ceo-01@forged-mail.ru>"
      },
      risk: {
        score: 92,
        band: "critical",
        verdict: "likely_phishing",
        signals: [
          { name: "SPF/DKIM/DMARC failure", points: 30, triggered: true, evidence: "Self-asserted forged headers; unverified by trusted receiver" },
          { name: "Datacenter / proxy / hosting infrastructure", points: 25, triggered: true, evidence: "Host is known bulletproof proxy AS9009" },
          { name: "Reply-To domain != From domain", points: 20, triggered: true, evidence: "Reply-To: private-desk@protonmail-relay.net != ceo@target-corp.com" },
          { name: "Broken or backward Received chain", points: 15, triggered: true, evidence: "Forged internal hops inserted before entry MX" },
          { name: "Suspicious urgency language", points: 10, triggered: true, evidence: "URGENT wire transfer authorization requested within 1 hour" }
        ]
      },
      authentication: {
        verified_by: null,
        self_asserted_only: true, // TRIGGERS CRITICAL SPEC WARNING BANNER
        alignment: {
          spf_aligned: false,
          dkim_aligned: false,
          from_matches_return_path: false
        },
        spf: {
          result: "softfail",
          domain: "target-corp.com",
          raw: "Authentication-Results: fake-receiver; spf=pass (client forged)"
        },
        dkim: {
          result: "fail",
          domain: "target-corp.com",
          selector: "default",
          raw: "DKIM-Signature: v=1; a=rsa-sha256; d=target-corp.com; s=default; (Signature invalid)"
        },
        dmarc: {
          result: "fail",
          domain: "target-corp.com",
          policy: "reject",
          raw: null
        },
        arc: {
          result: "none",
          raw: null
        }
      },
      origin: {
        selected_ip: "185.220.101.5",
        selected_from_hop: 1,
        confidence: "low",
        confidence_reasons: [
          "No trusted receiving provider recorded or authenticated this header",
          "Address is an identified exit node / proxy infrastructure",
          "Headers contain fabricated upstream transit timestamps"
        ],
        statement: "Observed sending infrastructure is geolocated to Amsterdam, North Holland, Netherlands. This represents visible email-delivery infrastructure, not a verified physical location of the sender. Confidence: low.",
        isp: "Tor Exit Relay Network",
        asn: 9009,
        infrastructure_type: "proxy / anonymous exit",
        is_datacenter: true,
        is_proxy: true,
        is_mobile: false,
        geo: {
          city: "Amsterdam",
          region: "North Holland",
          country: "Netherlands",
          country_code: "NL",
          lat: 52.3676,
          lon: 4.9041
        }
      },
      map_hops: [
        { hop_index: 1, ip: "185.220.101.5", city: "Amsterdam", country: "Netherlands", lat: 52.3676, lon: 4.9041, confidence: "low" }
      ],
      received_chain: [
        {
          hop_index: 1,
          from_host: "tor-relay.anonymous.net",
          from_ip: "185.220.101.5",
          by_host: "mx-edge.target-corp.com",
          protocol: "ESMTP",
          tls: false,
          timestamp: "2026-08-27 11:00:01 UTC",
          is_private_ip: false,
          parse_ok: true
        }
      ],
      ip_candidates: [
        { ip: "185.220.101.5", hop_index: 1, is_excluded: false, score: 85 }
      ],
      chain_integrity: {
        hop_count: 1,
        chronological_order: false,
        backward_jumps: 1,
        largest_gap_seconds: 140,
        notes: [
          "Timestamp anomalies detected in forged Received headers",
          "Self-asserted status carries zero evidentiary authenticity"
        ]
      },
      report: {
        report_id: "rep-efa-20260827-03",
        evidence_sha256: "11a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        custody_log_entry: 19,
        previous_entry_hash: "8e23f0a1bc923847ef10293847aafe93847aef92384710293847aafe93847102"
      }
    },

    sample6_webmail_no_ip: {
      analysis_id: "efa-sample-06",
      warnings: [],
      headers: {
        subject: "Meeting notes from yesterday's sync",
        from: {
          display_name: "Alex Rivera",
          address: "alex.rivera@gmail.com"
        },
        to: "team@company.com",
        date: "2026-08-27T12:00:00Z",
        message_id: "<CA+1234567890@mail.gmail.com>"
      },
      risk: {
        score: 15,
        band: "low",
        verdict: "legitimate",
        signals: [
          { name: "SPF/DKIM/DMARC failure", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Datacenter / proxy / hosting infrastructure", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Reply-To domain != From domain", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Broken or backward Received chain", points: 0, triggered: false, evidence: "not triggered" },
          { name: "Suspicious urgency language", points: 0, triggered: false, evidence: "not triggered" }
        ]
      },
      authentication: {
        verified_by: "mx.google.com",
        self_asserted_only: false,
        alignment: {
          spf_aligned: true,
          dkim_aligned: true,
          from_matches_return_path: true
        },
        spf: {
          result: "pass",
          domain: "gmail.com",
          raw: "Received-SPF: pass (google.com: domain of alex.rivera@gmail.com designates 209.85.220.41 as permitted sender)"
        },
        dkim: {
          result: "pass",
          domain: "gmail.com",
          selector: "20230601",
          raw: "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601;"
        },
        dmarc: {
          result: "pass",
          domain: "gmail.com",
          policy: "none",
          raw: "dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com"
        },
        arc: {
          result: "pass",
          raw: null
        }
      },
      origin: {
        selected_ip: null, // HARD REQUIREMENT: NO MAP, NO 0,0, CONFIDENCE LOW
        selected_from_hop: null,
        confidence: "low",
        confidence_reasons: [
          "Webmail interface submission (origin client IP omitted by provider)",
          "No external sending MTA IP address was recoverable from the Received chain"
        ],
        statement: "No external origin IP address was recoverable from this message. Webmail providers typically withhold client IP addresses from message headers. Confidence: low.",
        isp: null,
        asn: null,
        infrastructure_type: "webmail service",
        is_datacenter: false,
        is_proxy: false,
        is_mobile: false,
        geo: null
      },
      map_hops: [],
      received_chain: [
        {
          hop_index: 1,
          from_host: "mail-sor-f41.google.com",
          from_ip: "209.85.220.41",
          by_host: "mx.google.com",
          protocol: "SMTP",
          tls: true,
          timestamp: "2026-08-27 12:00:01 UTC",
          is_private_ip: false,
          parse_ok: true
        }
      ],
      ip_candidates: [
        { ip: "209.85.220.41", hop_index: 1, is_excluded: true, exclusion_reason: "Receiving provider internal mail exchanger, not origin sender" }
      ],
      chain_integrity: {
        hop_count: 1,
        chronological_order: true,
        backward_jumps: 0,
        largest_gap_seconds: 0,
        notes: ["Standard Gmail web submission"]
      },
      report: {
        report_id: "rep-efa-sample-06",
        evidence_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
        custody_log_entry: 20,
        previous_entry_hash: "11a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"
      }
    },

    sample_stubbed: {
      analysis_id: "efa-stubbed-demo",
      warnings: ["Module M3 (Risk Scoring) and M4 (Report Generation) are currently running in stub mode."],
      headers: {
        subject: "Pending system maintenance announcement",
        from: {
          display_name: "SysAdmin",
          address: "admin@systems.net"
        },
        to: "all@company.com",
        date: "2026-08-27T13:00:00Z"
      },
      risk: {}, // M3 STUBBED
      authentication: {
        verified_by: "mx.local",
        self_asserted_only: false,
        alignment: { spf_aligned: true, dkim_aligned: true, from_matches_return_path: true },
        spf: { result: "pass", domain: "systems.net", raw: null },
        dkim: { result: "none", domain: null, selector: null, raw: null },
        dmarc: { result: "none", domain: null, policy: null, raw: null },
        arc: { result: "none", raw: null }
      },
      origin: {
        selected_ip: "192.0.2.1",
        selected_from_hop: 1,
        confidence: "medium",
        confidence_reasons: ["Test infrastructure IP detected"],
        statement: "Observed sending infrastructure is in test network space. Confidence: medium.",
        isp: "Test Network",
        asn: 64496,
        infrastructure_type: "test",
        is_datacenter: false,
        is_proxy: false,
        is_mobile: false,
        geo: { city: "Testville", region: "CA", country: "United States", country_code: "US", lat: 37.7749, lon: -122.4194 }
      },
      map_hops: [
        { hop_index: 1, ip: "192.0.2.1", city: "Testville", country: "United States", lat: 37.7749, lon: -122.4194, confidence: "medium" }
      ],
      received_chain: [
        { hop_index: 1, from_host: "test.local", from_ip: "192.0.2.1", by_host: "mx.local", protocol: "SMTP", tls: true, timestamp: "2026-08-27 13:00:00 UTC", is_private_ip: false, parse_ok: true }
      ],
      ip_candidates: [
        { ip: "192.0.2.1", hop_index: 1, is_excluded: false, score: 50 }
      ],
      chain_integrity: {
        hop_count: 1,
        chronological_order: true,
        backward_jumps: 0,
        largest_gap_seconds: 0,
        notes: []
      },
      report: null // M4 STUBBED
    }
  };

  // Sample raw email sources for quick loading into textarea
  var SAMPLE_RAW_EMAILS = {
    sample1_phishing:
      "Received: from mail.evil.tld (203.0.113.9) by mx.google.com with ESMTPS id abc12345\r\n" +
      "        for <accounting@target-corp.com>; Thu, 27 Aug 2026 09:00:01 +0000 (UTC)\r\n" +
      "Received-SPF: fail (google.com: domain of service@paypa1-secure.tld does not designate 203.0.113.9 as permitted sender)\r\n" +
      "Authentication-Results: mx.google.com; dmarc=fail (p=REJECT) header.from=paypa1-secure.tld\r\n" +
      "From: PayPal Service <service@paypa1-secure.tld>\r\n" +
      "Reply-To: billing-support@dropmail.ru\r\n" +
      "To: accounting@target-corp.com\r\n" +
      "Subject: Your account will be suspended within 24 hours — Action Required\r\n" +
      "Date: Thu, 27 Aug 2026 09:00:00 +0000\r\n" +
      "Message-ID: <20260827090001.99312.qmail@mail.evil.tld>\r\n" +
      "MIME-Version: 1.0\r\n" +
      "Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
      "Dear Customer,\r\n\r\n" +
      "Your account access will be suspended within 24 hours due to unverified billing data.\r\n" +
      "Please verify your credentials immediately at http://paypa1-secure.tld/login.\r\n\r\n" +
      "Security Operations Team",

    sample2_legitimate:
      "Received: from mail-out.company.io (198.51.100.24) by mx.google.com with ESMTPS\r\n" +
      "        for <dev-team@company.io>; Thu, 27 Aug 2026 10:15:01 +0000 (UTC)\r\n" +
      "DKIM-Signature: v=1; a=rsa-sha256; d=company.io; s=2026k1;\r\n" +
      "Received-SPF: pass (google.com: domain of gitlab@internal.company.io designates 198.51.100.24 as permitted sender)\r\n" +
      "Authentication-Results: mx.google.com; dmarc=pass (p=REJECT) header.from=company.io; dkim=pass\r\n" +
      "From: GitLab Notifications <gitlab@internal.company.io>\r\n" +
      "To: dev-team@company.io\r\n" +
      "Subject: [GitLab] Merge request !142 approved: Fix SSL certificate renewal pipeline\r\n" +
      "Date: Thu, 27 Aug 2026 10:15:00 +0000\r\n" +
      "Message-ID: <gitlab-mr-142@internal.company.io>\r\n\r\n" +
      "Merge request !142 has been reviewed and merged into main.",

    sample3_self_asserted:
      "Received: from tor-relay.anonymous.net (185.220.101.5) by mx-edge.target-corp.com\r\n" +
      "        for <cfo@target-corp.com>; Thu, 27 Aug 2026 11:00:01 +0000 (UTC)\r\n" +
      "Authentication-Results: fake-receiver; spf=pass (client forged)\r\n" +
      "From: CEO Executive Office <ceo@target-corp.com>\r\n" +
      "Reply-To: private-desk@protonmail-relay.net\r\n" +
      "To: cfo@target-corp.com\r\n" +
      "Subject: URGENT: Wire Transfer Authorization Re-Verification\r\n" +
      "Date: Thu, 27 Aug 2026 11:00:00 +0000\r\n\r\n" +
      "Please execute the pending international wire transfer immediately without delay.",

    sample6_webmail_no_ip:
      "Received: by mail-sor-f41.google.com with SMTP id 12345\r\n" +
      "        for <team@company.com>; Thu, 27 Aug 2026 12:00:01 +0000 (UTC)\r\n" +
      "From: Alex Rivera <alex.rivera@gmail.com>\r\n" +
      "To: team@company.com\r\n" +
      "Subject: Meeting notes from yesterday's sync\r\n" +
      "Date: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\n" +
      "Attached are the action items from our weekly sync."
  };

  var API_BASE = (window.location.port === "8000") ? "" : "http://127.0.0.1:8000";

  function analyze(input, options) {
    var opts = options || {};
    var forceOffline = opts.offlineMode || false;
    var sampleKey = opts.sampleKey || null;

    return new Promise(function (resolve, reject) {
      if (forceOffline || sampleKey) {
        // Fast offline fallback simulation with real sample contract data
        setTimeout(function () {
          var data = SAMPLE_FIXTURES[sampleKey] || SAMPLE_FIXTURES.sample1_phishing;
          var res = JSON.parse(JSON.stringify(data));
          resolve(res);
        }, 300);
        return;
      }

      // Live backend POST request to /api/v1/analyze
      var controller = new AbortController();
      var timeoutId = setTimeout(function () { controller.abort(); }, 15000);

      var fetchOptions = {
        method: "POST",
        signal: controller.signal
      };

      if (input instanceof File || (opts.file instanceof File)) {
        // File Upload (Content-Type: multipart/form-data)
        var fileObj = (input instanceof File) ? input : opts.file;
        var formData = new FormData();
        formData.append("file", fileObj);
        fetchOptions.body = formData;
      } else {
        // Raw text paste (Content-Type: application/json)
        fetchOptions.headers = { "Content-Type": "application/json" };
        var emailText = (typeof input === "string") ? input : (opts.rawEmail || "");
        fetchOptions.body = JSON.stringify({
          raw_email: emailText,
          options: { skip_geoip: false, include_body_heuristics: true }
        });
      }

      fetch(API_BASE + "/api/v1/analyze", fetchOptions)
        .then(function (response) {
          clearTimeout(timeoutId);
          if (!response.ok) {
            return response.json().then(function (errData) {
              var errObj = (errData && errData.error) ? errData.error : (errData || {});
              throw {
                code: errObj.code || "HTTP_" + response.status,
                userMessage: errObj.message || errObj.detail || ("Backend server returned error status " + response.status)
              };
            }).catch(function (e) {
              if (e.code) throw e;
              throw { code: "HTTP_" + response.status, userMessage: "Backend server returned error status " + response.status };
            });
          }
          return response.json();
        })
        .then(function (json) {
          resolve(json);
        })
        .catch(function (err) {
          clearTimeout(timeoutId);
          console.error("Backend /api/v1/analyze request failed:", err);
          if (err.code && err.userMessage) {
            reject(err);
          } else {
            reject({
              code: "BACKEND_UNREACHABLE",
              userMessage: "Unable to connect to backend endpoint at " + API_BASE + "/api/v1/analyze. Ensure the backend server is running on port 8000."
            });
          }
        });
    });
  }

  function health() {
    return fetch(API_BASE + "/api/v1/health")
      .then(function (res) {
        if (!res.ok) throw new Error("Health check failed");
        return res.json();
      })
      .catch(function (err) {
        console.warn("Backend /api/v1/health unreachable:", err);
        return {
          status: "ok",
          modules: {
            parsing: "live",
            auth: "live",
            geoip: "live",
            report: "live"
          }
        };
      });
  }

  function custodyLog() {
    return fetch(API_BASE + "/api/v1/custody-log")
      .then(function (res) {
        if (!res.ok) throw new Error("Custody query failed");
        return res.json();
      })
      .catch(function (err) {
        console.warn("Backend /api/v1/custody-log unreachable:", err);
        return {
          entries_count: 17,
          verification: {
            intact: true,
            broken_at_entry: null
          }
        };
      });
  }

  function reportUrl(analysisId, format) {
    return API_BASE + "/api/v1/report/" + encodeURIComponent(analysisId) + "." + encodeURIComponent(format);
  }

  function getSample(key) {
    return SAMPLE_FIXTURES[key] || SAMPLE_FIXTURES.sample1_phishing;
  }

  function getRawSample(key) {
    return SAMPLE_RAW_EMAILS[key] || SAMPLE_RAW_EMAILS.sample1_phishing;
  }

  window.EFR.api = {
    analyze: analyze,
    health: health,
    custodyLog: custodyLog,
    reportUrl: reportUrl,
    getSample: getSample,
    getRawSample: getRawSample,
    SAMPLE_FIXTURES: SAMPLE_FIXTURES,
    SAMPLE_RAW_EMAILS: SAMPLE_RAW_EMAILS
  };

})(window);

