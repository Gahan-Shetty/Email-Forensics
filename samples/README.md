# Sample emails — OWNER: M6

Six deliberately chosen inputs. **These are synthetic**: the domains are
RFC-reserved or `.tld`/`.example` placeholders and the IPs are documentation
ranges (`203.0.113.0/24`) plus a few real-world-plausible public addresses. No
real victim data, nothing that will get anyone in trouble on a shared screen.

The point of the set is coverage of every branch of the confidence model, so
that "high / medium / low" is demonstrated rather than asserted.

| File | Exercises | Expected confidence | Expected band |
|---|---|---|---|
| `01_high_confidence_direct.eml` | Clean SPF+DKIM+DMARC pass, direct send from a residential/small-business ISP IP, observed by Google | **high** | low |
| `02_spoofed_paypal_hosted.eml` | Lookalike domain, Reply-To mismatch, SPF/DMARC fail, DigitalOcean hosted IP, private-IP hop that must be excluded | **medium** | critical |
| `03_vpn_exit_low_confidence.eml` | BEC/CEO-fraud wording, VPN/bulletproof-host exit IP, softfail SPF, no DKIM | **low** | critical |
| `04_webmail_no_origin_ip.eml` | Gmail-sent: auth all passes but the origin IP is Google's, not the sender's. Auth pass must NOT produce high confidence | **low** | medium |
| `05_broken_chain_backward_timestamps.eml` | Backward timestamps, chain gap (`by_host` != next `from_host`), loopback hop | **low** | high |
| `06_minimal_no_headers.eml` | Zero Received headers → the no-origin path | **low** | medium |

## Why 04 matters more than it looks

It is the case that catches naive implementations. Every authentication check
passes, so a scoring engine that keys off auth alone calls it clean — but the
only IP in the headers is Google's outbound relay, so we know nothing about the
sender's actual location. Correct behaviour: `infrastructure_type =
webmail_provider`, confidence forced to **low**, and the origin statement makes
clear we are looking at provider infrastructure. If your build reports "high"
confidence here, the confidence model is wrong.

## Adding real samples

If you add genuine phishing you received: strip your own address and any
personal data first, and keep the `Received` chain intact — that is the
evidence. Name files `NN_short_description.eml` and add a row above.
