"""Header parsing.   OWNER: M1.

You own this file completely.  Nobody else edits it.
Produces  ->  response["headers"]   (see API_CONTRACT.md section 3)

Rules for this file:
  * stdlib only (`email`, `re`, `hashlib`, `datetime`).  No pip installs needed.
  * return PLAIN DICTS, not Pydantic models.  M6's main.py validates them.
  * you DETECT structural facts.  You do NOT assign risk points or confidence -
    that's M3.  Emit an anomaly code and let M3 decide what it's worth.
"""
from __future__ import annotations
import email
from email import policy
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from datetime import timezone
import re
IS_STUB = False   # <-- M1: set to False when parse_headers is really implemented

BODY_PREVIEW_CHARS = 500

# Headers we explicitly check for and report as missing.
EXPECTED_HEADERS = ["Message-ID", "Date", "DKIM-Signature", "Received", "Return-Path"]


def _empty_mailbox() -> dict:
    return {"display_name": None, "address": None, "domain": None}


def parse_mailbox(header_value: str | None) -> dict:
    """Parse one address header into {display_name, address, domain}.

    TODO(M1): use email.utils.parseaddr, then split the domain on the LAST '@'
    (addresses like "a@b"@evil.tld exist and are used deliberately to fool
    naive parsers).  Lowercase the domain.  Return _empty_mailbox() on failure -
    never raise.
    """
    if not header_value or not str(header_value).strip():
        return _empty_mailbox()
    try:
        display_name, address = parseaddr(str(header_value))
        if not address or "@" not in address:
            return _empty_mailbox()
        # Split on the LAST '@' to handle legal quoted local-parts like "a@b"@evil.tld[cite: 1]
        domain = address.rsplit("@", 1)[-1].strip().rstrip(">").lower()
        if not domain:
            return _empty_mailbox()
        return {
            "display_name": display_name.strip() if display_name and display_name.strip() else None,
            "address": address.strip().lower(),
            "domain": domain,
        }
    except Exception:
        return _empty_mailbox()


def parse_mailbox_list(header_value: str | None) -> list[dict]:
    """Same as parse_mailbox but for To/Cc.  TODO(M1): email.utils.getaddresses."""
    # return []
    if not header_value or not str(header_value).strip():
        return []
    results = []
    try:
        raw_addrs = getaddresses([str(header_value)])
        for display_name, address in raw_addrs:
            if address and "@" in address:
                domain = address.rsplit("@", 1)[-1].strip().rstrip(">").lower()
                if domain:
                    results.append({
                        "display_name": display_name.strip() if display_name and display_name.strip() else None,
                        "address": address.strip().lower(),
                        "domain": domain,
                    })
    except Exception:
        pass
    return results


def extract_body_text(raw_email: str) -> str:
    """Return the plaintext body, HTML stripped.

    TODO(M1):
      * email.message_from_string(raw_email) -> walk() the parts
      * prefer text/plain; fall back to text/html with tags stripped
      * decode with charset from the part, errors="replace" (never raise on
        weird encodings - phishing mail is full of them)
      * return "" if there is no body
    M3 reads this for the URGENCY_KEYWORDS risk signal, so returning "" just
    means that one signal never fires.  Safe to leave until last.
    """
    # return ""
    if not raw_email:
        return ""
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        plain_parts = []
        html_parts = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if "attachment" in disp:
                    continue

                payload = part.get_payload(decode=True)
                if not payload:
                    continue

                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except Exception:
                    decoded = payload.decode("utf-8", errors="replace")

                if content_type == "text/plain":
                    plain_parts.append(decoded)
                elif content_type == "text/html":
                    html_parts.append(decoded)
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except Exception:
                    decoded = payload.decode("utf-8", errors="replace")

                if msg.get_content_type() == "text/html":
                    html_parts.append(decoded)
                else:
                    plain_parts.append(decoded)

        if plain_parts:
            text = "\n".join(plain_parts)
        elif html_parts:
            raw_html = "\n".join(html_parts)
            text = re.sub(r"<[^>]+>", " ", raw_html)
        else:
            text = ""

        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n\n", text)
        return text.strip()
    except Exception:
        return ""


def parse_headers(raw_email: str) -> dict:
    """MAIN ENTRY POINT for M1.  -> response["headers"]

    TODO(M1) implementation order:
      1. msg = email.message_from_string(raw_email)   (policy=email.policy.default
         gives you nicer decoded headers - worth using)
      2. from_/reply_to/return_path via parse_mailbox; to/cc via parse_mailbox_list
      3. subject: decode RFC2047 (=?utf-8?B?...?=) with
         email.header.make_header(email.header.decode_header(v))
      4. date -> ISO8601 UTC 'Z' string via email.utils.parsedate_to_datetime,
         then .astimezone(timezone.utc).  Keep the original in date_raw.
      5. message_id_domain: text inside <...> after the last '@', lowercased
      6. missing_headers: EXPECTED_HEADERS not present in msg
      7. body_preview = extract_body_text(raw)[:BODY_PREVIEW_CHARS]
      8. anomalies (codes are FROZEN - see API_CONTRACT.md section 5):
           REPLYTO_DOMAIN_MISMATCH     reply_to.domain != from.domain      medium
           RETURNPATH_DOMAIN_MISMATCH  return_path.domain != from.domain    medium
           MESSAGEID_DOMAIN_MISMATCH   message_id_domain != from.domain     low
           MISSING_MESSAGE_ID / MISSING_DATE                                low
           DISPLAY_NAME_LOOKALIKE      display_name contains a domain-like
                                       token that differs from from.domain  high

    Return the dict with EVERY key present, even when the value is None/[].
    The frontend indexes into these keys unconditionally.
    """
    # return {
    #     "from": _empty_mailbox(),
    #     "reply_to": None,
    #     "return_path": None,
    #     "to": [],
    #     "cc": [],
    #     "subject": None,
    #     "message_id": None,
    #     "message_id_domain": None,
    #     "date": None,
    #     "date_raw": None,
    #     "x_mailer": None,
    #     "raw_header_count": 0,
    #     "missing_headers": [],
    #     "body_preview": "",
    #     "anomalies": [],
    # }
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
    except Exception:
        msg = email.message_from_string("", policy=policy.default)

    from_parsed = parse_mailbox(msg.get("From"))
    reply_to_parsed = parse_mailbox(msg.get("Reply-To")) if msg.get("Reply-To") else None
    return_path_parsed = parse_mailbox(msg.get("Return-Path")) if msg.get("Return-Path") else None

    to_headers = msg.get_all("To") or []
    to_list = []
    for h in to_headers:
        to_list.extend(parse_mailbox_list(h))

    cc_headers = msg.get_all("Cc") or []
    cc_list = []
    for h in cc_headers:
        cc_list.extend(parse_mailbox_list(h))

    subject_raw = msg.get("Subject")
    subject = str(make_header(decode_header(str(subject_raw)))) if subject_raw is not None else None

    message_id = msg.get("Message-ID")
    message_id_str = str(message_id) if message_id is not None else None
    message_id_domain = None
    if message_id_str:
        clean_id = message_id_str.strip().strip("<>").strip()
        if "@" in clean_id:
            message_id_domain = clean_id.rsplit("@", 1)[-1].strip().lower()

    date_raw = msg.get("Date")
    date_raw_str = str(date_raw) if date_raw is not None else None
    date_iso = None
    if date_raw_str:
        try:
            dt = parsedate_to_datetime(date_raw_str)
            date_iso = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            date_iso = None

    x_mailer = msg.get("X-Mailer")
    x_mailer_str = str(x_mailer) if x_mailer is not None else None

    missing_headers = [h for h in EXPECTED_HEADERS if h not in msg]

    body_text = extract_body_text(raw_email)
    body_preview = body_text[:BODY_PREVIEW_CHARS]

    anomalies = []

    # Emit structural anomalies without scoring points[cite: 1, 2]
    if reply_to_parsed and from_parsed["domain"] and reply_to_parsed["domain"]:
        if reply_to_parsed["domain"] != from_parsed["domain"]:
            anomalies.append({
                "code": "REPLYTO_DOMAIN_MISMATCH",
                "severity": "medium",
                "detail": f"Reply-To {reply_to_parsed['domain']} != From {from_parsed['domain']}",
            })

    if return_path_parsed and from_parsed["domain"] and return_path_parsed["domain"]:
        if return_path_parsed["domain"] != from_parsed["domain"]:
            anomalies.append({
                "code": "RETURNPATH_DOMAIN_MISMATCH",
                "severity": "medium",
                "detail": f"Return-Path {return_path_parsed['domain']} != From {from_parsed['domain']}",
            })

    if message_id_domain and from_parsed["domain"]:
        if message_id_domain != from_parsed["domain"]:
            anomalies.append({
                "code": "MESSAGEID_DOMAIN_MISMATCH",
                "severity": "low",
                "detail": f"Message-ID domain {message_id_domain} != From {from_parsed['domain']}",
            })

    if not message_id_str:
        anomalies.append({
            "code": "MISSING_MESSAGE_ID",
            "severity": "medium",
            "detail": "Message-ID header is missing",
        })

    if not date_raw_str:
        anomalies.append({
            "code": "MISSING_DATE",
            "severity": "low",
            "detail": "Date header is missing",
        })

    if from_parsed["display_name"] and from_parsed["domain"]:
        disp_name = from_parsed["display_name"].lower()
        domain_tokens = re.findall(r"\b[a-z0-9-]+\.[a-z]{2,}\b", disp_name)
        for token in domain_tokens:
            if token != from_parsed["domain"]:
                anomalies.append({
                    "code": "DISPLAY_NAME_LOOKALIKE",
                    "severity": "high",
                    "detail": f"Display name contains domain-like string '{token}' differing from From domain '{from_parsed['domain']}'",
                })
                break

    return {
        "from": from_parsed,
        "reply_to": reply_to_parsed,
        "return_path": return_path_parsed,
        "to": to_list,
        "cc": cc_list,
        "subject": subject,
        "message_id": message_id_str,
        "message_id_domain": message_id_domain,
        "date": date_iso,
        "date_raw": date_raw_str,
        "x_mailer": x_mailer_str,
        "raw_header_count": len(msg.keys()),
        "missing_headers": missing_headers,
        "body_preview": body_preview,
        "anomalies": anomalies,
    }
