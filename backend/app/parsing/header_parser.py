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

IS_STUB = True   # <-- M1: set to False when parse_headers is really implemented

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
    return _empty_mailbox()


def parse_mailbox_list(header_value: str | None) -> list[dict]:
    """Same as parse_mailbox but for To/Cc.  TODO(M1): email.utils.getaddresses."""
    return []


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
    return {
        "from": _empty_mailbox(),
        "reply_to": None,
        "return_path": None,
        "to": [],
        "cc": [],
        "subject": None,
        "message_id": None,
        "message_id_domain": None,
        "date": None,
        "date_raw": None,
        "x_mailer": None,
        "raw_header_count": 0,
        "missing_headers": [],
        "body_preview": "",
        "anomalies": [],
    }
