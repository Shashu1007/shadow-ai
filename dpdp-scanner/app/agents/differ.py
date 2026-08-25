"""
Diff Agent
==========
Pure code, no LLM. Compares the current scan's classified findings against the
previous stored snapshot for the same client, keyed on detail_hash.

Outputs new / changed / removed lists, and applies the spec's severity rules:

  HIGH   — new third-party script/tracker, new financial/health/children's data
           field, consent banner missing or broken
  MEDIUM — new non-sensitive form field, privacy policy page changed
  LOW    — cosmetic changes with no data implication (log only, no alert)

"Changed" = same detail_hash but a field that shouldn't move (data_category or
dpdp_relevance) differs, or (for privacy_policy) the content hash differs.
"""
from __future__ import annotations

from app.models import ClassifiedFinding, DiffEntry, DiffResult

SENSITIVE_CATEGORIES = {"financial", "health", "children"}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def _severity_for_new(f: dict) -> tuple[str, str]:
    ftype = f.get("type")
    category = f.get("data_category")
    relevance = f.get("dpdp_relevance")
    confidence = f.get("confidence", "medium")

    if ftype == "third_party_script":
        return "high", "New third-party script/tracker detected — data processor/transfer risk."
    if ftype == "cookie":
        return "high", "New third-party cookie set without prior consent coverage."
    if category in SENSITIVE_CATEGORIES:
        return "high", f"New form field collecting {category} data."
    if ftype == "consent_banner" and "no consent banner" in f.get("detail", "").lower():
        return "high", "Consent banner missing or broken on this page."
    if ftype == "form_field":
        return "medium", "New non-sensitive form field."
    if ftype == "privacy_policy":
        return "medium", "New privacy policy page detected."
    if confidence == "low":
        return "low", "Low-confidence finding — logged only, routed to review queue."
    return "low", "Cosmetic or low-impact change."


def _severity_for_changed(prev: dict, curr: dict) -> tuple[str, str]:
    ftype = curr.get("type")
    if ftype == "privacy_policy" and prev.get("detail") != curr.get("detail"):
        return "medium", "Privacy policy content changed since last scan."
    if ftype == "consent_banner":
        prev_present = "no consent banner" not in prev.get("detail", "").lower()
        curr_present = "no consent banner" not in curr.get("detail", "").lower()
        if prev_present and not curr_present:
            return "high", "Consent banner was present, now missing."
        return "medium", "Consent banner configuration changed."
    if curr.get("data_category") in SENSITIVE_CATEGORIES and prev.get("data_category") != curr.get("data_category"):
        return "high", "Field reclassified into a sensitive data category."
    return "low", "Minor metadata change, no new data-protection implication."


def _severity_for_removed(f: dict) -> tuple[str, str]:
    ftype = f.get("type")
    if ftype == "consent_banner" and "no consent banner" not in f.get("detail", "").lower():
        return "high", "Consent banner that was present has been removed."
    if ftype == "privacy_policy":
        return "high", "Privacy policy page is no longer reachable."
    return "low", "Finding no longer present — logged, no alert."


def diff_findings(
    client_id: int,
    prev_scan_id: int | None,
    curr_scan_id: int,
    prev_findings: list[dict],
    curr_findings: list[dict],
) -> DiffResult:
    """
    prev_findings / curr_findings: lists of dicts as stored in the `findings` table
    (each must have at least: detail_hash, type, detail, data_category, dpdp_relevance, confidence).
    """
    prev_by_hash = {f["detail_hash"]: f for f in prev_findings}
    curr_by_hash = {f["detail_hash"]: f for f in curr_findings}

    new_entries: list[DiffEntry] = []
    changed_entries: list[DiffEntry] = []
    removed_entries: list[DiffEntry] = []

    for h, curr in curr_by_hash.items():
        if h not in prev_by_hash:
            sev, reason = _severity_for_new(curr)
            new_entries.append(DiffEntry(finding=curr, severity=sev, reason=reason))
        else:
            prev = prev_by_hash[h]
            if prev.get("data_category") != curr.get("data_category") or prev.get("detail") != curr.get("detail"):
                sev, reason = _severity_for_changed(prev, curr)
                # only record as "changed" if there's an actual meaningful diff
                if sev != "low" or prev.get("detail") != curr.get("detail"):
                    changed_entries.append(DiffEntry(finding=curr, severity=sev, reason=reason))

    for h, prev in prev_by_hash.items():
        if h not in curr_by_hash:
            sev, reason = _severity_for_removed(prev)
            removed_entries.append(DiffEntry(finding=prev, severity=sev, reason=reason))

    max_sev = "low"
    for entry in new_entries + changed_entries + removed_entries:
        if SEVERITY_ORDER[entry.severity] > SEVERITY_ORDER[max_sev]:
            max_sev = entry.severity

    return DiffResult(
        client_id=client_id,
        prev_scan_id=prev_scan_id,
        curr_scan_id=curr_scan_id,
        new=new_entries,
        changed=changed_entries,
        removed=removed_entries,
        severity=max_sev,
    )
