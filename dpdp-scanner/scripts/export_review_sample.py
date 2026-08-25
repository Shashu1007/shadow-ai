#!/usr/bin/env python3
"""
Exports a stratified sample of real findings to a CSV worksheet for a human,
DPDP-literate reviewer to actually use.

Why this exists: the go/no-go checklist (see the Claude Project doc, or
GO_NO_GO_CHECKLIST.md in this repo) flags, correctly, that no compliance
review of the classifier's output has happened — and that nothing in this
codebase can substitute for one. Code guardrails (low-confidence routing to
review, the compliance-conclusion-language filter) reduce the blast radius
of a wrong classification; they don't validate that app/config.py's field
patterns or app/agents/classifier.py's relevance rules are actually right
under DPDP. That validation needs a human who knows the law, looking at
real findings and saying "yes, this is/isn't a notice obligation" — this
script's ONLY job is to hand that human a well-formed worksheet instead of
them having to dig through the dashboard or query SQLite by hand. It does
not review anything itself, does not grade the classifier, and its output
being empty of red flags means nothing about whether the classifier is
correct.

Sampling strategy: real findings vary enormously in volume by type
(form_field findings usually dwarf consent_banner findings, say), so a
plain random sample tends to be dominated by whatever's most common and
under-represents rarer-but-important categories. This script instead
stratifies by (type, confidence) — round-robining across every combination
that actually occurs in the data — so a 15-row sample is far more likely to
include at least one of each finding type and each confidence tier, not
just 15 near-duplicate contact-form findings.

Usage:
    python3 scripts/export_review_sample.py                        # 15 rows, all clients, data/review_sample.csv
    python3 scripts/export_review_sample.py --n 25 --domain acme.example
    python3 scripts/export_review_sample.py --out /tmp/sample.csv --seed 42   # reproducible for a re-run

The output CSV has blank reviewer_verdict / corrected_category / notes
columns for the reviewer to fill in — nothing in this codebase reads those
columns back; this is a one-way export for a human to work from offline
(or in a spreadsheet), not a review-tracking system.
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.conn import get_connection, init_db  # noqa: E402

CSV_COLUMNS = [
    "client_domain", "scan_id", "scanned_at", "finding_id", "page_url", "type",
    "detail", "data_category", "dpdp_relevance", "confidence",
    "reviewer_verdict", "corrected_category", "notes",
]


def _fetch_candidates(domain: str | None) -> list[dict]:
    conn = get_connection()
    try:
        q = """
            SELECT f.id AS finding_id, f.page_url, f.type, f.detail, f.data_category,
                   f.dpdp_relevance, f.confidence, s.id AS scan_id, s.scanned_at, c.domain AS client_domain
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN clients c ON c.id = s.client_id
            WHERE s.status = 'completed'
        """
        params: list = []
        if domain:
            q += " AND c.domain = ?"
            params.append(domain)
        rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def stratified_sample(candidates: list[dict], n: int, rng: random.Random) -> list[dict]:
    """Round-robins across (type, confidence) buckets, in a randomized
    bucket order each pass, until `n` rows are picked or candidates run
    out. Deterministic given the same `rng` seed."""
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for row in candidates:
        buckets[(row["type"], row["confidence"])].append(row)
    for bucket in buckets.values():
        rng.shuffle(bucket)

    bucket_keys = list(buckets.keys())
    rng.shuffle(bucket_keys)

    sample: list[dict] = []
    while len(sample) < n and any(buckets[k] for k in bucket_keys):
        for k in bucket_keys:
            if len(sample) >= n:
                break
            if buckets[k]:
                sample.append(buckets[k].pop())
    return sample


def write_csv(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "client_domain": row["client_domain"],
                "scan_id": row["scan_id"],
                "scanned_at": row["scanned_at"],
                "finding_id": row["finding_id"],
                "page_url": row["page_url"],
                "type": row["type"],
                "detail": row["detail"],
                "data_category": row["data_category"] or "",
                "dpdp_relevance": row["dpdp_relevance"] or "",
                "confidence": row["confidence"],
                "reviewer_verdict": "",
                "corrected_category": "",
                "notes": "",
            })


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n", type=int, default=15, help="Number of findings to sample (default 15, per the spec's '10-15 real findings' review scope)")
    parser.add_argument("--domain", default=None, help="Restrict to one client's findings (default: across all clients)")
    parser.add_argument("--out", default="data/review_sample.csv", help="Output CSV path")
    parser.add_argument("--seed", type=int, default=None, help="Random seed, for a reproducible sample across re-runs")
    args = parser.parse_args()

    init_db()  # idempotent; ensures the schema exists if run against a brand-new DB
    candidates = _fetch_candidates(args.domain)
    if not candidates:
        print("No completed-scan findings in the database yet — nothing to sample. Run a scan first.")
        return 1

    rng = random.Random(args.seed)
    sample = stratified_sample(candidates, args.n, rng)

    out_path = Path(args.out)
    write_csv(sample, out_path)

    type_conf_counts: dict[tuple, int] = defaultdict(int)
    for row in sample:
        type_conf_counts[(row["type"], row["confidence"])] += 1

    print(f"Wrote {len(sample)} of {len(candidates)} candidate findings to {out_path}")
    print("Spread across (type, confidence):")
    for (t, c), count in sorted(type_conf_counts.items()):
        print(f"  {t:<20} {c:<8} {count}")
    print(
        "\nThis is a worksheet for a human DPDP-literate reviewer, not a "
        "review — see the script's own docstring. Send it to whoever is "
        "doing that review; nothing in this codebase reads the "
        "reviewer_verdict/corrected_category/notes columns back."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
