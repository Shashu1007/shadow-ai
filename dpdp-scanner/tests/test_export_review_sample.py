"""
Tests for scripts/export_review_sample.py — the stratified-sampling logic
(pure function, no DB) plus an end-to-end CLI smoke test against a scratch
DB with seeded findings across multiple types/confidences.
"""
import csv
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import export_review_sample as ers  # noqa: E402


def _fake_findings():
    rows = []
    fid = 1
    for ftype, confidences in [
        ("form_field", ["high"] * 30 + ["low"] * 5),
        ("cookie", ["medium"] * 8),
        ("third_party_script", ["high"] * 3),
        ("consent_banner", ["low"] * 1),
    ]:
        for conf in confidences:
            rows.append({
                "finding_id": fid, "page_url": "https://x.example/p", "type": ftype,
                "detail": f"detail-{fid}", "data_category": "contact", "dpdp_relevance": "notice",
                "confidence": conf, "scan_id": 1, "scanned_at": "2026-01-01", "client_domain": "x.example",
            })
            fid += 1
    return rows


def test_sample_respects_requested_count():
    rows = _fake_findings()
    sample = ers.stratified_sample(rows, n=15, rng=random.Random(1))
    assert len(sample) == 15


def test_sample_never_exceeds_available_candidates():
    rows = _fake_findings()[:5]
    sample = ers.stratified_sample(rows, n=50, rng=random.Random(1))
    assert len(sample) == 5


def test_sample_covers_rare_types_not_just_the_dominant_one():
    # form_field has 35 rows, consent_banner has just 1 — a plain random
    # sample of 8 could easily miss consent_banner entirely; the
    # stratified round-robin must not.
    rows = _fake_findings()
    sample = ers.stratified_sample(rows, n=8, rng=random.Random(7))
    types_in_sample = {r["type"] for r in sample}
    assert "consent_banner" in types_in_sample
    assert "third_party_script" in types_in_sample


def test_sample_is_deterministic_given_same_seed():
    rows = _fake_findings()
    sample1 = ers.stratified_sample(rows, n=10, rng=random.Random(42))
    sample2 = ers.stratified_sample(rows, n=10, rng=random.Random(42))
    ids1 = [r["finding_id"] for r in sample1]
    ids2 = [r["finding_id"] for r in sample2]
    assert ids1 == ids2


def test_sample_never_duplicates_a_finding():
    rows = _fake_findings()
    sample = ers.stratified_sample(rows, n=20, rng=random.Random(3))
    ids = [r["finding_id"] for r in sample]
    assert len(ids) == len(set(ids))


def test_cli_end_to_end_against_seeded_db():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(db_path)
    fd2, csv_path = tempfile.mkstemp(suffix=".csv")
    os.close(fd2)

    env = dict(os.environ)
    repo_root = Path(__file__).resolve().parent.parent

    seed_script = f"""
import sys
sys.path.insert(0, {str(repo_root)!r})
from pathlib import Path
import app.db.conn as conn_mod
conn_mod.DB_PATH = Path({db_path!r})
from app.db.conn import init_db
from app import repository as repo
init_db()
cid = repo.create_client("seed.example")
scan_id = repo.create_scan(cid, page_count=1, raw_findings={{}})
findings = []
for i in range(20):
    findings.append({{
        "url": "https://seed.example/p", "type": "form_field" if i % 3 else "cookie",
        "detail": f"detail-{{i}}", "detail_hash": f"h{{i}}", "data_category": "contact",
        "dpdp_relevance": "notice", "confidence": "high" if i % 2 else "low",
    }})
repo.bulk_insert_findings(scan_id, findings)
"""
    subprocess.run([sys.executable, "-c", seed_script], check=True, env=env)

    run_script = f"""
import sys
sys.path.insert(0, {str(repo_root)!r})
from pathlib import Path
import app.db.conn as conn_mod
conn_mod.DB_PATH = Path({db_path!r})
sys.argv = ["export_review_sample.py", "--n", "10", "--out", {csv_path!r}, "--seed", "1"]
sys.path.insert(0, {str(repo_root / "scripts")!r})
import export_review_sample as ers
raise SystemExit(ers.main())
"""
    result = subprocess.run([sys.executable, "-c", run_script], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Wrote 10 of 20" in result.stdout

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames == ers.CSV_COLUMNS
    assert len(rows) == 10
    for r in rows:
        assert r["reviewer_verdict"] == ""
        assert r["corrected_category"] == ""
        assert r["client_domain"] == "seed.example"

    os.unlink(db_path)
    os.unlink(csv_path)


def test_cli_handles_empty_db_gracefully():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(db_path)
    env = dict(os.environ)
    repo_root = Path(__file__).resolve().parent.parent

    run_script = f"""
import sys
sys.path.insert(0, {str(repo_root)!r})
from pathlib import Path
import app.db.conn as conn_mod
conn_mod.DB_PATH = Path({db_path!r})
sys.argv = ["export_review_sample.py"]
sys.path.insert(0, {str(repo_root / "scripts")!r})
import export_review_sample as ers
raise SystemExit(ers.main())
"""
    result = subprocess.run([sys.executable, "-c", run_script], capture_output=True, text=True, env=env)
    assert result.returncode == 1
    assert "nothing to sample" in result.stdout
    if os.path.exists(db_path):
        os.unlink(db_path)


if __name__ == "__main__":
    import inspect
    mod = sys.modules[__name__]
    tests = [f for name, f in inspect.getmembers(mod) if name.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"FAIL {t.__name__}: {e!r}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
