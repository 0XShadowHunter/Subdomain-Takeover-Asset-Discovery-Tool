"""Tests for the CLI — pipeline mocked, no network, output written to tmp_path."""

import json

from src.cli import main
from src.models import Phase1Result


def test_cli_rejects_ip_target():
    assert main(["discover", "--domain", "1.2.3.4"]) == 2


def test_cli_rejects_nonsense_target():
    assert main(["discover", "--domain", "not a domain"]) == 2


def test_cli_discover_writes_contract_file(tmp_path, monkeypatch):
    seen = {}

    async def fake_enum(domain, settings, skip_brute=False, wordlist=None):
        seen["domain"] = domain
        seen["skip_brute"] = skip_brute
        return Phase1Result(
            target=domain, generated_at="now", sources_used=["crtsh"], subdomains=[]
        )

    monkeypatch.setattr("src.cli.enumerate_subdomains", fake_enum)
    out = tmp_path / "phase1.json"
    rc = main(["discover", "--domain", "Example.COM", "--skip-brute", "--output", str(out)])
    assert rc == 0
    assert seen["domain"] == "example.com"  # normalized
    assert seen["skip_brute"] is True
    raw = json.loads(out.read_text(encoding="utf-8"))
    assert raw["target"] == "example.com"
    assert raw["subdomains"] == []


def test_cli_passes_threads_and_resolvers_override(tmp_path, monkeypatch):
    seen = {}

    async def fake_enum(domain, settings, skip_brute=False, wordlist=None):
        seen["concurrency"] = settings["general"]["concurrency"]
        seen["resolvers"] = settings["general"]["resolvers"]
        return Phase1Result(target=domain, generated_at="now", sources_used=[], subdomains=[])

    monkeypatch.setattr("src.cli.enumerate_subdomains", fake_enum)
    out = tmp_path / "phase1.json"
    rc = main(
        [
            "discover",
            "--domain",
            "example.com",
            "--threads",
            "25",
            "--resolvers",
            "9.9.9.9",
            "149.112.112.112",
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    assert seen["concurrency"] == 25
    assert seen["resolvers"] == ["9.9.9.9", "149.112.112.112"]


def test_cli_resolve_writes_contract(tmp_path, monkeypatch):
    from src.models import Phase2Result, ResolvedRecord

    seen = {}

    async def fake_resolve(
        input_path, settings, threads=None, resolvers=None, rate=None, progress_callback=None
    ):
        seen["input"] = str(input_path)
        seen["threads"] = threads
        seen["rate"] = rate
        return Phase2Result(
            target="example.com",
            generated_at="now",
            records=[
                ResolvedRecord(
                    name="www.example.com", resolved=True, dns_status="NOERROR", a=["1.2.3.4"]
                )
            ],
        )

    monkeypatch.setattr("src.cli.resolve_from_phase1", fake_resolve)
    inp = tmp_path / "phase1.json"
    inp.write_text(
        json.dumps(
            {"target": "example.com", "generated_at": "t", "sources_used": [], "subdomains": []}
        ),
        encoding="utf-8",
    )
    out = tmp_path / "phase2.json"
    rc = main(
        ["resolve", "--input", str(inp), "--threads", "7", "--rate", "50", "--output", str(out)]
    )
    assert rc == 0
    assert seen["threads"] == 7
    assert seen["rate"] == 50.0
    raw = json.loads(out.read_text(encoding="utf-8"))
    assert raw["records"][0]["name"] == "www.example.com"
    assert raw["records"][0]["http"] is not None


def test_cli_resolve_missing_input(tmp_path):
    assert main(["resolve", "--input", str(tmp_path / "missing.json")]) == 2


def _phase2_input(tmp_path):
    inp = tmp_path / "phase2.json"
    inp.write_text(
        json.dumps(
            {
                "target": "example.com",
                "generated_at": "t",
                "records": [
                    {
                        "name": "blog.example.com",
                        "resolved": True,
                        "dns_status": "NOERROR",
                        "a": ["185.199.108.153"],
                        "aaaa": [],
                        "cname_chain": ["blog.example.com", "blog.example.github.io"],
                        "ns": [],
                        "http": {
                            "url": "https://blog.example.com",
                            "status": 404,
                            "title": None,
                            "body_snippet": "There isn't a GitHub Pages site here.",
                            "headers": {},
                            "redirects": [],
                            "error": None,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return inp


def test_cli_detect_writes_findings(tmp_path):
    inp = _phase2_input(tmp_path)
    out = tmp_path / "phase3.json"
    rc = main(["detect", "--input", str(inp), "--no-recheck", "--output", str(out)])
    assert rc == 0
    raw = json.loads(out.read_text(encoding="utf-8"))
    assert set(raw) == {"target", "generated_at", "findings", "summary"}
    assert raw["summary"]["total_scanned"] == 1
    assert raw["findings"][0]["type"] == "CNAME_FINGERPRINT"
    assert raw["findings"][0]["service"] == "GitHub Pages"
    assert raw["findings"][0]["remediation"]


def test_cli_detect_missing_input(tmp_path):
    assert main(["detect", "--input", str(tmp_path / "missing.json")]) == 2


def test_scan_defaults_to_per_domain_folder(tmp_path, monkeypatch):
    """No --output-dir → everything lands in data/output/<domain>/ (SQLite too)."""
    from src.models import Phase1Result, Phase2Result, Phase3Result

    async def fake_enum(domain, settings, skip_brute=False, wordlist=None):
        return Phase1Result(target=domain, generated_at="t", sources_used=[], subdomains=[])

    async def fake_resolve(
        input_path, settings, threads=None, resolvers=None, rate=None, progress_callback=None
    ):
        return Phase2Result(target="example.com", generated_at="t", records=[])

    def fake_detect(input_path, settings, fingerprints_path=None, recheck_dns=None):
        return Phase3Result(
            target="example.com",
            generated_at="t",
            findings=[],
            summary={"total_scanned": 0, "vulnerable": 0,
                     "by_confidence": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}},
        )

    monkeypatch.setattr("src.cli.enumerate_subdomains", fake_enum)
    monkeypatch.setattr("src.cli.resolve_from_phase1", fake_resolve)
    monkeypatch.setattr("src.cli.run_detection", fake_detect)
    monkeypatch.setattr("src.cli.domain_output_dir", lambda d: tmp_path / d)

    rc = main(["scan", "--domain", "Example.COM"])  # no --output-dir on purpose
    assert rc == 0
    folder = tmp_path / "example.com"  # dedicated per-domain folder
    assert (folder / "phase1_subdomains.json").is_file()
    assert (folder / "phase2_resolved.json").is_file()
    assert (folder / "phase3_findings.json").is_file()
    assert (folder / "subtake.db").is_file()
    assert not (tmp_path / "phase1_subdomains.json").exists()  # nothing flat


def test_explicit_output_dir_still_wins(tmp_path, monkeypatch):
    from src.models import Phase1Result, Phase2Result, Phase3Result

    async def fake_enum(domain, settings, skip_brute=False, wordlist=None):
        return Phase1Result(target=domain, generated_at="t", sources_used=[], subdomains=[])

    async def fake_resolve(
        input_path, settings, threads=None, resolvers=None, rate=None, progress_callback=None
    ):
        return Phase2Result(target="example.com", generated_at="t", records=[])

    def fake_detect(input_path, settings, fingerprints_path=None, recheck_dns=None):
        return Phase3Result(
            target="example.com", generated_at="t", findings=[],
            summary={"total_scanned": 0, "vulnerable": 0,
                     "by_confidence": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}},
        )

    monkeypatch.setattr("src.cli.enumerate_subdomains", fake_enum)
    monkeypatch.setattr("src.cli.resolve_from_phase1", fake_resolve)
    monkeypatch.setattr("src.cli.run_detection", fake_detect)

    custom = tmp_path / "my-results"
    rc = main(["scan", "--domain", "example.com", "--output-dir", str(custom)])
    assert rc == 0
    assert (custom / "subtake.db").is_file()


def _seed_db(db_path, target="example.com"):
    from src.models import Phase1Result, SubdomainEntry
    from src.storage.sqlite_store import ScanDatabase

    db = ScanDatabase(db_path)
    scan_id = db.new_scan(target)
    entry = SubdomainEntry(f"www.{target}")
    entry.add_source("crtsh")
    db.save_phase1(
        scan_id,
        Phase1Result(target=target, generated_at="t", sources_used=["crtsh"],
                     subdomains=[entry]),
    )
    db.close()
    return scan_id


def test_clean_deletes_records_with_yes(tmp_path):
    import sqlite3

    db_path = tmp_path / "subtake.db"
    _seed_db(db_path)
    rc = main(["clean", "--domain", "example.com", "--yes", "--db", str(db_path)])
    assert rc == 0
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0] == 0
    finally:
        conn.close()


def test_clean_missing_db_is_noop(tmp_path):
    rc = main(["clean", "--domain", "example.com", "--yes", "--db", str(tmp_path / "nope.db")])
    assert rc == 0


def test_clean_invalid_domain(tmp_path):
    assert main(["clean", "--domain", "1.2.3.4", "--yes"]) == 2


def test_clean_non_interactive_refuses_without_yes(tmp_path, monkeypatch):
    import sqlite3

    db_path = tmp_path / "subtake.db"
    _seed_db(db_path)
    monkeypatch.setattr("sys.stdin", type("FakeStdin", (), {"isatty": lambda self: False})())
    rc = main(["clean", "--domain", "example.com", "--db", str(db_path)])
    assert rc == 1  # refused
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1  # untouched
    finally:
        conn.close()


def test_clean_purge_files_removes_folder(tmp_path, monkeypatch):
    db_path = tmp_path / "example.com" / "subtake.db"
    _seed_db(db_path)
    (tmp_path / "example.com" / "report.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setattr("src.cli.domain_output_dir", lambda d, source="cli": tmp_path / source / d)
    rc = main(
        ["clean", "--domain", "example.com", "--yes", "--purge-files", "--db", str(db_path)]
    )
    assert rc == 0
    assert not (tmp_path / "cli" / "example.com").exists()  # whole folder gone


def test_scan_routes_to_cli_results_area(tmp_path, monkeypatch):
    """scan must save under data/results/cli/<domain>/ — the CLI area."""
    from src.models import Phase1Result, Phase2Result, Phase3Result

    seen = {}

    async def fake_enum(domain, settings, skip_brute=False, wordlist=None):
        return Phase1Result(target=domain, generated_at="t", sources_used=[], subdomains=[])

    async def fake_resolve(
        input_path, settings, threads=None, resolvers=None, rate=None, progress_callback=None
    ):
        return Phase2Result(target="example.com", generated_at="t", records=[])

    def fake_detect(input_path, settings, fingerprints_path=None, recheck_dns=None):
        return Phase3Result(
            target="example.com", generated_at="t", findings=[],
            summary={"total_scanned": 0, "vulnerable": 0,
                     "by_confidence": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}},
        )

    def fake_domain_dir(domain, source="cli"):
        seen["domain"] = domain
        seen["source"] = source
        return tmp_path / source / domain

    monkeypatch.setattr("src.cli.enumerate_subdomains", fake_enum)
    monkeypatch.setattr("src.cli.resolve_from_phase1", fake_resolve)
    monkeypatch.setattr("src.cli.run_detection", fake_detect)
    monkeypatch.setattr("src.cli.domain_output_dir", fake_domain_dir)

    rc = main(["scan", "--domain", "example.com"])
    assert rc == 0
    assert seen == {"domain": "example.com", "source": "cli"}
    assert (tmp_path / "cli" / "example.com" / "subtake.db").is_file()


def test_clean_can_target_the_gui_area(tmp_path, monkeypatch):
    db_path = tmp_path / "gui" / "example.com" / "subtake.db"
    _seed_db(db_path)
    monkeypatch.setattr(
        "src.cli.domain_output_dir", lambda d, source="cli": tmp_path / source / d
    )
    rc = main(["clean", "--domain", "example.com", "--source", "gui", "--yes", "--purge-files"])
    assert rc == 0
    assert not (tmp_path / "gui" / "example.com").exists()  # gui area cleared
    assert not (tmp_path / "cli" / "example.com").exists()  # cli area untouched


def test_cli_detect_clean_data_no_findings(tmp_path):
    inp = tmp_path / "phase2.json"
    inp.write_text(
        json.dumps(
            {
                "target": "example.com",
                "generated_at": "t",
                "records": [
                    {
                        "name": "www.example.com",
                        "resolved": True,
                        "dns_status": "NOERROR",
                        "a": ["93.184.216.34"],
                        "aaaa": [],
                        "cname_chain": ["www.example.com"],
                        "ns": [],
                        "http": {"url": "https://www.example.com", "status": 200,
                                 "title": "Example Domain", "body_snippet": "hello",
                                 "headers": {}, "redirects": [], "error": None},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "phase3.json"
    rc = main(["detect", "--input", str(inp), "--no-recheck", "--output", str(out)])
    assert rc == 0
    raw = json.loads(out.read_text(encoding="utf-8"))
    assert raw["findings"] == []
    assert raw["summary"]["vulnerable"] == 0
