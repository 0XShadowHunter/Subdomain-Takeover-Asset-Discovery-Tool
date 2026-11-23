"""Tests for fingerprint loading/matching — no network, uses the shipped YAML."""

from src.detection.fingerprints import (
    DetectionConfig,
    ServiceFingerprint,
    load_fingerprints,
)


def _default_services():
    services, _config = load_fingerprints()  # the real config/fingerprints.yaml
    return services


def test_default_yaml_loads_expected_services():
    services = _default_services()
    assert len(services) >= 20  # shipped file has 20+ entries
    names = {svc.service for svc in services}
    # Required fixture services (§5 AC) are present:
    assert {"GitHub Pages", "AWS S3", "Heroku", "Azure Web Apps", "Netlify"} <= names
    # And the not-vulnerable documentation entries:
    assert "CloudFront" in names


def test_default_yaml_statuses_and_config():
    services, config = load_fingerprints()
    by_name = {svc.service: svc for svc in services}
    assert by_name["GitHub Pages"].status == "vulnerable"
    assert by_name["Pingdom (public status page)"].status == "edge-case"
    assert by_name["CloudFront"].status == "not-vulnerable"
    assert config.recheck_dns is True
    assert config.enable_dangling_a is False


def test_matches_cname_patterns():
    github = next(s for s in _default_services() if s.service == "GitHub Pages")
    assert github.matches_cname("blog.example.github.io")
    assert github.matches_cname("GITHUB.IO") is False  # pattern needs a subdomain
    assert not github.matches_cname("example.com")
    s3 = next(s for s in _default_services() if s.service == "AWS S3")
    assert s3.matches_cname("assets.s3-website-eu-west-1.amazonaws.com")
    assert not s3.matches_cname("evil.example.com")


def test_match_fingerprint_case_insensitive():
    heroku = next(s for s in _default_services() if s.service == "Heroku")
    assert heroku.match_fingerprint("<h1>NO SUCH APP</h1>") == "No such app"
    assert heroku.match_fingerprint("Welcome to my app") is None
    assert heroku.match_fingerprint("") is None


def test_invalid_entries_are_skipped(tmp_path):
    path = tmp_path / "fp.yaml"
    path.write_text(
        "services:\n"
        "  - service: \"Good\"\n"
        "    status: vulnerable\n"
        "    cname_patterns: [\"*.good.example\"]\n"
        "  - service: \"BadStatus\"\n"
        "    status: totally-wrong\n"
        "  - service: \"\"\n"
        "  - \"just a string\"\n",
        encoding="utf-8",
    )
    services, _config = load_fingerprints(path)
    assert [svc.service for svc in services] == ["Good"]


def test_missing_file_returns_empty(tmp_path):
    services, config = load_fingerprints(tmp_path / "nope.yaml")
    assert services == []
    assert config == DetectionConfig()


def test_fingerprint_dataclass_rejects_missing_name():
    try:
        ServiceFingerprint.from_dict({"status": "vulnerable"})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for missing service name")
