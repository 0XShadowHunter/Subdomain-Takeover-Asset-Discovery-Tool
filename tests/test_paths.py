"""Tests for the results folder layout: main folder + cli/gui separation."""

from src.utils.paths import RESULTS_DIR, _find_project_root, domain_output_dir


def test_find_project_root_detects_checkout(tmp_path):
    """A folder with config/settings.yaml is recognized as the project root."""
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.yaml").write_text("general: {}", encoding="utf-8")
    exe_dir = tmp_path / "dist"
    exe_dir.mkdir()
    assert _find_project_root(exe_dir) == tmp_path


def test_find_project_root_returns_none_without_marker(tmp_path):
    exe_dir = tmp_path / "anywhere"
    exe_dir.mkdir()
    assert _find_project_root(exe_dir) is None


def test_cli_is_the_default_results_area():
    assert domain_output_dir("Example.COM") == RESULTS_DIR / "cli" / "example.com"
    assert domain_output_dir("Example.COM", "cli") == RESULTS_DIR / "cli" / "example.com"


def test_gui_area_is_separate_from_cli():
    assert domain_output_dir("example.com", "gui") == RESULTS_DIR / "gui" / "example.com"
    assert domain_output_dir("example.com", "GUI") == RESULTS_DIR / "gui" / "example.com"
    # the two areas must never collide
    assert domain_output_dir("example.com", "cli") != domain_output_dir("example.com", "gui")


def test_unknown_source_falls_back_to_cli():
    assert domain_output_dir("example.com", "bogus") == RESULTS_DIR / "cli" / "example.com"


def test_domain_output_dir_sanitizes_unsafe_characters():
    path = domain_output_dir("we!rd_domain.example.com")
    assert "!" not in path.name and "_" not in path.name
    assert path == RESULTS_DIR / "cli" / "we-rd-domain.example.com"


def test_domain_output_dir_handles_dots():
    assert (
        domain_output_dir("sub.blog.example.co.uk", "gui")
        == RESULTS_DIR / "gui" / "sub.blog.example.co.uk"
    )
