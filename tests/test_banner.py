"""Tests for the CLI banner and the bundled logo/icon assets."""


from src.cli import print_banner
from src.utils.paths import ICON_FILE, LOGO_FILE


def test_logo_asset_is_bundled_in_the_repo():
    assert LOGO_FILE.is_file(), f"missing brand asset: {LOGO_FILE}"


def test_banner_renders_without_error(capsys):
    print_banner()
    output = capsys.readouterr().out
    # The word-mark is block glyphs; the tagline text is assertable.
    assert "Asset-Discovery Tool" in output
    assert "DISCOVER" in output and "ANALYZE" in output and "SECURE" in output
    assert "█" in output  # block letters rendered


def test_banner_glyph_rows_are_column_aligned():
    from src.cli import _BANNER_GLYPHS

    widths = [len(glyph) for glyph in _BANNER_GLYPHS[0]]
    for row in _BANNER_GLYPHS[1:]:
        assert [len(glyph) for glyph in row] == widths  # every glyph aligned


def test_windows_icon_files_are_generated():
    assert ICON_FILE.is_file(), f"missing square icon: {ICON_FILE}"
    ico = LOGO_FILE.parent / "logo.ico"
    assert ico.is_file(), f"missing windows icon: {ico}"
    # ICONDIR header: reserved=0, type=1 (icon), count=1
    assert ico.read_bytes()[:4] == b"\x00\x00\x01\x00"
