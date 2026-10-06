"""Static hardware-support checks for the LILYGO T-Display-S3 target.

No device needed. Verifies build config, partition math, HAL separation
(core never touches display drivers/GPIOs directly) and the documented pins.
Run: python -m pytest tests/test_hardware.py -q
"""
import configparser
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_env_uses_real_board():
    ini = (ROOT / "platformio.ini").read_text()
    assert "board = lilygo-t-display-s3" in ini
    assert "board = esp32s3box" not in ini
    assert "GFX Library for Arduino@1.3.6" in ini


def test_partitions_fit_16mb():
    total = 0
    end = 0
    rows = []
    for line in (ROOT / "partitions_s3.csv").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, _, off, size = [x.strip() for x in line.split(",")]
        off, size = int(off, 16), int(size, 16)
        assert off >= end, f"{name} overlaps previous partition"
        end = off + size
        total = max(total, end)
        rows.append((name, size))
    assert total == 16 * 1024 * 1024, hex(total)
    sizes = dict(rows)
    assert sizes["app0"] == sizes["app1"] == 0x300000
    assert sizes["spiffs"] >= 9 * 1024 * 1024  # ~2M domains + update headroom


def test_core_has_no_display_dependencies():
    main = (ROOT / "src" / "main.cpp").read_text()
    assert "Arduino_GFX" not in main
    assert "TFT_eSPI" not in main
    assert "Arduino_ESP32PAR8Q" not in main
    assert "tdisplay" not in main  # core talks to hardware.h only
    assert "hardware/hardware.h" in main
    assert "hwBegin()" in main and "hwTick(" in main


def test_hal_structure_and_guards():
    hw = ROOT / "src" / "hardware"
    for f in ("hardware.h", "hardware.cpp", "tdisplay_s3/display.h",
              "tdisplay_s3/display.cpp", "tdisplay_s3/buttons.h",
              "tdisplay_s3/buttons.cpp"):
        assert (hw / f).exists(), f
    assert "LILYGO_T_DISPLAY_S3" in (hw / "hardware.cpp").read_text()
    disp = (hw / "tdisplay_s3" / "display.cpp").read_text()
    for token in ("Arduino_ESP32PAR8Q", "170", "320", "GFX_PWD", "GFX_BL"):
        assert token in disp


def test_display_shows_no_secrets():
    disp = (ROOT / "src" / "hardware" / "tdisplay_s3" / "display.cpp").read_text()
    for token in ("WEB_PASS", "OTA_PASS", "WIFI_PASS", "authenticate", "setPassword"):
        assert token not in disp


def test_backlight_init_before_display():
    disp = (ROOT / "src" / "hardware" / "tdisplay_s3" / "display.cpp").read_text()
    assert "pinMode(GFX_BL, OUTPUT)" in disp
    assert "digitalWrite(GFX_BL, HIGH)" in disp
    # Backlight must come up before the panel init so boot is never dark.
    assert disp.index("digitalWrite(GFX_BL, HIGH)") < disp.index("gfx->begin()")


def test_missing_blocklist_is_none_not_error():
    disp = (ROOT / "src" / "hardware" / "tdisplay_s3" / "display.cpp").read_text()
    assert '"NONE"' in disp
    assert '? "READY" : "ERROR"' not in disp


def test_ci_builds_s3_target():
    yml = (ROOT / ".github" / "workflows" / "build.yml").read_text()
    assert "lilygo-t-display-s3" in yml


def test_snapshot_compiled_only_for_s3_and_throttled():
    main = (ROOT / "src" / "main.cpp").read_text()
    idx = main.find("hwTick(st)")
    assert idx > 0
    guard = main.rfind("#ifdef LILYGO_T_DISPLAY_S3", 0, idx)
    assert guard > 0, "status snapshot must be compiled only for S3"
    assert main.find("#endif", idx) > idx
    window = main[guard:main.find("#endif", idx)]
    assert "1500" in window, "snapshot must be throttled"
