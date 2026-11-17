# Windows setup & troubleshooting

This page covers the Windows-specific parts of flashing the ESP32-C3 build. The general
build/flash flow lives in [README.md](README.md) — read that first; this document only
adds what is different, or commonly goes wrong, on Windows.

Scope: **Windows 10/11**, **ESP32-C3** (and other native-USB parts: C6/S3). Porting to a
classic ESP32 or an ESP8266 is different — see [Other chips](#other-chips).

---

## You do not need a driver

The ESP32-C3 has a **USB-Serial/JTAG peripheral built into the chip**. There is no CH340,
CP210x or FTDI bridge on these boards, so there is no driver to download. Windows 10/11
binds its in-box `usbser.sys` automatically the first time the board is plugged in.

Advice telling you to install a CH340 driver for a C3 is wrong and will send you down a
dead end. The device enumerates as **two** interfaces, which looks alarming but is normal:

| Interface | Device Manager name | Driver |
|---|---|---|
| `MI_00` | USB Serial Device (COMx) — under *Ports (COM & LPT)* | `usbser` |
| `MI_02` | USB JTAG/serial debug unit — under *Universal Serial Bus devices* | `WINUSB` |

Ignore the JTAG entry. You flash and monitor over the COM port.

### Confirm the driver is healthy (no admin required)

```powershell
# COM ports the kernel currently has registered
Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM'

# Every Espressif device Windows has seen (VID 303A = Espressif)
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' |
  Where-Object { $_.PSChildName -match 'VID_303A' } |
  Select-Object -ExpandProperty PSChildName
```

```powershell
# Fault state + assigned port for the CDC interface
$k = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB\VID_303A&PID_1001&MI_00'
Get-ChildItem $k | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath
  "FriendlyName = $($p.FriendlyName)"
  "Service      = $($p.Service)"
  "ConfigFlags  = $($p.ConfigFlags)"   # 0 = healthy
  $dp = Join-Path $_.PSPath 'Device Parameters'
  if (Test-Path $dp) { "PortName     = $((Get-ItemProperty $dp).PortName)" }
}
```

`ConfigFlags = 0` means Windows considers the device healthy. If you see that, the driver
is not your problem — look at the cable (below) or the firmware.

> `Get-PnpDevice` and `Get-CimInstance Win32_PnPEntity` can fail with *Access denied* in a
> restricted shell. The registry queries above work without elevation.

---

## It doesn't appear at all

In order of real-world frequency:

1. **Charge-only USB-C cable.** By far the most common cause. Use a cable that carries data.
2. **USB-C → USB-C cable.** Many inexpensive C3 SuperMini boards omit the 5.1 kΩ CC
   pull-down resistors, so a C-to-C cable from a laptop or charger never enumerates the
   board. **Use a USB-A → USB-C cable into a USB-A port.**
3. **A hub.** Marginal power during boot current spikes causes dropouts. Connect directly
   to a rear motherboard port.
4. **The USB-C jack itself.** These connectors are a known weak point on SuperMini clones.
   A quick flex test while watching the port list will confirm intermittent contact.

If the board shows up nowhere in Device Manager — not even under *Unknown devices* — the
fault is electrical, not software.

---

## It connects and disconnects repeatedly

This is the most misdiagnosed symptom. **Look at the timing**, not the fact that it repeats.

Poll the live port map rather than eyeballing Device Manager:

```powershell
$last = $null; $changes = 0; $end = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $end) {
  $cur = (Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM').PSObject.Properties |
    Where-Object { $_.Name -notmatch '^PS' } |
    ForEach-Object { "$($_.Value)=$($_.Name)" } | Sort-Object
  $s = if ($cur) { $cur -join '; ' } else { '(none)' }
  if ($s -ne $last) { "{0}  {1}" -f (Get-Date).ToString('HH:mm:ss.fff'), $s; $last = $s; $changes++ }
  Start-Sleep -Milliseconds 200
}
"changes: $changes"
```

| Pattern | Meaning |
|---|---|
| **Regular** period (e.g. a consistent ~2 s cycle) | The **chip is resetting** — firmware crash-loop or brownout |
| **Irregular** / random | Cable, connector, or contact problem |

On a native-USB part, **every chip reset tears down the USB peripheral**, because it lives
inside the chip. A firmware crash therefore presents as a USB disconnect loop, which makes
it look like a cable or driver fault when it is neither.

### Isolating the cause

**Test 1 — download mode.** Hold **BOOT**, tap **RESET**, release **BOOT**. The application
never runs in this state.

- Port becomes stable → the application firmware was resetting. Reflash (or erase and reflash).
- Port still cycles → the fault is electrical: cable, connector, or power.

**Test 2 — erase the flash.** If the loop stops the moment the flash is blank, the old
firmware was the cause and the hardware is fine:

```powershell
python -m esptool --chip esp32c3 --port COMx erase-flash
```

> Note: `esptool` v5 renamed its commands to hyphenated form (`erase-flash`, `read-flash`,
> `write-flash`). Older tutorials using `erase_flash` will fail on v5.

**Test 3 — brownout.** If the device boots and then resets only under load (notably when
WiFi starts transmitting), it is a power problem, not firmware. The firmware already
retries at a reduced 8.5 dBm TX power to work around the known SuperMini antenna quirk;
a sturdier power source is the real fix.

---

## `pio device monitor` shows nothing

Two independent traps, and both are normal on native-USB parts:

1. **USB-Serial/JTAG does not replay past output.** It emits only what happens while a host
   is attached. Open the monitor after boot and you get silence — this is documented in the
   README as the console "swallowing" early boot output.
2. **A reset invalidates the open serial handle.** When the chip resets it re-enumerates on
   USB, so the handle the monitor holds now points at a device that no longer exists. The
   monitor can sit there looking alive and receive nothing.

A silent monitor therefore proves **nothing** about whether the firmware is running.
Verify another way — read the partitions, or capture the console directly:

```powershell
$code = @'
import serial, time
ser = serial.Serial('COMx', 115200, timeout=0.2)
ser.dtr = False; ser.rts = False
time.sleep(0.4); ser.reset_input_buffer()
end = time.time() + 6; buf = b''
while time.time() < end: buf += ser.read(512)
print('bytes:', len(buf)); print(buf.decode('utf-8','replace'))
ser.close()
'@
$code | python -
```

Opening the port this way can itself trigger a reset, which is useful here — it guarantees
you capture the boot sequence. A healthy boot prints the blocklist entry count, free heap,
and either a WiFi connection or the setup-portal banner.

---

## Firmware is present but the device does nothing

`pio run -t upload` and `pio run -t uploadfs` write **different partitions** and you need both:

| Command | Writes | Partition |
|---|---|---|
| `pio run -t upload` | firmware | `app0` |
| `pio run -t uploadfs` | blocklist | `spiffs` (LittleFS) |

Running only `uploadfs` leaves a valid filesystem with **no application**. The board still
enumerates on USB, so it looks alive while doing nothing. Running only `upload` gives you a
device that boots but reports an empty blocklist.

Confirm what is actually on the chip (first byte `E9` = valid ESP image header):

```powershell
python -m esptool --chip esp32c3 --port COMx read-flash 0x10000 0x10 app.bin
Format-Hex app.bin
```

The stock 4 MB partition table puts `app0` at `0x10000`, `app1` at `0x160000`, and the
LittleFS partition at `0x2b0000` — see [partitions.csv](partitions.csv).

---

## The upload hangs with no output

**Symptom:** `pio run -t upload` prints `Uploading .pio/build/<env>/firmware.bin`, then sits
there for minutes — sometimes long enough that you give up. No error is printed.

**Cause:** PlatformIO draws the upload progress bar with Unicode block characters (`░`/`█`).
If the console codepage is not UTF-8 (the default is `cp1252` on most Windows installs),
Python cannot encode them, and the exception kills the thread reading the uploader's output.
The transfer stalls behind it:

```
Exception in thread Thread-16 (run):
  ...
  File "encodings\cp1252.py", line 19, in encode
UnicodeEncodeError: 'charmap' codec can't encode characters in position 23-52
```

The build output itself hints at this: *"Firmware metrics can not be shown. Set the terminal
codepage to 'utf-8' or 'cp65001' on Windows."*

**Fix:** set the Python stream encoding and the console codepage before flashing:

```powershell
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUTF8 = '1'
chcp 65001
pio run -t upload --upload-port COMx
```

The same upload then completes in well under a minute.

Two related notes:

- **Don't buffer the output** if you need to watch progress. `pio ... | Select-Object -Last 20`
  prints nothing until the command exits, so a stalled upload looks exactly like a slow one.
  Redirect to a file or run it unpiped when you need to see it live.
- A stall like this usually happens once the progress bar starts drawing, which is *after* the
  target region has been erased — so the board is left blank or partially written. Just re-run
  the upload; there is nothing to recover by hand.

---

## `nvs_open failed: NOT_FOUND` in the boot log

```
[478][E][Preferences.cpp:47] begin(): nvs_open failed: NOT_FOUND
```

Harmless after a fresh `erase-flash`. The NVS partition is uninitialized, so the first
`Preferences::begin()` finds no namespace. It self-heals as soon as anything is written,
which happens the moment the WiFi setup portal saves credentials.

---

## The `C3-AdBlock-XXXX` network doesn't appear

First check whether the machine you are scanning from **has a Wi-Fi radio at all**:

```powershell
netsh wlan show interfaces
netsh wlan show networks mode=bssid | Select-String 'C3-AdBlock' -Context 0,4
```

If `netsh wlan show interfaces` prints nothing, there is no wireless adapter and the AP can
never appear — the scan is not evidence that it is missing. A wired-only desktop will never
see it; scan from a phone or a Wi-Fi laptop.

The AP name is derived from the station MAC (`C3-AdBlock-` + the last two MAC bytes), so
exact suffixes vary per board — scan for the `C3-AdBlock-` prefix rather than a fixed name.

The firmware deliberately drops the AP to 8.5 dBm because of the SuperMini antenna quirk,
so scan from a few feet away rather than across a room.

Two further constraints on the network you provision it onto:

- **2.4 GHz only** — the C3 has no 5 GHz radio.
- **WPA2** is the safe choice; WPA3-only networks commonly fail on ESP32.

---

## Other chips

The "no driver needed" rule above applies **only** to native-USB parts (C3/C6/S3).

| Board | USB layer | Driver on Windows |
|---|---|---|
| ESP32-C3 / C6 / S3 | on-chip USB-Serial/JTAG | **none** — in-box `usbser` |
| Classic ESP32 dev boards | usually a USB-UART bridge | CH340 or CP210x, depending on the bridge |
| ESP8266 (NodeMCU / D1 mini) | USB-UART bridge | usually CH340 |

If you move to a classic ESP32 or ESP8266, do install the driver for whichever bridge chip
your board actually carries — check the silkscreen or Device Manager for a CH34x / CP210x
device. The BOOT pin also changes (GPIO9 on C3; GPIO0 on classic ESP32 and ESP8266), which
matters because the firmware reads it at boot.

---

## Quick reference

```powershell
python -m pip install -U platformio esptool

Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM'          # find the port
python -m esptool --chip esp32c3 --port COMx chip-id           # is it talking?
python -m esptool --chip esp32c3 --port COMx erase-flash       # blank it

pio run -e c3
pio run -t upload        # firmware -> app0   (see the UTF-8 note below if this hangs)
pio run -t uploadfs      # blocklist -> spiffs
pio device monitor
```

If `pio run -t upload` hangs with no output, the progress bar is crashing on a non-UTF-8
console — see [The upload hangs with no output](#the-upload-hangs-with-no-output).
