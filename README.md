## Quick start

```bash
uv sync
uv run midealocal-toshiba login --account YOUR_EMAIL --password YOUR_PASSWORD
uv run midealocal-toshiba devices
uv run midealocal-toshiba status --appliance-id YOUR_DEVICE_ID --parse
```

## Session

Login saves credentials to `~/.midealocal-toshiba-session.json`. Subsequent commands reuse the saved session automatically.

## Commands

```bash
# Login & save session
uv run midealocal-toshiba login --account EMAIL --password PASS

# List devices
uv run midealocal-toshiba devices

# Get per-device info (category, modelNumber, sn)
uv run midealocal-toshiba info --appliance-id YOUR_DEVICE_ID

# Query AC status (parsed JSON)
uv run midealocal-toshiba status --appliance-id 24189258142030 --parse

# Control (single or multiple changes in one payload)
uv run midealocal-toshiba set --appliance-id 24189258142030 --power on
uv run midealocal-toshiba set --appliance-id 24189258142030 --mode cool --temp 24 --fanspeed high
```

## Architecture

- `security.py` — Key derivation from accessToken (`decode_with_app_key`), AES encrypt/decrypt (`ECB`/`CBC` text-key), V1 sign (`SHA256`), CRC8/CRC16
- `cloud.py` — `IoLifeClient`: login, `transparent_send`, `build_order` (5a5a datagram + AES encrypt), `decode_reply` (AES decrypt + datagram parse)
- `converter.py` — AC payload builder (`55 AA CC 33` UART frame + 5a5a WiFi datagram) and response parser (`parse_ac_status_body` — ports `T_0008_AC_30.lua` `binToModel`)
- `client.py` — `ToshibaACClient`: `get_status()`, `set_power()`, `set_temperature()`, `set_mode()`, `set_fan_speed()`, `set_swing_ud()`, `set_swing_lr()`, `set_eco()`
- `cli.py` — argparse-based CLI tool (`console_script`: `midealocal-toshiba`)

## Protocol layers

```
HTTP Cloud Relay (transparent_send API)
  → AES/ECB encrypt with dataKey derived from accessToken
    → 5a5a WiFi datagram (timestamp + device ID + CRC)
      → 55 AA CC 33 UART frame (AC protocol + CRC16)
```

Device communication uses the **cloud relay exclusively** — local TCP on port 6444 is not supported because the device uses a Toshiba-specific `55 AA CC 33` frame format instead of the standard Midea `AA` frame.

## Dependencies

- Python >= 3.12
- `pycryptodome` — AES, SHA256, MD5
- `aiohttp` — async HTTP (optional; CLI uses `urllib` only)
