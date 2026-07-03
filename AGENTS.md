## Dependencies

```bash
uv sync
```

## Build

```bash
python -m build
```

## Lint & typecheck

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy midealocal_toshiba/
```

## Tests

```bash
uv run python -m pytest tests/
```

## Architecture

```
midealocal_toshiba/
├── security.py    — key derivation, AES (ECB/CBC text-key), SHA256 sign, CRC8/16
├── cloud.py       — IOLife HTTP client (login, transparent_send, build_order, decode_reply)
├── converter.py   — AC 55AACC33 payload builder + response parser (port of T_0008_AC_30.lua)
├── client.py      — ToshibaACClient: get_status, set_power, set_temp, set_mode, etc.
└── cli.py         — CLI tool (console_script: midealocal-toshiba)
```

## Key conventions

- All API calls use synchronous `urllib` (no async needed for simple CLI).
- `aiohttp` is available as an optional dependency for async usage.
- The cloud relay API (`/v1/appliance/transparent/send`) is the only communication path — local TCP on port 6444 is not used because the device speaks a Toshiba-specific frame format (`55 AA CC 33`) that differs from standard Midea.
- AES uses **text keys** (`.encode("utf-8")`), not hex-decoded keys. Derived from `accessToken` via `decode_with_app_key()`.
- Session is persisted to `~/.midealocal-toshiba-session.json`.
- Python >= 3.12.
- Build config is `pyproject.toml` (setuptools backend).
