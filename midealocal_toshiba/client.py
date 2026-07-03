"""High-level Toshiba AC client using IOLife cloud relay."""

import json
from typing import Any

from midealocal_toshiba.cloud import IoLifeClient
from midealocal_toshiba.converter import (
    AC_FAN_SPEEDS,
    AC_MODES,
    build_ac_control_body,
    build_ac_power_body,
    build_ac_query_body,
    parse_wifidatagram,
)


class ToshibaACClient:
    def __init__(
        self,
        appliance_id: str,
        session_id: str,
        data_key: str,
        data_iv: str | None = None,
        language: str = "ja_JP",
    ) -> None:
        self.appliance_id = appliance_id
        self.session_id = session_id
        self.data_key = data_key
        self.data_iv = data_iv
        self.cloud = IoLifeClient(language=language)

    def _transparent_send(self, payload: bytes) -> dict[str, Any]:
        order = self.cloud.build_order(
            payload_hex=payload.hex().upper(),
            appliance_id=self.appliance_id,
            data_key=self.data_key,
            data_iv=self.data_iv,
        )
        resp = self.cloud.transparent_send(
            session_id=self.session_id,
            appliance_id=self.appliance_id,
            order=order,
        )
        error_code = str(resp.get("errorCode", "")).strip()
        if error_code != "0":
            raise RuntimeError(f"API error: errorCode={error_code}, msg={resp.get('msg')}")

        result = resp.get("result") or {}
        reply_hex = result.get("reply")
        if reply_hex:
            parsed = self.cloud.decode_reply(reply_hex, self.data_key, self.data_iv)
            return resp, parsed
        return resp, {}

    def get_status(self) -> dict[str, Any]:
        """Query all AC attributes."""
        payload = build_ac_query_body("all")
        resp, parsed = self._transparent_send(payload)
        body_hex = parsed.get("bodyHex", "")
        return {"raw": resp, "parsed": parsed}

    def set_power(self, on: bool) -> dict[str, Any]:
        """Turn AC on or off."""
        state = "on" if on else "off"
        payload = build_ac_power_body(state)
        resp, parsed = self._transparent_send(payload)
        return {"raw": resp, "parsed": parsed}

    def set_mode(self, mode: str) -> dict[str, Any]:
        """Set AC mode: auto, cool, dry, heat, fan."""
        value = AC_MODES.get(mode.lower())
        if value is None:
            raise ValueError(f"unknown mode '{mode}', expected: {', '.join(AC_MODES)}")
        payload = build_ac_control_body((0x02, value))
        resp, parsed = self._transparent_send(payload)
        return {"raw": resp, "parsed": parsed}

    def set_temperature(self, temp: float) -> dict[str, Any]:
        """Set target temperature. Temp is * 2 internally (e.g., 24.0 → 48)."""
        value = int(temp * 2)
        payload = build_ac_control_body((0x03, value))
        resp, parsed = self._transparent_send(payload)
        return {"raw": resp, "parsed": parsed}

    def set_fan_speed(self, speed: str) -> dict[str, Any]:
        """Set fan speed: auto, high, mid, low, mute."""
        value = AC_FAN_SPEEDS.get(speed.lower())
        if value is None:
            raise ValueError(f"unknown fan speed '{speed}', expected: {', '.join(AC_FAN_SPEEDS)}")
        payload = build_ac_control_body((0x06, value))
        resp, parsed = self._transparent_send(payload)
        return {"raw": resp, "parsed": parsed}

    def set_swing_ud(self, value: int = 3) -> dict[str, Any]:
        """Set vertical swing (0-3)."""
        payload = build_ac_control_body((0x08, value))
        resp, parsed = self._transparent_send(payload)
        return {"raw": resp, "parsed": parsed}

    def set_swing_lr(self, value: int = 3) -> dict[str, Any]:
        """Set horizontal swing (0-3)."""
        payload = build_ac_control_body((0x09, value))
        resp, parsed = self._transparent_send(payload)
        return {"raw": resp, "parsed": parsed}

    def set_eco(self, on: bool) -> dict[str, Any]:
        """Enable/disable eco mode."""
        payload = build_ac_control_body((0x0D, 1 if on else 0))
        resp, parsed = self._transparent_send(payload)
        return {"raw": resp, "parsed": parsed}
