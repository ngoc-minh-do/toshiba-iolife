"""AC message converter: build 5a5a datagram + 55AACC33 UART frame.

Ported from reference-toshiba-iolife/main.py and T_0008_AC_30.lua.
"""

import itertools
import random
from datetime import datetime
from typing import Any

from midealocal_toshiba.security import crc16_ccitt, crc8_854

AC_DEVICE_TYPE = 0xAC
AC_REQUEST_CONTROL = 0x0002
AC_REQUEST_QUERY = 0x0003
AC_CONTROL_PROPERTY_CMD = 0xB0
AC_QUERY_PROPERTY_CMD = 0xB1
MESSAGE_COUNTER = itertools.count(1)

AC_QUERY_PROPERTIES: dict[str, int] = {
    "power": 0x01,
    "mode": 0x02,
    "temperature": 0x03,
    "indoor_temperature": 0x04,
    "outdoor_temperature": 0x05,
    "wind_speed": 0x06,
    "wind_speed_real": 0x07,
    "wind_swing_ud": 0x08,
    "wind_swing_lr": 0x09,
    "wind_deflector": 0x0A,
    "power_on_timer": 0x0B,
    "power_off_timer": 0x0C,
    "eco": 0x0D,
    "purifier": 0x0E,
    "cool_hot_sense": 0x21,
    "ai_study_control": 0x22,
    "ai_study_temperature": 0x23,
    "dry": 0x10,
    "nobody_energy_save": 0x30,
    "wind_straight": 0x32,
    "wind_avoid": 0x33,
    "humidity": 0x14,
    "indoor_humidity": 0x15,
    "screen_display": 0x17,
    "no_wind_sense": 0x18,
    "buzzer": 0x1A,
    "filter": 0x3D,
    "error_code_query": 0x3F,
    "mode_query": 0x41,
    "clean": 0x46,
    "high_temperature_monitor": 0x47,
    "rate_select": 0x48,
    "power_on_timer_specific": 0x53,
    "power_off_timer_specific": 0x54,
    "timer_expired": 0x60,
    "timer_setting": 0x61,
    "new_no_wind_sense": 0x70,
    "wind_radar": 0x71,
    "area": 0x72,
    "way_out": 0x73,
    "quick_mode": 0x74,
    "change_air": 0x75,
    "air_clean_switch": 0x76,
    "circle_fan": 0x79,
    "eco_power_saving": 0x7A,
    "weak_cool": 0x7B,
    "high_temperature_wind": 0x7C,
    "manual_defrost": 0x7D,
}

AC_MODES: dict[str, int] = {
    "auto": 0x01,
    "cool": 0x02,
    "dry": 0x03,
    "heat": 0x04,
    "fan": 0x05,
}

AC_FAN_SPEEDS: dict[str, int] = {
    "auto": 0x00,
    "high": 0x50,
    "mid": 0x3C,
    "low": 0x14,
    "mute": 0x01,
}


def timestamp_bytes() -> bytes:
    now = datetime.now()
    year = now.year
    return bytes(
        [
            (now.microsecond // 1000) & 0xFF,
            now.second & 0xFF,
            now.minute & 0xFF,
            (now.hour % 12) & 0xFF,
            now.day & 0xFF,
            (now.month - 1) & 0xFF,
            (year % 100) & 0xFF,
            (year // 100) & 0xFF,
        ]
    )


def build_wifidatagram(
    payload_hex: str,
    appliance_id: str,
    msg_type: int = 32,
    msg_id: int | None = None,
) -> bytes:
    body = bytes.fromhex(payload_hex)
    msg_id = next(MESSAGE_COUNTER) if msg_id is None else msg_id
    dev_id = int(appliance_id).to_bytes(8, "little", signed=False)[:6]
    length = len(body) + 56
    packet = bytearray()
    packet += b"\x5A\x5A"
    packet += b"\x01"
    packet += b"\x00"
    packet += length.to_bytes(2, "little", signed=False)
    packet += int(msg_type).to_bytes(2, "little", signed=False)
    packet += int(msg_id).to_bytes(4, "little", signed=False)
    packet += timestamp_bytes()
    packet += dev_id
    packet += b"\x00\x00"
    packet += bytes(6)
    packet += bytes(6)
    packet += body
    packet += bytes(16)
    if len(packet) != length:
        raise ValueError(f"datagram length mismatch: expected={length}, actual={len(packet)}")
    return bytes(packet)


def parse_wifidatagram(data: bytes) -> dict[str, Any]:
    if len(data) < 56 or data[0:2] != b"\x5A\x5A":
        raise ValueError("invalid datagram")
    length = int.from_bytes(data[4:6], "little", signed=False)
    msg_type = int.from_bytes(data[6:8], "little", signed=False)
    body_len = length - 56
    body = data[40 : 40 + body_len] if body_len > 0 else b""
    return {
        "length": length,
        "msgType": msg_type,
        "msgId": int.from_bytes(data[8:12], "little", signed=False),
        "devIdHex": data[20:26].hex(),
        "bodyHex": body.hex().upper(),
        "rawHex": data.hex().upper(),
    }


def build_ac_uart_payload(body: list[int], request_type: int) -> bytes:
    body_length = len(body)
    msg_length = body_length + 0x10 + 2
    msg = [0] * msg_length
    msg[0] = 0x55
    msg[1] = 0xAA
    msg[2] = 0xCC
    msg[3] = 0x33
    msg_len = msg_length - 4
    msg[4] = msg_len & 0xFF
    msg[5] = (msg_len >> 8) & 0xFF
    msg[6] = 0x01
    msg[7] = AC_DEVICE_TYPE
    msg[14] = request_type & 0xFF
    msg[15] = (request_type >> 8) & 0xFF
    for i, value in enumerate(body):
        msg[0x10 + i] = value & 0xFF
    crc = crc16_ccitt(msg, 0, msg_length - 3)
    msg[msg_length - 2] = crc & 0xFF
    msg[msg_length - 1] = (crc >> 8) & 0xFF
    return bytes(msg)


def build_ac_query_body(query_type: str = "all") -> bytes:
    """Build AC query payload (55AACC33 frame)."""
    query_type = (query_type or "all").strip().lower()
    if query_type in {"all", "*"}:
        body = [0] * 22
        body[0] = 0x41
        body[1] = 0x81
        body[3] = 0xFF
        body[20] = random.randint(1, 254)
        body[21] = crc8_854(body, 0, 20)
        return build_ac_uart_payload(body, AC_REQUEST_QUERY)

    prop_code = AC_QUERY_PROPERTIES.get(query_type)
    if prop_code is None:
        supported = ", ".join(sorted(AC_QUERY_PROPERTIES.keys()))
        raise ValueError(f"unsupported query type '{query_type}'. use: all, {supported}")

    body = [AC_QUERY_PROPERTY_CMD, 1, prop_code, 0x00]
    body.append(random.randint(1, 254))
    body.append(0x00)
    body[-1] = crc8_854(body, 0, len(body) - 2)
    return build_ac_uart_payload(body, AC_REQUEST_QUERY)


def build_ac_control_body(*props: tuple[int, int]) -> bytes:
    """Build AC control payload from (property_code, value) tuples.

    Example: build_ac_control_body((0x01, 1)) → power on
    """
    n = len(props)
    body = [AC_CONTROL_PROPERTY_CMD, n]
    for prop_code, value in props:
        body.extend([prop_code, 0x00, 0x01, value])
    body.append(random.randint(1, 254))
    body.append(0x00)
    body[-1] = crc8_854(body, 0, len(body) - 2)
    return build_ac_uart_payload(body, AC_REQUEST_CONTROL)


def build_ac_power_body(state: str) -> bytes:
    state_value = 1 if state.lower() in ("on", "true", "1") else 0
    return build_ac_control_body((0x01, state_value))


# ── Response parsing (ported from T_0008_AC_30.lua binToModel + dataToJson) ──

MODE_NAMES: dict[int, str] = {
    0x01: "auto",
    0x02: "cool",
    0x03: "dry",
    0x04: "heat",
    0x05: "fan",
    0x06: "smart_dry",
}

FAN_SPEED_NAMES: dict[int, str] = {
    0x00: "auto",
    0x50: "high",
    0x3C: "mid",
    0x14: "low",
    0x01: "mute",
}


def parse_ac_status_body(body: bytes) -> dict[str, object]:
    """Parse the binary AC status body (55AACC33 frame body)."""
    if len(body) < 21:
        return {"_error": "body too short", "_raw": body.hex()}

    # header: 55 AA CC 33 [len2] [01 AC] [6 reserved] [cType2]
    # body starts after 16-byte header (0x10)
    ofs = 0x10
    msg = body
    data_type = msg[14]  # cType low byte

    result: dict[str, object] = {}

    if data_type in (0x02, 0x03, 0x05) and len(body) > ofs and msg[ofs] in (0xC0, 0xD0):
        result = _parse_c0_response(msg, ofs)

    elif data_type == 0x04 and len(body) > ofs and msg[ofs] == 0xA0:
        result = _parse_a0_response(msg, ofs)

    elif data_type == 0x04 and len(body) > ofs and msg[ofs] == 0xA1:
        result = _parse_a1_response(msg, ofs)

    return result


def _parse_c0_response(msg: bytes, ofs: int) -> dict[str, object]:
    """Parse C0/D0 response type (standard query/all response)."""
    r: dict[str, object] = {"function_type": "base"}
    m = msg

    # Byte 1: power
    r["power"] = "on" if (m[ofs + 1] & 0x01) else "off"

    # Byte 2: mode (bits 4-7) + mode_real (bits 0-3)
    mode_val = (m[ofs + 2] & 0xF0) >> 4
    mode_real = m[ofs + 2] & 0x0F
    r["mode"] = MODE_NAMES.get(mode_val, mode_val)
    r["mode_real"] = MODE_NAMES.get(mode_real, mode_real)

    # Byte 4: temperature (bits 0-6) / 2
    temp_raw = m[ofs + 4] & 0x7F
    r["temperature"] = temp_raw // 2
    r["small_temperature"] = (temp_raw % 2) * 0.5

    # Byte 3: fan speed (bits 0-6)
    fan_raw = m[ofs + 3] & 0x7F
    r["wind_speed"] = FAN_SPEED_NAMES.get(fan_raw, fan_raw)

    # Timer switches and values
    # Byte 5: openTimerSwitch (bit 7) + openTime hours (bits 0-6)
    r["power_on_timer"] = "on" if (m[ofs + 5] & 0x80) else "off"
    open_hours = m[ofs + 5] & 0x7F
    open_mins = m[ofs + 6]
    r["power_on_time_value"] = open_hours * 60 + open_mins

    # Byte 7: closeTimerSwitch (bit 7) + closeTime hours (bits 0-6)
    r["power_off_timer"] = "on" if (m[ofs + 7] & 0x80) else "off"
    close_hours = m[ofs + 7] & 0x7F
    close_mins = m[ofs + 8]
    r["power_off_time_value"] = close_hours * 60 + close_mins

    # Humidity
    r["humidity"] = m[ofs + 9]
    r["indoor_humidity"] = m[ofs + 10]

    # Swing
    r["wind_swing_lr"] = m[ofs + 11] & 0x0F
    r["wind_swing_ud"] = (m[ofs + 11] & 0xF0) >> 4

    # Rate select
    r["rate_select"] = m[ofs + 12]

    # Temperatures
    if m[ofs + 13] != 0xFF:
        r["indoor_temperature"] = (m[ofs + 13] - 50) / 2 + 0.1 * (m[ofs + 15] & 0x0F)
    else:
        r["indoor_temperature"] = -100

    if m[ofs + 14] != 0xFF:
        r["outdoor_temperature"] = (m[ofs + 14] - 50) / 2 + 0.1 * ((m[ofs + 15] & 0xF0) >> 4)
    else:
        r["outdoor_temperature"] = -100

    # Byte 16: flags
    b16 = m[ofs + 16]
    r["eco"] = "on" if (b16 & 0x01) else "off"
    r["purifier"] = "on" if (b16 & 0x02) else "off"
    r["dry"] = "on" if (b16 & 0x04) else "off"
    r["cool_hot_sense"] = "on" if (b16 & 0x08) else "off"
    r["clean_manual"] = "on" if (b16 & 0x10) else "off"
    r["clean_auto"] = "on" if (b16 & 0x20) else "off"
    r["ai_study_control"] = "on" if (b16 & 0x40) else "off"

    # Byte 17: monitor + filter
    b17 = m[ofs + 17]
    r["high_temp_monitor"] = "on" if (b17 & 0x10) else "off"
    r["high_temp_monitor_status"] = b17 & 0x0F
    r["filter_full"] = "on" if (b17 & 0x20) else "off"

    # Byte 18: no wind sense + circle fan + eco power
    b18 = m[ofs + 18]
    r["no_wind_sense"] = b18 & 0x0F
    r["circle_fan"] = "on" if (b18 & 0x10) else "off"
    r["eco_power_saving"] = "on" if (b18 & 0x20) else "off"

    # Byte 19-20: deflector angles
    r["wind_deflector_angle_ud"] = m[ofs + 19]
    r["wind_deflector_angle_lr"] = m[ofs + 20]

    # Byte 21: more flags
    b21 = m[ofs + 21]
    r["energy_save"] = "on" if (b21 & 0x01) else "off"
    r["dehumidify"] = (b21 & 0x0E) >> 1
    r["comfort_airflow"] = "on" if (b21 & 0x10) else "off"
    r["dash_heating"] = "on" if (b21 & 0x20) else "off"
    r["timer_daily"] = "on" if (b21 & 0x40) else "off"
    r["timer_remoter"] = "on" if (b21 & 0x80) else "off"

    # Error code
    if len(m) > ofs + 25:
        r["error_code"] = m[ofs + 23]

    # Extended fields (AC_26+)
    if len(m) > ofs + 26:
        b24 = m[ofs + 24]
        b25 = m[ofs + 25]
        b26 = m[ofs + 26]
        b27 = m[ofs + 27]

        r["quick_mode"] = "on" if (b24 & 0x01) else "off"
        r["air_monitor_status"] = (b24 & 0x06) >> 1
        r["air_monitor_switch"] = "on" if (b24 & 0x08) else "off"
        r["new_no_wind_sense"] = (b24 & 0x30) >> 4
        r["area"] = (b24 & 0xC0) >> 6

        r["radar_area_c_3"] = "on" if (b25 & 0x01) else "off"
        r["radar_status"] = "on" if (b25 & 0x02) else "off"
        r["wind_radar"] = (b25 & 0x0C) >> 2
        r["defrost"] = "on" if (b25 & 0x10) else "off"
        r["way_out"] = "on" if (b25 & 0x20) else "off"
        r["air_clean_status"] = "on" if (b25 & 0x40) else "off"
        r["air_clean_switch"] = "on" if (b25 & 0x80) else "off"

        r["radar_area_a_1"] = "on" if (b26 & 0x01) else "off"
        r["radar_area_a_2"] = "on" if (b26 & 0x02) else "off"
        r["radar_area_a_3"] = "on" if (b26 & 0x04) else "off"
        r["radar_area_b_1"] = "on" if (b26 & 0x08) else "off"
        r["radar_area_b_2"] = "on" if (b26 & 0x10) else "off"
        r["radar_area_b_3"] = "on" if (b26 & 0x20) else "off"
        r["radar_area_c_1"] = "on" if (b26 & 0x40) else "off"
        r["radar_area_c_2"] = "on" if (b26 & 0x80) else "off"

        r["uvc_set"] = "on" if (b27 & 0x01) else "off"
        r["weak_cool"] = "on" if (b27 & 0x02) else "off"
        r["high_temperature_wind"] = "on" if (b27 & 0x04) else "off"
        r["manual_defrost"] = "on" if (b27 & 0x08) else "off"
        r["preheat_setting"] = "on" if (b27 & 0x10) else "off"
        r["preheat_working"] = "on" if (b27 & 0x20) else "off"

    return r


def _parse_a0_response(msg: bytes, ofs: int) -> dict[str, object]:
    """Parse A0 response type (periodic energy data)."""
    r: dict[str, object] = {"function_type": "periodic"}
    m = msg
    if len(m) > ofs + 87:
        total_elec = (m[ofs + 81] * 16777216 + m[ofs + 82] * 65536
                      + m[ofs + 83] * 256 + m[ofs + 84]) / 100
        r["total_elec"] = total_elec
        real_time_power = (m[ofs + 85] * 65536 + m[ofs + 86] * 256 + m[ofs + 87]) / 100
        r["real_time_power"] = real_time_power
    return r


def _parse_a1_response(msg: bytes, ofs: int) -> dict[str, object]:
    """Parse A1 response type (periodic data with error + temps)."""
    r: dict[str, object] = {"function_type": "periodic"}
    m = msg
    if len(m) > ofs + 25:
        r["error_code"] = m[ofs + 23]
    if m[ofs + 13] not in (0x00, 0xFF):
        r["indoor_temperature"] = (m[ofs + 13] - 50) / 2
        small_indoor = m[ofs + 18] & 0x0F
        if small_indoor:
            r["indoor_temperature"] += 0.1 * small_indoor
    if m[ofs + 14] not in (0x00, 0xFF):
        r["outdoor_temperature"] = (m[ofs + 14] - 50) / 2
        small_outdoor = (m[ofs + 18] & 0xF0) >> 4
        if small_outdoor:
            r["outdoor_temperature"] += 0.1 * small_outdoor
    return r


def parse_ac_response(body_hex: str) -> dict[str, object]:
    """Parse the full AC 55AACC33 response frame from hex body."""
    body = bytes.fromhex(body_hex)
    if len(body) < 18 or body[:4] != b"\x55\xAA\xCC\x33":
        raise ValueError(f"not a valid 55AACC33 frame: {body_hex[:20]}")
    return parse_ac_status_body(body)
