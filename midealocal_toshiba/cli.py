"""Toshiba IOLife AC command-line tool."""

import argparse
import json
import pathlib
import sys
from typing import Any

from midealocal_toshiba.cloud import IoLifeClient, SessionExpiredError
from midealocal_toshiba.security import encrypt_password, decrypt_password
from midealocal_toshiba.converter import (
    build_ac_query_body,
    build_ac_control_body,
    AC_MODES,
    AC_FAN_SPEEDS,
)

SESSION_FILE = pathlib.Path.home() / ".midealocal-toshiba-session.json"


def load_session() -> dict[str, Any]:
    if not SESSION_FILE.exists():
        raise RuntimeError(f"session file not found: {SESSION_FILE}. Run 'login' first.")
    return json.loads(SESSION_FILE.read_text(encoding="utf-8"))


def save_session(data: dict[str, Any]) -> None:
    SESSION_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def _do_relogin(session: dict[str, Any]) -> None:
    encrypted = session.get("encryptedPassword")
    if not encrypted:
        raise RuntimeError("No encrypted password in session file. Run 'login' first.")
    password = decrypt_password(encrypted)
    account = session.get("account")
    if not account:
        raise RuntimeError("No account in session file.")
    client = IoLifeClient()
    new_session = client.login(account=account, password=password)
    new_session["encryptedPassword"] = encrypted
    save_session(new_session)


def _cmd_with_retry(args: argparse.Namespace, fn: Any) -> None:
    try:
        fn(args)
    except SessionExpiredError:
        print("Session expired, re-logging in...", file=sys.stderr)
        _do_relogin(load_session())
        fn(args)


def cmd_login(args: argparse.Namespace) -> None:
    client = IoLifeClient(language=args.language)
    session = client.login(
        account=args.account,
        password=args.password,
        push_type=args.push_type,
        push_token=args.push_token,
    )
    session["encryptedPassword"] = encrypt_password(args.password)
    save_session(session)
    print(f"Saved session to {SESSION_FILE}")
    print(json.dumps({
        k: session.get(k) for k in ["account", "userId", "sessionId", "dataKey", "dataIV"]
    }, ensure_ascii=False, indent=2))


def _require_session(args: argparse.Namespace) -> dict[str, Any]:
    session = load_session()
    session_id = args.session_id or session.get("sessionId")
    if not session_id:
        raise RuntimeError("sessionId not found")
    data_key = session.get("dataKey")
    if not data_key:
        raise RuntimeError("dataKey missing in session")
    return session


def cmd_devices(args: argparse.Namespace) -> None:
    _cmd_with_retry(args, _cmd_devices_impl)


def _cmd_devices_impl(args: argparse.Namespace) -> None:
    session = load_session()
    session_id = args.session_id or session.get("sessionId")
    if not session_id:
        raise RuntimeError("sessionId not found. Run login first.")
    client = IoLifeClient(language=args.language)
    resp = client.list_devices(session_id=session_id, app_version=args.app_version)
    print(json.dumps(resp, ensure_ascii=False, indent=2))


def cmd_device_info(args: argparse.Namespace) -> None:
    _cmd_with_retry(args, _cmd_device_info_impl)


def _cmd_device_info_impl(args: argparse.Namespace) -> None:
    session = load_session()
    session_id = args.session_id or session.get("sessionId")
    if not session_id:
        raise RuntimeError("sessionId not found. Run login first.")
    client = IoLifeClient(language=args.language)
    resp = client.get_device_info(
        session_id=session_id,
        appliance_id=args.appliance_id,
        app_version=args.app_version,
    )
    print(json.dumps(resp, ensure_ascii=False, indent=2))


def cmd_status(args: argparse.Namespace) -> None:
    _cmd_with_retry(args, _cmd_status_impl)


def _cmd_status_impl(args: argparse.Namespace) -> None:
    session = _require_session(args)
    client = IoLifeClient(language=args.language)
    payload = build_ac_query_body("all")
    order = client.build_order(
        payload_hex=payload.hex().upper(),
        appliance_id=args.appliance_id,
        data_key=session["dataKey"],
        data_iv=session.get("dataIV"),
    )
    resp = client.transparent_send(
        session_id=session["sessionId"],
        appliance_id=args.appliance_id,
        order=order,
    )
    error_code = str(resp.get("errorCode", "")).strip()
    if error_code == "0" and resp.get("result", {}).get("reply"):
        parsed = client.decode_reply(
            reply_hex=resp["result"]["reply"],
            data_key=session["dataKey"],
            data_iv=session.get("dataIV"),
        )
        body_hex = parsed.get("bodyHex", "")
        if body_hex and args.parse:
            from midealocal_toshiba.converter import parse_ac_response
            ac_status = parse_ac_response(body_hex)
            print(json.dumps(ac_status, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(parsed, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(resp, ensure_ascii=False, indent=2))


def _send_control(args: argparse.Namespace, props: list[tuple[int, int]]) -> None:
    session = _require_session(args)
    client = IoLifeClient(language=args.language)
    payload = build_ac_control_body(*props)
    order = client.build_order(
        payload_hex=payload.hex().upper(),
        appliance_id=args.appliance_id,
        data_key=session["dataKey"],
        data_iv=session.get("dataIV"),
    )
    resp = client.transparent_send(
        session_id=session["sessionId"],
        appliance_id=args.appliance_id,
        order=order,
    )
    error_code = str(resp.get("errorCode", "")).strip()
    if error_code == "0" and resp.get("result", {}).get("reply") and getattr(args, "parse", False):
        parsed = client.decode_reply(
            reply_hex=resp["result"]["reply"],
            data_key=session["dataKey"],
            data_iv=session.get("dataIV"),
        )
        body_hex = parsed.get("bodyHex", "")
        if body_hex:
            from midealocal_toshiba.converter import parse_ac_response
            ac_status = parse_ac_response(body_hex)
            print(json.dumps(ac_status, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(parsed, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(resp, ensure_ascii=False, indent=2))


def cmd_set(args: argparse.Namespace) -> None:
    _cmd_with_retry(args, _cmd_set_impl)


def _cmd_set_impl(args: argparse.Namespace) -> None:
    props: list[tuple[int, int]] = []
    if args.power is not None:
        props.append((0x01, 1 if args.power == "on" else 0))
    if args.mode is not None:
        props.append((0x02, AC_MODES[args.mode]))
    if args.temp is not None:
        props.append((0x03, int(args.temp * 2)))
    if args.fanspeed is not None:
        props.append((0x06, AC_FAN_SPEEDS[args.fanspeed]))
    if not props:
        raise ValueError("at least one of --power, --mode, --temp, --fanspeed required")
    _send_control(args, props)


def main() -> None:
    parser = argparse.ArgumentParser(description="Toshiba IOLIFE AC control")
    parser.add_argument("--language", default="ja_JP", help="request language")
    sub = parser.add_subparsers(dest="command", required=True)

    p_login = sub.add_parser("login", help="login and save session")
    p_login.add_argument("--account", required=True)
    p_login.add_argument("--password", required=True)
    p_login.add_argument("--push-type", default="4")
    p_login.add_argument("--push-token", default="false")
    p_login.set_defaults(func=cmd_login)

    p_devices = sub.add_parser("devices", help="list devices")
    p_devices.add_argument("--session-id")
    p_devices.add_argument("--app-version", default="3.3.2")
    p_devices.set_defaults(func=cmd_devices)

    p_info = sub.add_parser("info", help="get device info (category, modelNumber, sn, etc.)")
    p_info.add_argument("--appliance-id", required=True)
    p_info.add_argument("--session-id")
    p_info.add_argument("--app-version", default="3.3.2")
    p_info.set_defaults(func=cmd_device_info)

    p_status = sub.add_parser("status", help="query AC status")
    p_status.add_argument("--appliance-id", required=True)
    p_status.add_argument("--session-id")
    p_status.add_argument("--parse", action="store_true", help="parse AC status body")
    p_status.set_defaults(func=cmd_status)

    p_set = sub.add_parser("set", help="set AC state (power, mode, temp, fanspeed)")
    p_set.add_argument("--appliance-id", required=True)
    p_set.add_argument("--power", choices=["on", "off"])
    p_set.add_argument("--mode", choices=sorted(AC_MODES.keys()))
    p_set.add_argument("--temp", type=float)
    p_set.add_argument("--fanspeed", choices=sorted(AC_FAN_SPEEDS.keys()))
    p_set.add_argument("--session-id")
    p_set.add_argument("--parse", action="store_true")
    p_set.set_defaults(func=cmd_set)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
