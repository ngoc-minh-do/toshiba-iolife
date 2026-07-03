"""Toshiba IOLife cloud API client."""

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from midealocal_toshiba.security import (
    APP_ENTERPRISE,
    APP_ID,
    APP_KEY,
    APP_SRC,
    CLIENT_TYPE,
    HOST,
    SCHEME,
    SERVER_VERSION,
    DEFAULT_LANGUAGE,
    aes_encrypt_hex,
    bytes_to_dec_string,
    decode_with_app_key,
    md5_hex,
    sha256_hex,
    sign_v1,
)
from midealocal_toshiba.converter import (
    build_ac_power_body,
    build_ac_query_body,
    build_ac_control_body,
    build_ac_uart_payload,
    build_wifidatagram,
    parse_wifidatagram,
)

AC_REQUEST_CONTROL = 0x0002
AC_REQUEST_QUERY = 0x0003


class IoLifeClient:
    def __init__(
        self,
        language: str = DEFAULT_LANGUAGE,
        host: str = HOST,
        scheme: str = SCHEME,
        server_version: str = SERVER_VERSION,
        app_id: str = APP_ID,
        app_src: str = APP_SRC,
    ) -> None:
        self.host = host
        self.scheme = scheme
        self.server_version = server_version
        self.app_id = app_id
        self.app_src = app_src
        self.language = language

    def _request_path(self, endpoint: str) -> str:
        endpoint = endpoint.lstrip("/")
        return f"/{self.server_version}/{endpoint}"

    def _base_params(self, session_id: str | None = None) -> dict[str, str]:
        from datetime import datetime
        params: dict[str, str] = {
            "format": "2",
            "stamp": datetime.now().strftime("%Y%m%d%H%M%S"),
            "language": self.language,
            "appId": self.app_id,
            "src": self.app_src,
        }
        if session_id:
            params["sessionId"] = session_id
        return params

    def _post(self, endpoint: str, params: dict[str, Any], signed: bool = True) -> dict[str, Any]:
        path = self._request_path(endpoint)
        payload: dict[str, Any] = dict(params)
        if signed:
            payload["sign"] = sign_v1(path, {k: str(v) for k, v in payload.items()})
        body = urllib.parse.urlencode(payload).encode("utf-8")
        url = f"{self.scheme}://{self.host}{path}"
        req = urllib.request.Request(url=url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            err = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {err}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"network error: {exc}") from exc
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise RuntimeError(f"invalid JSON response: {text}") from None

    def get_login_id(self, account: str) -> str:
        params = self._base_params()
        params["clientType"] = CLIENT_TYPE
        params["loginAccount"] = account
        resp = self._post("user/login/id/get", params, signed=True)
        result = resp.get("result") or {}
        login_id = result.get("loginId")
        if not login_id:
            raise RuntimeError(f"loginId not found: {resp}")
        return str(login_id)

    def login(self, account: str, password: str, push_type: str = "4", push_token: str = "false") -> dict[str, Any]:
        login_id = self.get_login_id(account)
        password_sha = sha256_hex(password)
        password_enc = sha256_hex(f"{login_id}{password_sha}{APP_KEY}")
        iampwd = sha256_hex(f"{login_id}{md5_hex(md5_hex(password))}{APP_KEY}")

        params = self._base_params()
        params["clientType"] = CLIENT_TYPE
        params["loginAccount"] = account
        params["password"] = password_enc
        params["pushType"] = push_type
        params["pushToken"] = push_token
        params["iampwd"] = iampwd

        resp = self._post("user/login", params, signed=True)
        result = resp.get("result") or {}

        access_token = result.get("accessToken")
        random_data = result.get("randomData")
        data_key = None
        data_iv = None
        if access_token:
            try:
                data_key = decode_with_app_key(str(access_token))
            except Exception:
                data_key = None
        if random_data:
            try:
                data_iv = decode_with_app_key(str(random_data))
            except Exception:
                data_iv = None

        return {
            "account": account,
            "loginId": login_id,
            "sessionId": result.get("sessionId"),
            "userId": result.get("userId"),
            "accessToken": access_token,
            "randomData": random_data,
            "dataKey": data_key,
            "dataIV": data_iv,
            "raw": resp,
        }

    def list_devices(self, session_id: str, app_version: str = "3.3.2") -> dict[str, Any]:
        params = self._base_params(session_id=session_id)
        params["appVersion"] = app_version
        params["clientType"] = CLIENT_TYPE
        params["appId"] = self.app_id
        return self._post("appliance/user/home/page/list/info", params, signed=True)

    def get_device_info(self, session_id: str, appliance_id: str, app_version: str = "3.3.2") -> dict[str, Any]:
        params = self._base_params(session_id=session_id)
        params["appVersion"] = app_version
        params["clientType"] = CLIENT_TYPE
        params["applianceId"] = appliance_id
        return self._post("appliance/user/info/get", params, signed=True)

    def transparent_send(self, session_id: str, appliance_id: str, order: str) -> dict[str, Any]:
        params = self._base_params(session_id=session_id)
        params["applianceId"] = appliance_id
        params["funId"] = APP_ENTERPRISE
        params["order"] = order
        return self._post("appliance/transparent/send", params, signed=True)

    def build_order(
        self,
        payload_hex: str,
        appliance_id: str,
        data_key: str,
        data_iv: str | None = None,
        msg_type: int = 32,
    ) -> str:
        """Build encrypted order from raw payload hex."""
        normalized = payload_hex.strip().replace(" ", "").replace(":", "")
        packet = build_wifidatagram(payload_hex=normalized, appliance_id=appliance_id, msg_type=msg_type)
        plain_dec = bytes_to_dec_string(packet)
        return aes_encrypt_hex(plain_dec, data_key, data_iv)

    def decode_reply(self, reply_hex: str, data_key: str, data_iv: str | None = None) -> dict[str, Any]:
        """Decrypt and parse transparent_send reply."""
        from midealocal_toshiba.security import aes_decrypt_hex, dec_string_to_bytes

        dec = aes_decrypt_hex(reply_hex, data_key, data_iv)
        raw = dec_string_to_bytes(dec)
        return parse_wifidatagram(raw)
