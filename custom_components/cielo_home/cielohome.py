"""None."""

import asyncio
from collections.abc import Awaitable
import contextlib
import copy
from datetime import datetime
import hashlib
import json
import logging
import re
import sys
from threading import Lock, Timer
import uuid

import aiohttp
from aiohttp import ClientSession, ClientWebSocketResponse, WSMsgType

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    IOS_USER_AGENT,
    IOS_X_API_KEY,
    REST_POLL_INTERVAL,
    URL_API,
    URL_API_LOGIN,
    URL_API_WSS,
    URL_CIELO,
    USER_AGENT,
    WEB_X_API_KEY,
    WSS_INITIAL_RETRY_DELAY,
    WSS_MAX_RETRY_DELAY,
)

_LOGGER = logging.getLogger(__name__)

TIMEOUT_RECONNECT = 10
TIME_REFRESH_TOKEN = 3300
TIMER_PING = 540
TIMER_PONG = 60

_URL_SECRET_RE = re.compile(
    r"([?&](?:token|access_token|refresh_token)=)[^&\s'\"]+", re.IGNORECASE
)


def _redact_url_secrets(value: object) -> str:
    """Return an exception-safe representation without bearer tokens."""
    return _URL_SECRET_RE.sub(r"\1***", str(value))

# TIME_REFRESH_TOKEN = 20
# TIMER_PING = 100


class CieloHome:
    """Set up Cielo Home api."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Set up Cielo Home api."""
        self.can_reload: bool = True
        self._is_running: bool = True
        self._stop_running: bool = False
        self._access_token: str = ""
        self._refresh_token: str = ""
        self._session_id: str = ""
        self._user_id: str = ""
        self._mobile_device_id: str = ""
        # self._user_name: str = ""
        # self._password: str = ""
        self._headers: dict[str, str] = {}
        self._websocket: ClientWebSocketResponse
        self._ws_session: ClientSession
        self.__event_listener: list[object] = []
        self._msg_to_send: list[object] = []
        self._msg_lock = Lock()
        self._timer_connection_lost: Timer = None
        self._last_refresh_token_ts: int
        self._token_expire_in_ts: int
        self._last_ts_msg: int = 0
        self._last_ts_ping: int = 0
        self._last_ts_pong: int = 0
        self._last_connection_ts: int = 0
        self._last_x_api_key: str = None
        self._stop_event = asyncio.Event()
        self._poll_task: asyncio.Task | None = None
        self._wss_retry_delay = WSS_INITIAL_RETRY_DELAY
        self._wss_rate_limited = False
        self.hass: HomeAssistant = hass
        self._entry: ConfigEntry = entry
        self._appliance_id = None
        self.background_tasks_wss = set()
        self._headers = {
            "content-type": "application/json; charset=UTF-8",
            "referer": URL_CIELO,
            "origin": URL_CIELO,
            "user-agent": USER_AGENT,
            "host": URL_API,
        }

    async def close(self):
        """None."""
        self._stop_running = True
        self._is_running = False
        self._stop_event.set()
        if self._poll_task is not None:
            self._poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._poll_task
        await asyncio.sleep(0.5)

    def add_listener(self, listener: object):
        """None."""
        self.__event_listener.append(listener)

    async def async_auth(
        self,
        access_token: str,
        refresh_token: str,
        session_id: str,
        user_id: str,
        x_api_key: str,
        mobile_device_id: str = "",
    ) -> bool:
        """Set up Cielo Home auth."""

        self._access_token = access_token
        self._refresh_token = refresh_token
        self._session_id = session_id
        self._user_id = user_id
        self._last_x_api_key = x_api_key
        self._mobile_device_id = mobile_device_id

        self._last_refresh_token_ts = self.get_ts()
        self._token_expire_in_ts = self.get_ts() + TIME_REFRESH_TOKEN

        if not await self.async_refresh_token(test=True):
            return False

        self._start_rest_polling()
        self.create_websocket_log_exception(False)
        return True

    async def async_refresh_token(
        self,
        access_token: str = "",
        refresh_token: str = "",
        session_id: str = "",
        user_id: str = "",
        x_api_key: str = "",
        test: bool = False,
    ) -> bool:
        """Set up Cielo Home refresh."""
        _LOGGER.debug("Call refreshToken %s", x_api_key)

        # Opening JSON file
        # fullpath: str = str(pathlib.Path(__file__).parent.resolve()) + "/login.json"
        # file = open(fullpath)

        # # returns JSON object as
        # # a dictionary
        # data = json.load(file)
        # # Iterating through the json
        # # list
        # access_token = data["data"]["user"]["accessToken"]
        # refresh_token = data["data"]["user"]["refreshToken"]
        # self._session_id = data["data"]["user"]["sessionId"]
        # file.close()
        try:
            if test:
                self._last_refresh_token_ts = self.get_ts()
                self._token_expire_in_ts = self.get_ts() + TIME_REFRESH_TOKEN

            if access_token != "":
                self._access_token = access_token
                self._refresh_token = refresh_token
                self._session_id = session_id
                self._user_id = user_id
                self._last_x_api_key = x_api_key

            headers: dict[str, str] = self._headers
            headers["authorization"] = self._access_token
            headers["x-api-key"] = self._last_x_api_key

            data = {
                "local": "en",
                "refreshToken": self._refresh_token,
            }
            async with ClientSession() as session:  # noqa: SIM117
                async with session.post(
                    "https://" + URL_API + "/web/token/refresh",
                    headers=self._headers,
                    json=data,
                ) as response:
                    if response.status == 200:
                        repjson = await response.json()
                        if repjson["status"] == 200 and repjson["message"] == "SUCCESS":
                            self._access_token = repjson["data"]["accessToken"]
                            self._refresh_token = repjson["data"]["refreshToken"]
                            # Cielo's web app accepts a key returned by the
                            # login/refresh response. Prefer it over the
                            # bundled fallback so a server-side key rotation
                            # does not strand an existing config entry.
                            response_api_key = repjson["data"].get("x-api-key")
                            if response_api_key:
                                self._last_x_api_key = response_api_key
                            expire: int = int(repjson["data"]["expiresIn"]) - 300
                            if (
                                expire < self._token_expire_in_ts
                                or expire < self.get_ts()
                            ):
                                self._token_expire_in_ts = (
                                    self.get_ts() + TIME_REFRESH_TOKEN
                                )
                            else:
                                self._token_expire_in_ts = expire

                            if not test:
                                if self._entry is not None:
                                    config_data = self._entry.data.copy()
                                    config_data["access_token"] = self._access_token
                                    config_data["refresh_token"] = self._refresh_token
                                    config_data["x_api_key"] = self._last_x_api_key
                                    self.can_reload = False
                                    self.hass.config_entries.async_update_entry(
                                        self._entry, data=config_data
                                    )
                                _LOGGER.debug("Call refreshToken success")
                                await self._ws_session.close()
                                self._last_refresh_token_ts = self.get_ts()
                            else:
                                _LOGGER.debug("Call test refreshToken success")
                            return True
                    else:
                        _LOGGER.error("Call refreshToken error %s", response.status)
        except Exception as err:
            _LOGGER.error("Call refreshToken failed: %s", _redact_url_secrets(err))

        return False

    async def async_login(self, user_id: str, password: str) -> dict | None:
        """Log in with email + password via the mobile endpoint (no captcha).

        Returns the token bundle the config entry needs, or None on failure.
        The password is sent as a SHA-256 hash, matching the apps. Login uses
        the iOS app key; the returned bundle uses the WEB key, which is what the
        integration's /web/* endpoints require.
        """
        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        mobile_device_id = uuid.uuid4().hex[:8].upper()
        payload = {
            "user": {
                "isDeviceCountRequired": 1,
                "isSmartHVAC": 1,
                "ipAddress": "",
                "deviceTokenId": "N/A",
                "mobileDeviceId": mobile_device_id,
                "deviceType": "iPhone17,1",
                "appType": "iOS",
                "userId": user_id,
                "password": pwd_hash,
                "timeZone": "-04:00",
                "mobileDeviceName": "iPhone",
                "locale": "en",
                "appVersion": "4.3.0",
            }
        }
        headers = {
            "accept": "*/*",
            "content-type": "application/json",
            "x-api-key": IOS_X_API_KEY,
            "user-agent": IOS_USER_AGENT,
        }
        try:
            async with ClientSession() as session:  # noqa: SIM117
                async with session.post(
                    "https://" + URL_API + "/" + URL_API_LOGIN,
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.status != 200:
                        _LOGGER.error("Cielo login HTTP %s", response.status)
                        return None
                    repjson = await response.json()
                    if repjson.get("status") != 200:
                        _LOGGER.error(
                            "Cielo login failed: %s", repjson.get("message")
                        )
                        return None
                    data = repjson["data"]
                    user = data["user"]
                    # The mobile login does not return a sessionId; generate a
                    # client-side identifier for the websocket (the web app uses
                    # "<deviceName>-<timestamp>").
                    session_id = user.get("sessionId") or (
                        "ha-" + str(int(datetime.now().timestamp() * 1000))
                    )
                    return {
                        "access_token": user["accessToken"],
                        "refresh_token": user["refreshToken"],
                        "session_id": session_id,
                        "user_id": user["userId"],
                        "x_api_key": data.get("x-api-key") or WEB_X_API_KEY,
                        "mobile_device_id": mobile_device_id,
                    }
        except Exception as err:
            _LOGGER.error("Cielo login failed: %s", _redact_url_secrets(err))
        return None

    def _start_rest_polling(self) -> None:
        """Start the REST state poller once for this config entry."""
        if self._poll_task is None or self._poll_task.done():
            self._poll_task = self.hass.async_create_task(self._async_poll_loop())

    async def _async_poll_loop(self) -> None:
        """Refresh state through REST while WebSocket availability is uncertain."""
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(), timeout=REST_POLL_INTERVAL
                )
                break
            except TimeoutError:
                pass

            try:
                await self.update_state_device()
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("REST state refresh failed: %s", _redact_url_secrets(err))

    async def async_connect_wss(self, update_state: bool = False):
        """None."""
        headers_wss = {
            "Host": URL_API_WSS,
            "Cache-control": "no-cache",
            "Pragma": "no-cache",
            "User-agent": USER_AGENT,
        }

        wss_uri = "wss://" + URL_API_WSS + "/websocket/"

        self._is_running = True
        self._stop_running = False
        try:
            async with ClientSession() as ws_session:
                self._ws_session = ws_session
                async with ws_session.ws_connect(
                    wss_uri,
                    headers=headers_wss,
                    params={
                        "sessionId": self._session_id,
                        "token": self._access_token,
                    },
                    origin=URL_CIELO[:-1],
                    compress=15,
                    autoping=False,
                ) as websocket:
                    self._websocket = websocket
                    if self._last_ts_ping == 0:
                        self._last_ts_ping = self.get_ts()
                        self._last_ts_pong = self._last_ts_ping + TIMER_PONG

                    _LOGGER.info("Connected success")
                    self._last_connection_ts = self.get_ts()
                    self._wss_retry_delay = WSS_INITIAL_RETRY_DELAY
                    self._wss_rate_limited = False
                    self.stop_timer_connection_lost()

                    if update_state:
                        self.create_task_log_exception(
                            self.update_state_device(), False
                        )
                    # self.start_timer_ping()
                    while self._is_running:
                        now: int = self.get_ts()

                        try:
                            msg = await self._websocket.receive(timeout=0.1)
                            if msg.type in (
                                WSMsgType.CLOSE,
                                WSMsgType.CLOSED,
                                WSMsgType.CLOSING,
                                WSMsgType.ERROR,
                            ):
                                # self._timer_ping.cancel()
                                _LOGGER.debug("Websocket closed : %s", msg.type)
                                break

                            try:
                                js_data = json.loads(msg.data)
                                if _LOGGER.isEnabledFor(logging.DEBUG):
                                    debug_data = copy.copy(js_data)
                                    if hasattr(debug_data, "accessToken"):
                                        debug_data["accessToken"] = "*****"
                                    if hasattr(debug_data, "refreshToken"):
                                        debug_data["refreshToken"] = "*****"
                                    _LOGGER.debug(
                                        "Receive Json : %s", json.dumps(debug_data)
                                    )

                                with contextlib.suppress(Exception):
                                    if js_data["message"] == "Internal server error":
                                        self._last_ts_pong = self.get_ts() + 1

                                with contextlib.suppress(Exception):
                                    if (
                                        js_data["message_type"] == "StateUpdate"
                                        or js_data["message_type"]
                                        == "DeviceSettingsAck"
                                        or js_data["message_type"]
                                        == "CalibrationAck"
                                    ):
                                        for listener in self.__event_listener:
                                            listener.data_receive(js_data)

                            except ValueError:
                                pass

                        except asyncio.exceptions.TimeoutError:
                            pass
                        except asyncio.exceptions.CancelledError:
                            pass

                        if now > (self._token_expire_in_ts):
                            self._token_expire_in_ts = now + 60
                            self.create_task_log_exception(self.async_refresh_token())
                        elif now - self._last_ts_ping >= TIMER_PING:
                            self._last_ts_ping = now
                            self._last_ts_pong = now
                            self.send_json("ping")
                        elif (
                            now > (self._last_ts_pong + TIMER_PONG)
                        ) and self._last_ts_pong == self._last_ts_ping:
                            self._is_running = False

                        msg: object = None
                        if len(self._msg_to_send) > 0:
                            with self._msg_lock:
                                try:
                                    while len(self._msg_to_send) > 0:
                                        msg = self._msg_to_send.pop(0)
                                        if msg == "ping":
                                            _LOGGER.debug("Send text : ping")
                                            await self._websocket.send_str(msg)
                                        else:
                                            if _LOGGER.isEnabledFor(logging.DEBUG):
                                                debug_data = copy.copy(msg)
                                                # debug_data["token"] = "*****"
                                                _LOGGER.debug(
                                                    "Send Json : %s",
                                                    json.dumps(debug_data),
                                                )

                                            await self._websocket.send_json(msg)

                                        msg = None
                                        await asyncio.sleep(0.1)
                                except Exception:
                                    _LOGGER.error("Failed to send Json")
                                    if msg is not None:
                                        self._msg_to_send.insert(0, msg)

        except Exception as err:
            status = getattr(err, "status", None)
            headers = getattr(err, "headers", {}) or {}
            retry_after = headers.get("Retry-After")
            if status == 429:
                self._wss_rate_limited = True
                try:
                    retry_delay = int(retry_after) if retry_after else 0
                except (TypeError, ValueError):
                    retry_delay = 0
                self._wss_retry_delay = min(
                    WSS_MAX_RETRY_DELAY,
                    max(retry_delay, self._wss_retry_delay * 2),
                )
                _LOGGER.warning(
                    "Cielo WebSocket is rate-limited; continuing REST polling and retrying in %s seconds",
                    self._wss_retry_delay,
                )
            else:
                self._wss_retry_delay = min(
                    WSS_MAX_RETRY_DELAY,
                    max(WSS_INITIAL_RETRY_DELAY, self._wss_retry_delay * 2),
                )
                _LOGGER.error("Cielo WebSocket failed: %s", _redact_url_secrets(err))

        if hasattr(self, "_ws_session") and not self._ws_session.closed:
            # self._timer_ping.cancel()
            await self._ws_session.close()

        if hasattr(self, "_websocket") and not self._websocket.closed:
            # self._timer_ping.cancel()
            await self._websocket.close()

        if not self._stop_running:
            # A 429 describes Cielo's WebSocket service, not the controller's
            # reachability. Keep entities available while the REST poller can
            # still obtain state.
            if not self._wss_rate_limited:
                self.start_timer_connection_lost()
            _LOGGER.debug(
                "Retrying Cielo WebSocket in %s seconds", self._wss_retry_delay
            )
            await asyncio.sleep(self._wss_retry_delay)
            self._last_ts_ping = 0
            if self.get_ts() > self._token_expire_in_ts:
                if not await self.async_refresh_token():
                    _LOGGER.warning("Cielo token refresh failed; retaining REST polling")
            self.create_websocket_log_exception(True)

    def send_action(self, msg, device: dict | None = None) -> None:
        """Send an action, using Cielo's mobile REST fallback when needed."""
        # msg["token"] = self._access_token
        with contextlib.suppress(KeyError):
            if msg["mid"] == "":
                msg["mid"] = self._session_id

        msg["ts"] = self.get_ts()

        # to be sure each msg have different ts, when 2 msg are send quickly
        if msg["ts"] == self._last_ts_msg:
            msg["ts"] = msg["ts"] + 1

        self._last_ts_msg = msg["ts"]

        # Cielo currently rate-limits the legacy WebSocket used by this
        # integration. The current mobile client has a REST command endpoint
        # for its mini-split widget. It supports the basic controls exposed by
        # Home Assistant, and unlike the socket it provides a response for the
        # attempted command. Do not queue commands while rate-limited: an old
        # power or temperature request must not run much later after recovery.
        if self._wss_rate_limited:
            if device is not None and self._mobile_device_id:
                # Entity service methods may be invoked from an executor
                # thread. add_job is Home Assistant's thread-safe handoff to
                # the event loop; async_create_task is not safe here.
                self.hass.add_job(self.async_send_widget_action(msg, device))
            else:
                _LOGGER.warning(
                    "Cielo command dropped while WebSocket is rate-limited; "
                    "reconfigure the integration to enable the mobile REST fallback"
                )
            return

        self.send_json(msg)

    async def async_send_widget_action(self, msg: dict, device: dict) -> None:
        """Send a basic mini-split action through Cielo's mobile REST API."""
        action_type = msg.get("actionType")
        if msg.get("action") != "actionControl" or action_type not in {
            "power",
            "mode",
            "temp",
        }:
            _LOGGER.warning(
                "Cielo command %s is unavailable while WebSocket is rate-limited",
                action_type or msg.get("action"),
            )
            return

        device_id = device.get("deviceId")
        if not device_id:
            _LOGGER.warning(
                "Cielo mobile REST fallback needs deviceId; command was not sent"
            )
            return

        actions = msg.get("actions", {})
        action_payload = {
            "power": actions.get("power"),
            "mode": actions.get("mode"),
            "temp": str(actions["temp"])
            if actions.get("temp") is not None
            else None,
            "actionType": action_type,
        }
        # iOS omits unavailable widget fields rather than sending JSON null.
        action_payload = {
            key: value for key, value in action_payload.items() if value is not None
        }
        payload = {
            "macAddress": device.get("macAddress"),
            "deviceName": device.get("deviceName"),
            "mobileDeviceId": self._mobile_device_id,
            "deviceId": str(device_id),
            "userId": self._user_id,
            "actionSource": "iOS",
            "actions": action_payload,
        }
        headers = {
            "accept": "*/*",
            "authorization": self._access_token,
            "content-type": "application/json",
            "x-api-key": IOS_X_API_KEY,
            "user-agent": IOS_USER_AGENT,
        }

        try:
            async with ClientSession() as session:
                async with session.post(
                    "https://" + URL_API + "/device/perform-widget-action/1",
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.status != 200:
                        _LOGGER.warning(
                            "Cielo mobile REST command failed with HTTP %s",
                            response.status,
                        )
                        return
                    result = await response.json()
                    if result.get("status") not in (None, 200):
                        _LOGGER.warning(
                            "Cielo mobile REST command failed: %s",
                            result.get("message", "unknown response"),
                        )
                        return
                    self._apply_widget_action_result(device, result.get("data"))
                    _LOGGER.debug("Cielo mobile REST command accepted")
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning(
                "Cielo mobile REST command failed: %s", _redact_url_secrets(err)
            )

    def _apply_widget_action_result(
        self, device: dict, response_data: object
    ) -> None:
        """Apply Cielo's command acknowledgement before the next REST poll.

        The widget endpoint returns the accepted ``latestAction`` immediately,
        while ``/web/devices`` can lag behind it. Applying the acknowledgement
        prevents an optimistic Home Assistant state from being overwritten by
        a stale REST response just after a successful command.
        """
        if not isinstance(response_data, dict):
            return

        latest_action = response_data.get("latestAction")
        if isinstance(latest_action, dict):
            device.setdefault("latestAction", {}).update(latest_action)

        if "deviceStatus" in response_data:
            device["deviceStatus"] = response_data["deviceStatus"]

        mac_address = device.get("macAddress")
        for listener in self.__event_listener:
            if listener.get_mac_address() == mac_address:
                listener.state_device_receive(device)

    def start_timer_connection_lost(self):
        """None."""
        self._timer_connection_lost = Timer(
            TIMEOUT_RECONNECT + 2, self.dispatch_connection_lost
        )
        self._timer_connection_lost.start()  # Here run is called

    def stop_timer_connection_lost(self):
        """None."""
        if self._timer_connection_lost:
            self._timer_connection_lost.cancel()
            self._timer_connection_lost = None

    def dispatch_connection_lost(self):
        """None."""
        for listener in self.__event_listener:
            listener.lost_connection()

    def send_json(self, data):
        """None."""
        with self._msg_lock:
            try:
                self._msg_to_send.append(data)
            except Exception:
                _LOGGER.error(sys.exc_info()[1])

    def get_ts(self) -> int:
        """None."""
        return int(datetime.now().timestamp())
        # return int((datetime.utcnow() - datetime.fromtimestamp(0)).total_seconds())

    async def async_get_devices(self):
        """None."""
        devices = await self.async_get_thermostats()
        devicesNotSupported = []

        appliance_ids = ""
        unique_appliance_ids = set()  # Use a set to track unique appliance IDs

        if devices is not None:
            for device in devices:
                appliance_id: str = str(device["applianceId"])
                if appliance_id in ("0", ""):
                    devicesNotSupported.append(device)
                    continue

                # Only add to appliance_ids string if we haven't seen this appliance ID before
                if appliance_id not in unique_appliance_ids:
                    unique_appliance_ids.add(appliance_id)
                    if appliance_ids != "":
                        appliance_ids = appliance_ids + ","
                    appliance_ids = appliance_ids + str(appliance_id)

            appliances = await self.async_get_thermostat_info(appliance_ids)

            if len(devicesNotSupported) > 0:
                for device in devicesNotSupported:
                    _LOGGER.warning(
                        "Device '"
                        + str(device["deviceName"])
                        + "' not supported, invalid appliance '"
                        + str(device["applianceId"])
                        + "'"
                    )
                    devices.remove(device)

            # Attach appliance data to ALL devices, even those sharing the same appliance ID
            for device in devices:
                device_appliance_id = device["applianceId"]
                appliance_attached = False
                for appliance in appliances:
                    if appliance["applianceId"] == device_appliance_id:
                        device["appliance"] = appliance
                        appliance_attached = True
                        break

                # If no appliance data was found, log a warning
                if not appliance_attached:
                    _LOGGER.warning(
                        "No appliance data found for device '%s' with appliance ID %s",
                        device.get("deviceName", "Unknown"),
                        device_appliance_id,
                    )

            return devices

        return []

    async def update_state_device(self):
        """None."""
        devices = await self.async_get_thermostats()
        for listener in self.__event_listener:
            for device in devices:
                if device["macAddress"] == listener.get_mac_address():
                    if self._is_stale_rest_state(listener.get_device(), device):
                        _LOGGER.debug(
                            "Ignoring stale Cielo REST state for %s",
                            device["macAddress"],
                        )
                        continue
                    listener.state_device_receive(device)

    @staticmethod
    def _is_stale_rest_state(current_device: dict, polled_device: dict) -> bool:
        """Return whether a REST response predates the current device action."""
        try:
            current_timestamp = int(current_device["latestAction"]["timestamp"])
            polled_timestamp = int(polled_device["latestAction"]["timestamp"])
        except (KeyError, TypeError, ValueError):
            return False
        return polled_timestamp < current_timestamp

    async def async_get_thermostats(self):
        """Get de the list Devices/Thermostats."""
        if self._last_x_api_key is None:
            await self.async_refresh_token()

        self._headers["authorization"] = self._access_token
        self._headers["x-api-key"] = self._last_x_api_key
        devices = None

        # Retry logic for API calls
        max_retries = 3
        for attempt in range(max_retries):
            try:
                async with ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as session:
                    async with session.get(
                        "https://" + URL_API + "/web/devices?limit=420",
                        headers=self._headers,
                    ) as response:
                        if response.status == 200:
                            repjson = await response.json()
                            if (
                                repjson["status"] == 200
                                and repjson["message"] == "SUCCESS"
                            ):
                                devices = repjson["data"]["listDevices"]
                                if _LOGGER.isEnabledFor(logging.DEBUG):
                                    _LOGGER.debug("devices : %s", json.dumps(devices))
                                break
                            else:
                                _LOGGER.warning(
                                    f"API returned error: {repjson.get('message', 'Unknown error')}"
                                )
                        elif response.status == 401:
                            _LOGGER.info("Unauthorized, refreshing token...")
                            if await self.async_refresh_token():
                                self._headers["authorization"] = self._access_token
                                continue
                            else:
                                _LOGGER.error("Failed to refresh token")
                                break
                        else:
                            _LOGGER.warning(
                                f"HTTP {response.status}: {await response.text()}"
                            )

            except asyncio.TimeoutError:
                _LOGGER.warning(f"Timeout on attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2**attempt)  # Exponential backoff
            except Exception as e:
                _LOGGER.error(
                    f"Error getting devices on attempt {attempt + 1}/{max_retries}: {e}"
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(2**attempt)  # Exponential backoff

        devices_supported: list = []

        if devices is not None:
            for device in devices:
                try:
                    appliance_id: str = str(device.get("applianceId", ""))
                    if appliance_id and appliance_id != "0":
                        devices_supported.append(device)
                    else:
                        _LOGGER.warning(
                            f"Device {device.get('deviceName', 'Unknown')} has invalid appliance ID: {appliance_id}"
                        )
                except Exception as e:
                    _LOGGER.error(f"Error processing device: {e}")
                    continue

        return devices_supported

    async def async_get_thermostat_info(self, appliance_ids):
        """Get de the list Devices/Thermostats."""
        # https://api.smartcielo.com/web/sync/db/6?applianceIdList=[1674]
        self._headers["authorization"] = self._access_token
        self._headers["x-api-key"] = self._last_x_api_key
        async with ClientSession() as session:  # noqa: SIM117
            async with session.get(
                "https://"
                + URL_API
                + "/web/sync/db/6?applianceIdList=["
                + appliance_ids
                + "]",
                headers=self._headers,
            ) as response:
                if response.status == 200:
                    repjson = await response.json()
                    if repjson["status"] == 200 and repjson["message"] == "SUCCESS":
                        appliances = repjson["data"]["listAppliances"]
                        if _LOGGER.isEnabledFor(logging.DEBUG):
                            _LOGGER.debug("appliances : %s", json.dumps(appliances))
                        return appliances
                else:
                    pass
        return []

    def create_websocket_log_exception(self, update_state: bool = True) -> asyncio.Task:
        """None."""
        task = asyncio.create_task(_log_exception(self.async_connect_wss(update_state)))
        self.background_tasks_wss.add(task)
        task.add_done_callback(self.call_back_task)
        return task

    def call_back_task(self, task: asyncio.Task):
        """None."""
        self.background_tasks_wss.remove(task)

    def create_task_log_exception(
        self, awaitable: Awaitable, long_running: bool = True
    ) -> asyncio.Task:
        """None."""

        task = asyncio.create_task(_log_exception(awaitable))
        if long_running:
            self.background_tasks_wss.add(task)
            task.add_done_callback(self.call_back_task)
        return task


async def _log_exception(awaitable):
    try:
        return await awaitable
    except Exception as err:
        _LOGGER.error("Cielo background task failed: %s", _redact_url_secrets(err))
