# WebSocket rate-limit fallback

## Problem

Beginning on 2026-07-10, multiple users reported that Cielo Home entities
cycled between available and unavailable. The common error was an HTTP 429
while connecting to `wss://apiwss.smartcielo.com/websocket/`. In at least one
report, the next token-refresh request was rejected with HTTP 403.

The existing reconnect path amplified that outage:

1. The WebSocket connection failed.
2. After a fixed 10-second delay, the integration marked every device
   unavailable.
3. It refreshed the token regardless of the token expiry time.
4. It immediately opened another WebSocket connection.

This produced a repeated refresh/reconnect cycle and exposed the WebSocket
token in exception messages because the token is part of the connection URL.

## Implementation

The integration now uses REST polling as the state transport when the legacy
WebSocket is unavailable, while retaining WebSockets for push updates and
commands when Cielo accepts a connection.

### REST state polling

After authentication, `CieloHome` starts one background task. Every 120
seconds it calls the existing `/web/devices` request through
`update_state_device()`. Returned state is matched to each in-memory device by
MAC address and forwarded through the existing `state_device_receive()` path.
No new Cielo endpoint is introduced.

### 429-aware WebSocket reconnection

The WebSocket exception handler reads `status` and `Retry-After` from the
aiohttp exception. For HTTP 429 it:

- does not invoke `lost_connection()` or set `deviceStatus` to offline;
- continues REST polling;
- retries with exponential backoff, starting at 60 seconds and capped at 15
  minutes; and
- refreshes the access token only if the known token expiry time has passed.

Non-429 WebSocket failures retain the existing unavailable behavior, but use
the same bounded backoff instead of a tight retry loop.

### Credential and logging safeguards

The mobile-login and refresh handlers now prefer an `x-api-key` returned by
Cielo over the bundled fallback key. This maintains compatibility if Cielo
rotates the key associated with the session.

The WebSocket and background-task error paths redact `token`, `access_token`,
and `refresh_token` URL parameters before logging them.

### Mobile REST command fallback

The current Android Cielo Home app contains a mini-split widget command path:
`POST /device/perform-widget-action/1`. Its request supports `power`, `mode`,
and `temp` actions and returns the resulting state. The integration uses this
path only while the WebSocket is rate-limited, and only for those three basic
actions. Switches such as fan speed, swing, turbo, light, and follow-me remain
WebSocket-only.

The endpoint requires the mobile device ID supplied during the mobile login.
The previous config flow generated that ID but did not retain it. The updated
flow stores `mobile_device_id` with the config entry so it can submit the
fallback command. Existing entries can use Home Assistant's **Reconfigure**
action after installing this revision; the flow asks for Cielo credentials,
registers a fresh HA mobile client, verifies the REST token, and replaces the
entry data atomically. Commands are deliberately not queued while rate-limited:
an old power or temperature change must never be applied after a long
server-side recovery.

## Validation

### Isolated Home Assistant smoke test

The patched custom component was mounted read-only into a disposable Home
Assistant Core 2026.7.2 container. Home Assistant started successfully, and
the integration module imported successfully inside the container.

A targeted mocked WebSocket test simulated an aiohttp-style HTTP 429 handshake
failure. It verified that the integration:

- records the rate-limited state;
- changes the first retry delay from 30 to 60 seconds;
- schedules a later WebSocket attempt; and
- does **not** invoke token refresh for that 429.

The same test verifies the mobile REST fallback request shape, including the
stored mobile device ID and the power/mode/temperature action payload. It does
not claim a live command result yet.

### Personal Home Assistant device test

The patch was manually deployed to a personal Home Assistant OS installation
that uses this custom integration version 1.9.1. It has two Cielo Breez Plus
devices (`BREEZ-PLUS`, hardware version `BP01`) and 26 entities.

Deployment preserved the original custom component outside of
`custom_components` and restarted Home Assistant. This placement matters:
Home Assistant treats every directory directly inside `custom_components` as
an integration, so a backup must not remain there.

At deployment time the integration loaded and the devices/entities were
present. The meaningful live test is ongoing: during a Cielo WebSocket 429,
the entities must remain available and refresh through REST within roughly two
minutes rather than repeatedly toggling unavailable.

For this command-fallback revision, use the Cielo Home entry's **Reconfigure**
action after the component is updated. Test a power, mode, and temperature
change while the WebSocket remains rate-limited. The mobile app is the control
comparison: it must still act immediately, and Home Assistant must report
either a successful REST command or a clear failure in the log rather than
silently queueing the command.

On 2026-07-12, an independent new connection using an active Cielo dashboard
WebSocket URL (including the dashboard-provided `sessionId` and access token)
also received HTTP 429. Therefore the documented workaround must not assume
that changing the integration's synthetic session ID will restore the legacy
WebSocket. The server is refusing new WebSocket connections at that time.

## Rollback

Stop Home Assistant, remove `custom_components/cielo_home`, restore the saved
component directory into `custom_components/cielo_home`, and start Home
Assistant again. Do not leave the backup directory directly under
`custom_components`.
