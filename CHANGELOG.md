# Changelog

## Unreleased

- Keep devices available through REST polling when Cielo rate-limits the legacy WebSocket service.
- Use Cielo's mobile widget REST endpoint for basic power, mode, and temperature controls during a WebSocket rate limit.
- Apply command acknowledgements immediately and ignore stale REST state responses.
- Add temperature offset calibration as a Number entity per supporting device, plus a `cielo_home.set_temperature_offset` service on climate entities. Per-call magnitude is capped at 8 by the protocol, so reaching the extremes of the ±15 range may require multiple calls.

## 1.0.0

- First version support for Cielo Home
