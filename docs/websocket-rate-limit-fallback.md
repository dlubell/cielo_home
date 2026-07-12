# REST continuity during Cielo WebSocket rate limits

The integration still uses Cielo's legacy WebSocket whenever it is available.
Some accounts receive HTTP 429 responses when opening that socket. A 429 means
the socket service is rate-limited; it does not mean the controller is offline.

When that happens, the integration:

- backs off WebSocket reconnect attempts;
- keeps device state current through the existing REST device endpoint; and
- sends basic power, mode, and temperature controls through Cielo's mobile
  widget endpoint.

The widget command response includes the accepted `latestAction`. The
integration applies that response immediately. If a subsequent REST poll has
an older action timestamp, it is ignored so a delayed cloud response cannot
undo a successful command in Home Assistant.

This path has been validated against Cielo Breez Plus BP01 controllers. It is
slower than a live socket connection because commands and state updates travel
through Cielo's cloud. Advanced controls continue to use the WebSocket path
and are unavailable while that service is rate-limited.
