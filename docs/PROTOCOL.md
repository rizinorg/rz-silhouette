# Rizin Silhouette Protocol

The protocol is intentionally small and simple to minimize transport overhead for exact-match resolve and share operations.

1. Each packet starts with its size stored as a 32-bit unsigned big-endian integer.
2. The packet body starts with the `SILC` magic and then carries a packed Cap'n Proto payload.
3. The `client` always sends a pre-shared key, the protocol version, the request route, and the exact-match bundle required by that route.
4. The `server` closes the connection without replying if the packet exceeds the configured maximum size.
5. The `server` always replies with a status code and the data linked to that status.
6. The `server` uses the pre-shared key to decide who may upload new data.

For the concrete message definitions, see `src/service.capnp` in the client repository and `servicecapnp/service.capnp` in the server repository.
