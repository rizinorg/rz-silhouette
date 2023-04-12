# Rizin Silhouette Protocol

The protocol implemented is quite simple on purpose to optimize the number of bytes sent and received by the server.

1. Each packet always start with its size which is store in a a 32 bit unsigned word (big-endian)
2. The packet is encoded using the protobuf format; the reason behind this is to compress as much as possible the data and make the transfer as fast as possible between client and server.
3. The `client` will always send a pre-shared-key, the protocol version, the type of request (also known in the protocol as `route`) and the encoded data needed by the route.
4. The `server` will close the connection without replying if the size of the packet exeeds the max size defined in the server settings.
5. The `server` will always reply with a status code, and the encoded data linked to its status.
6. The `server` uses the pre-shared-key sent by the client to determine who can and cannot upload new data to the server.

For more information please check the `service.proto` file available in both client and server repository.
