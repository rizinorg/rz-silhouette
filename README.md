# Rizin Silhouette Client

This is a rizin plugin which fetches symbols and hints from a remote server and applies the received data to the current opened binary.

For more info about the server please check the repo [rz-silhouette-server](https://github.com/rizinorg/rz-silhouette-server)

## Public Servers

- [eu-symbols.rizin.re](https://eu-symbols.rizin.re)

## Setup

To setup the server, just add the following lines to your `.rizinrc`

```
e silhouette.enable=true
e silhouette.psk=<user pre-shared-key>
e silhouette.host=<server>
e silhouette.port=<port>
# available only if rizin was built with openssl
e silhouette.tls=true
```

To test if the credentials are correct, you can open rizin and execute the following command.
```
[0x00000000]> sil test

Hello World from the server!
response delay: 2.5ms
```

## Dependencies

To build this tool, it requires `libprotobuf-c` and `pthreads`
