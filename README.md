# Rizin Silhouette Client

This is a rizin plugin which fetches symbols and hints from a remote server and applies the received data to the current opened binary.

For more info about the server please check the repo [rz-silhouette-server](https://github.com/rizinorg/rz-silhouette-server)

## Public Servers

- [eu-symbols.rizin.re](https://eu-symbols.rizin.re)

## Setup

To use the server, add the following lines to your `.rizinrc`

```
e silhouette.enable=true
e silhouette.psk=<user pre-shared-key>
e silhouette.host=<server>
e silhouette.port=<port>
# available only if rizin was built with openssl
e silhouette.tls=true
```

The client uses a single Cap'n Proto protocol.
Cap'n Proto changes serialization only. On the raw TCP port the PSK is still sent in clear text, so use `e silhouette.tls=true` against a TLS listener when confidentiality matters.

To test if the credentials are correct, you can open rizin and execute the following command.
```
[0x00000000]> sil test

silhouette server: protocol 1, tls=optional
response delay: 2.5ms
```

## Compilation

Install Meson, Ninja, the `capnp` tool, and Rizin development files first, then build from a clean checkout:

```sh
meson setup builddir
meson compile -C builddir
meson install -C builddir
```

If `rz_core` is not available through `pkg-config`, pass the Rizin installation prefix explicitly:

```sh
meson setup builddir -Drizin_root=/path/to/rizin/prefix
```

The client Cap'n Proto C bindings are generated at build time from `src/service.capnp`. Meson uses the bundled `c-capnproto` generator by default; `-Duse_sys_capnp_c=enabled` can be used when a system CapnC runtime and `capnpc-c` are already installed.

## Documentation

Documentation is available [here](https://github.com/rizinorg/rz-silhouette/tree/main/docs)
