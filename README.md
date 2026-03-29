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

Install Meson, Ninja, and Rizin development files first, then build from a clean checkout:

```sh
meson setup builddir
meson compile -C builddir
meson install -C builddir
```

If `rz_core` is not available through `pkg-config`, pass the Rizin installation prefix explicitly:

```sh
meson setup builddir -Drizin_root=/path/to/rizin/prefix
```

The client ships tracked Cap'n Proto C bindings in `src/service.capnp.c` and `src/service.capnp.h`, and it vendors the Cap'n Proto C runtime sources used by the plugin. Normal builds therefore do not require the `capnp` compiler, `capnpc-c`, or a system CapnC package.

If `src/service.capnp` changes, just regenerate those two files. The repository CI checks that the tracked generated files stay in sync with the schema.

One way to regenerate them manually is:

```sh
meson subprojects download c-capnproto
meson setup .ci/capnpc-build subprojects/c-capnproto -Ddefault_library=static -Denable_tests=false
meson compile -C .ci/capnpc-build capnpc-c
capnp compile --src-prefix=src -Isrc -o .ci/capnpc-build/capnpc-c:src src/service.capnp
```

## Documentation

Documentation is available [here](https://github.com/rizinorg/rz-silhouette/tree/main/docs)
