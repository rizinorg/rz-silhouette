# Signature Format

## Client side

The **client** has to generate a masked pattern which is then hashed.

1. Read the bytes from the function entry address to the highest basic block address in a linear way.
2. The bytes read needs to be masked to remove any static address which might be embedded by one or multiple instructions.
3. The masked bytes needs then to be hashed; in the silhouette client we use `blake3`, but potentially any hash function (like `md5`) can be used.
4. As part of the signature we also collect the architecture name, bits and the number of bytes read to make the signature more unique.

## Server side

On the `server` side we use the received data from the client to query a database and return the following info as response:

 - Symbol name (for example: `foo`; on Rizin/Cutter it will match to `sym.foo`).
 - Function signature (for example: `int foo(double bar);`).
 - Call convention (for example: `cdecl`, `fastcall`, etc..)
 - Architecture bits (this is useful for some archs to distinguish between different modes, like `arm` which has `arm mode` and `thumb mode`)
