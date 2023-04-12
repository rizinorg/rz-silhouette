# Hints Format

**Currently this format is in experiment phase**

We are trying to find the best solution to implement a solution which is able to provide metadata of known binary blocks which can match binaries previously seen with symbols.

The current implementation might change with new the protocol versions.

## Client side

The **client** has to generate a hash of the section.

1. Read and calculate the hash of a section using the physical size as size of the amount of data to be digested by the hash algorithm; in the silhouette client we use `blake3`.
2. As part of the signature we also collect the the number of bytes read, the operating system name and the binary type (i.e. `elf`, `pe`, etc..) to make the signature more unique.
3. As part of the request, each section data will contain also the physical base address for hints calculation purposes.

## Server side

On the `server` side we use the received data from the client to query a database and return the following info as response:

 - Architecture bits (this is useful for some archs to distinguish between different modes, like `arm` which has `arm mode` and `thumb mode`)
 - Physical address of the function pointed by the hint, calculated from the base address of the matched section hash provided in the request data.
