# Hashes for Nushell

A [Nushell](https://www.nushell.sh) plugin that adds a massive collection of cryptographic hash functions from the [RustCrypto/Hashes](https://github.com/RustCrypto/hashes) project.

This is a modernized and expanded fork of the original `nu_plugin_hashes`, updated to support the latest Nushell plugin protocol and adding several algorithms previously considered "impossible" to implement in this plugin.

## Key Features in this Fork

- **Modernized:** Updated for Nushell **0.112.2**.
- **Blake2b Variable Size:** Added `hash blake2b --size <int>` support for runtime-defined output sizes.
- **SHA-1 Collision Detection:** Added `hash sha1-checked` which detects and fails safely if a collision attack (SHAttered) is detected in the input.
- **XOF Support:** Added support for Extendable-Output Functions (XOFs) including:
  - **cSHAKE** (cshake128, cshake256)
  - **KangarooTwelve**
  - **KMAC** (kmac128, kmac256) — *Requires a key parameter*
  - **TupleHash** (tuple-hash128, tuple-hash256)
  - **ParallelHash** (parallel-hash128, parallel-hash256)
- **75+ Algorithms:** Over 75 algorithms are supported through a hybrid system of automated code generation and specialized manual implementations.

## Installation

To install this plugin with all algorithms enabled:

```bash
cargo install --path . --locked

Then, in Nushell:

Code snippet
plugin add ~/.cargo/bin/nu_plugin_hashes
plugin use hashes
Usage Examples
Standard Hashing
Code snippet
"hello world" | hash sha3-256
Blake2b with custom output size
Code snippet
"hello world" | hash blake2b --size 32
KMAC with a secret key
Code snippet
"hello world" | hash kmac256 "my-secret-key"
SHA-1 with collision protection
Code snippet
open suspicious_file.bin | hash sha1-checked
Implementation Details
This plugin uses a hybrid architecture:

Automated Generation: A build.rs script automatically generates Nushell command wrappers for any algorithm implementing the Digest trait.

Specialized Hashers: Complex algorithms (XOFs, keyed MACs, or collision-checked hashes) are manually implemented in src/special_hashers.rs to allow for custom flags like --size or --key.

License
This crate is licensed under the MIT license.


### Why you should push this before opening the issue:
1. **It removes the "Abandoned" warning:** It makes your repo look like the "Official New Home" of the project.
2. **It documents the new flags:** The original author didn't think `--size` or `--key` could be added easily; this shows them that you've improved the architecture.
3. **Professionalism:** It shows you care about the users who will eventually find your fork.

**To update it:**
1. Open `README.md` in your editor and replace the text.
2. Run:
   ```bash
   git add README.md
   git commit -m "Update README to reflect new features and maintainer status"
   git push
