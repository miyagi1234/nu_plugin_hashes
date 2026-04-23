# Hashes for Nushell

> [!WARNING]
> This project isn't being actively maintained - I don't have the energy to
> update it to keep up with Nushell updates. It's been months since I last
> used my plugin and I barely use Nushell nowadays. I will not contribute to
> this project anymore, nor will I accept pull requests. I'm happy to transfer
> ownership of this crate on [crates.io](https://crates.io/crates/nu_plugin_hashes)
> to another contributor if needed. Thanks to everyone who helped and to those
> who used my plugin.

> [!NOTE]
> This fork adds the following algorithms that were missing from the original:
>
> - cSHAKE (cshake128, cshake256)
> - KangarooTwelve
> - KMAC (kmac128, kmac256)
> - ParallelHash (parallel-hash128, parallel-hash256)
> - TupleHash (tuple-hash128, tuple-hash256)

A [Nushell](https://www.nushell.sh) plugin that adds a collection of **63+**
cryptographic hash functions from [Hashes](https://github.com/RustCrypto/hashes)
project.

This plugin's implementation is based on code stolen from the official Nushell
repository and on compile-time code generation with a build script.

Excess algorithms can be filtered off by selecting only specific features of the
crate.

## Installation

To install this plugin with all algorithms available run

```nu
cargo install nu_plugin_hashes
plugin add ($env.CARGO_HOME ++ /bin/nu_plugin_hashes)
```
