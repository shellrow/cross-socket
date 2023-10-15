[crates-badge]: https://img.shields.io/crates/v/cross-socket.svg
[crates-url]: https://crates.io/crates/cross-socket
[license-badge]: https://img.shields.io/crates/l/cross-socket.svg
[examples-url]: https://github.com/shellrow/cross-socket/tree/main/examples

# cross-socket [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
`cross-socket` is a cross-platform library designed for working with RawSocket. 
Empowers you to create, send, and receive raw network packets.

## Usage
Add `cross-socket` to your dependencies  
```toml:Cargo.toml
[dependencies]
cross-socket = "0.8"
```

## Example
See [Examples][examples-url]

## Supported platform
- Linux
- macOS
- Windows

## Feature flags 
The following feature flags can be used to enable/disable specific features.
#### `--feature setup` (for Windows users)
**For Windows**. This feature allows you to easy check/setup dependencies.
