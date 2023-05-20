[crates-badge]: https://img.shields.io/crates/v/nesmap.svg
[crates-url]: https://crates.io/crates/nesmap

# nesmap [![Crates.io][crates-badge]][crates-url]
Network mapper for diagnosis and discovery

## Features
- Port Scan
    - Service detection
    - OS detection
- Host Scan
- Ping
- Traceroute
- Subdomain scan

## Supported platforms
- Linux
- macOS
- Windows

## Install
```
cargo install nesmap
```

## Privileges
`nesmap` uses a raw socket which require elevated privileges.  Execute with administrator privileges.

## Additional Notes
Support for VM environments is in progress. Results may not be correct.
