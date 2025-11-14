# wpa-ctrl

[![Rust](https://github.com/DoumanAsh/wpa-ctrl/actions/workflows/rust.yml/badge.svg)](https://github.com/DoumanAsh/wpa-ctrl/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/wpa-ctrl.svg)](https://crates.io/crates/wpa-ctrl)
[![Documentation](https://docs.rs/wpa-ctrl/badge.svg)](https://docs.rs/crate/wpa-ctrl/)

## Usage

```rust,no_run
use wpa_ctrl::{WpaControlReq, WpaControllerBuilder};

const WPA_CTRL_BUILD: WpaControllerBuilder<'static> = WpaControllerBuilder::new();

let mut ctrl = match WPA_CTRL_BUILD.open("wlan0") {
    Ok(ctrl) => ctrl.into_buffered(),
    Err(error) => panic!("Cannot open wlan0"),
};

ctrl.request(WpaControlReq::status()).expect("Successful command");
while let Some(resp) = ctrl.recv().expect("To read message") {
    //Skip messages that are not intended as responses
    if resp.is_unsolicited() {
        continue;
    }

    if let Some(status) = resp.as_status() {
        println!("Network status={:?}", status);
        break;
    }
}
```

## Usage scenarios

### Add new network

- Optionally `scan` and check list of networks using `scan_results`
- `add_network` which returns returns `id` of network
- `set_network <id> ssid "network name"` which specifies network's name to associate with
- `set_network <id> psk "WAP password"` which specifies WPA password, only usable when network
requires WPA security
- `set_network <id> key_mgmt NONE` which specifies no security, required to connect to networks
without password
- `select_network <id>` - Select network for use.
- `save_config` - Optionally to save configuration.

### Reconnect

- Optionally `disconnect`;
- Run `reassociate` to start process of connecting to currently selected network

