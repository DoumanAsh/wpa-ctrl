use wpa_ctrl::{WpaControlMessage, WpaAuth, WpaEncryption};

const NETWORK_DATA: &str = "network id / ssid / bssid / flags
0\tcoilinc\tany\t[CURRENT]
1\tDouPixel6\tany\t[DISABLED]
";

const SCAN_DATA: &str = "bssid / frequency / signal level / flags / ssid
00:09:5b:95:e0:4e\t2412\t208\t[WPA2-PSK-CCMP]\tjkm private
02:55:24:33:77:a3\t2462\t187\t[WPA-PSK-TKIP]\ttesting
00:09:5b:95:e0:4f\t2412\t209\t\tjkm guest
";

#[test]
fn should_parse_valid_network_list() {
    let msg = WpaControlMessage {
        raw: NETWORK_DATA,
    };

    let list = msg.as_network_list().expect("To parse network list");
    let list = list.collect::<Vec<_>>();
    assert_eq!(list.len(), 2);

    //ID
    assert_eq!(list[0].id.0, 0);
    assert_eq!(list[1].id.0, 1);

    //ssid
    assert_eq!(list[0].ssid, "coilinc");
    assert_eq!(list[1].ssid, "DouPixel6");

    //bssid
    assert_eq!(list[0].bssid, "any");
    assert_eq!(list[1].bssid, "any");

    //flags
    assert!(list[0].flags.current);
    assert!(!list[0].flags.disabled);
    assert!(!list[0].flags.p2p_persistent);

    assert!(!list[1].flags.current);
    assert!(list[1].flags.disabled);
    assert!(!list[1].flags.p2p_persistent);
}

#[test]
fn should_parse_valid_scan_result() {
    let msg = WpaControlMessage {
        raw: SCAN_DATA,
    };

    let list = msg.as_scan_results().expect("To parse scan results");
    let list = list.collect::<Vec<_>>();
    assert_eq!(list.len(), 3);

    //bssid
    assert_eq!(list[0].bssid, "00:09:5b:95:e0:4e");
    assert_eq!(list[1].bssid, "02:55:24:33:77:a3");
    assert_eq!(list[2].bssid, "00:09:5b:95:e0:4f");

    //frequency
    assert_eq!(list[0].freq, 2412);
    assert_eq!(list[1].freq, 2462);
    assert_eq!(list[2].freq, 2412);

    //signal level
    assert_eq!(list[0].level, 208);
    assert_eq!(list[1].level, 187);
    assert_eq!(list[2].level, 209);

    //ssid
    assert_eq!(list[0].ssid, "jkm private");
    assert_eq!(list[1].ssid, "testing");
    assert_eq!(list[2].ssid, "jkm guest");

    //flags
    assert_eq!(list[0].flags.auth, WpaAuth::Wpa2Psk);
    assert_eq!(list[0].flags.encryption, WpaEncryption::CCMP);
    assert_eq!(list[1].flags.auth, WpaAuth::WpaPsk);
    assert_eq!(list[1].flags.encryption, WpaEncryption::TKIP);
    assert_eq!(list[2].flags.auth, WpaAuth::Open);
    assert_eq!(list[2].flags.encryption, WpaEncryption::NONE);
}
