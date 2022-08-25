use wpa_ctrl::WpaControlMessage;

const DATA: &str = "network id / ssid / bssid / flags
0\tcoilinc\tany\t[CURRENT]
1\tDouPixel6\tany\t[DISABLED]
";

#[test]
fn should_parse_valid_network_list() {
    let msg = WpaControlMessage {
        raw: DATA,
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
