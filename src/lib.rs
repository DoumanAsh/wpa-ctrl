//!WPA controller
//!
//!## Usage
//!
//!```rust,no_run
//!use wpa_ctrl::{WpaControlReq, WpaControllerBuilder};
//!
//!const WPA_CTRL_BUILD: WpaControllerBuilder<'static> = WpaControllerBuilder::new();
//!
//!let mut ctrl = match WPA_CTRL_BUILD.open("wlan0") {
//!    Ok(ctrl) => ctrl.into_buffered(),
//!    Err(error) => panic!("Cannot open wlan0"),
//!};
//!
//!ctrl.request(WpaControlReq::status()).expect("Successful command");
//!while let Some(resp) = ctrl.recv().expect("To read message") {
//!    //Skip messages that are not intended as responses
//!    if resp.is_unsolicited() {
//!        continue;
//!    }
//!
//!    if let Some(status) = resp.as_status() {
//!        println!("Network status={:?}", status);
//!        break;
//!    }
//!}
//!```
//!
//!## Usage scenarios
//!
//!### Add new network
//!
//!- Optionally `scan` and check list of networks using `scan_results`
//!- `add_network` which returns returns `id` of network
//!- `set_network <id> ssid "network name"` which specifies network's name to associate with
//!- `set_network <id> psk "WAP password"` which specifies WPA password, only usable when network requires WPA security
//!- `set_network <id> key_mgmt NONE` which specifies no security, required to connect to networks without password
//!- `select_network <id>` - Select network for use.
//!- `save_config` - Optionally to save configuration.
//!
//!### Reconnect
//!
//!- Optionally `disconnect`;
//!- Run `reassociate` to start process of connecting to currently selected network

#![cfg(unix)]
#![warn(missing_docs)]
#![allow(clippy::style, clippy::should_implement_trait)]

mod utils;

const BUF_SIZE: usize = 512;
const DEFAULT_ROOT: &str = "/var/run/wpa_supplicant/";

#[cfg(not(unix))]
compile_error!("Supports only unix targets");

#[cfg(target_os = "android")]
const LOCAL_SOCKET_DIR: &str = "/data/misc/wifi/sockets";
#[cfg(not(target_os = "android"))]
const LOCAL_SOCKET_DIR: &str = "/tmp";
const LOCAL_SOCKET_PREFIX: &str = "wpa_ctrl_";
const UNSOLICITED_PREFIX: char = '<';
type LocalSocketName = str_buf::StrBuf<23>;
type BssidStr = str_buf::StrBuf<17>;
type SsidStr = str_buf::StrBuf<32>;

use std::os::unix::net::UnixDatagram;
use std::{fs, io, path, net};
use core::{str, time};
use core::sync::atomic::{AtomicU32, Ordering};
use core::fmt::{self, Write};

///Suffix Generator for socket name
///
///When wpa-control attempts to connect it shall bind unix socket with name `wpa_crtl_<counter>`
///
///Default implementation is implemented on ()
pub trait SuffixGenerator {
    ///Creates suffix for file name
    fn generate_suffix(&self) -> u32;
}

impl SuffixGenerator for () {
    fn generate_suffix(&self) -> u32 {
        static COUNTER: AtomicU32 = AtomicU32::new(1);
        COUNTER.fetch_add(1, Ordering::SeqCst)
    }
}

///Options to control behavior when creating instance
pub struct Options<S: SuffixGenerator> {
    ///Method to generate socket name to bind to.
    ///
    ///When not used, it uses static counter
    pub suffix: S
}

static DEFAULT_OPTIONS: Options<()> = Options {
    suffix: ()
};

fn local_socket_name(generator: &impl SuffixGenerator) -> LocalSocketName {
    let mut name = LocalSocketName::new();
    let _ = write!(&mut name, "{}{}", LOCAL_SOCKET_PREFIX, generator.generate_suffix());
    name
}

///Surrounds value with quotes, useful when setting `ssid` or `psk`
pub struct QuotedValue<T: fmt::Display>(pub T);

impl<T: fmt::Display> fmt::Display for QuotedValue<T> {
    #[inline]
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_fmt(format_args!("\"{}\"", self.0))
    }
}

///Client builder
#[derive(Copy, Clone, Debug)]
pub struct WpaControllerBuilder<'a> {
    ///Folder where to look up wpa_supplicant's interfaces.
    pub root: &'a str,
    ///Read timeout for responses.
    pub read_timeout: Option<time::Duration>,
}

impl WpaControllerBuilder<'static> {
    ///Creates default instance.
    ///
    ///- `root` - `/var/run/wpa_supplicant/`
    ///- `read_timeout` - `Some(Duration::from_secs(10))`
    pub const fn new() -> Self {
        Self {
            root: DEFAULT_ROOT,
            read_timeout: Some(time::Duration::from_secs(10)),
        }
    }
}

impl<'a> WpaControllerBuilder<'a> {
    #[inline]
    #[allow(clippy::needless_lifetimes)]
    ///Changes root folder
    pub const fn set_root<'b>(self, new: &'b str) -> WpaControllerBuilder<'b> {
        WpaControllerBuilder {
            root: new,
            read_timeout: self.read_timeout,
        }
    }

    #[inline]
    ///Changes read_timeout
    ///
    ///If None, then block indefinitely, otherwise return error on timeout.
    ///This library handles timeout error, returning `None` response
    pub const fn set_read_timeout(mut self, read_timeout: Option<time::Duration>) -> Self {
        self.read_timeout = read_timeout;
        self
    }

    #[inline]
    ///Attempts to open socket.
    pub fn open(self, interface: &str) -> Result<WpaController, io::Error> {
        let path = path::Path::new(self.root).join(interface);
        WpaController::open_path(&path)
    }

    #[inline]
    ///Attempts to open socket with options.
    pub fn open_with(self, interface: &str, options: &Options<impl SuffixGenerator>) -> Result<WpaController, io::Error> {
        let path = path::Path::new(self.root).join(interface);
        WpaController::open_path_with(&path, options)
    }
}

///Request type
///
///Max message size 127 bytes
pub struct WpaControlReq {
    buf: str_buf::StrBuf<127>,
}

impl WpaControlReq {
    #[inline]
    ///Creates raw request, 127 bytes maximum
    ///
    ///Panics on overflow.
    pub const fn raw(text: &str) -> Self {
        Self {
            buf: str_buf::StrBuf::from_str(text)
        }
    }

    #[inline]
    ///Creates PING request
    pub const fn ping() -> Self {
        Self::raw("PING")
    }

    #[inline]
    ///Creates STATUS request
    pub const fn status() -> Self {
        Self::raw("STATUS")
    }

    #[inline]
    ///Creates SCAN request
    pub const fn scan() -> Self {
        Self::raw("SCAN")
    }

    #[inline]
    ///Creates SCAN_RESULTS request
    pub const fn scan_results() -> Self {
        Self::raw("SCAN_RESULTS")
    }

    #[inline]
    ///Creates DISCONNECT request
    pub const fn disconnect() -> Self {
        Self::raw("DISCONNECT")
    }

    #[inline]
    ///Creates REASSOCIATE request
    pub const fn reassociate() -> Self {
        Self::raw("REASSOCIATE")
    }

    #[inline]
    ///Creates LIST_NETWORKS request
    pub const fn list_networks() -> Self {
        Self::raw("LIST_NETWORKS")
    }

    #[inline]
    ///Creates ENABLE_NETWORK request
    pub fn add_network() -> Self {
        Self::raw("ADD_NETWORK")
    }

    #[inline]
    ///Creates GET_NETWORK request
    pub fn get_network(id: Id, var: &str) -> Self {
        let mut this = Self::raw("SET_NETWORK");
        let _ = write!(&mut this.buf, " {}", id.0);
        this.buf.push_str(" ");
        this.buf.push_str(var);
        this
    }

    #[inline]
    ///Creates SET_NETWORK request
    pub fn set_network(id: Id, var: &str, value: impl fmt::Display) -> Self {
        let mut this = Self::raw("SET_NETWORK");
        let _ = write!(&mut this.buf, " {}", id.0);
        this.buf.push_str(" ");
        this.buf.push_str(var);
        let _ = write!(&mut this.buf, " {}", value);
        this
    }

    #[inline]
    ///Creates SELECT_NETWORK request
    pub fn select_network(id: Id) -> Self {
        let mut this = Self::raw("SELECT_NETWORK");
        let _ = write!(&mut this.buf, " {}", id.0);
        this
    }

    #[inline]
    ///Creates ENABLE_NETWORK request
    pub fn enable_network(id: Id) -> Self {
        let mut this = Self::raw("ENABLE_NETWORK");
        let _ = write!(&mut this.buf, " {}", id.0);
        this
    }

    #[inline]
    ///Creates DISABLE_NETWORK request
    pub fn disable_network(id: Id) -> Self {
        let mut this = Self::raw("DISABLE_NETWORK");
        let _ = write!(&mut this.buf, " {}", id.0);
        this
    }

    #[inline]
    ///Creates REMOVE_NETWORK request
    pub fn remove_network(id: Id) -> Self {
        let mut this = Self::raw("REMOVE_NETWORK");
        let _ = write!(&mut this.buf, " {}", id.0);
        this
    }

    #[inline]
    ///Creates REMOVE_NETWORK all request
    pub fn remove_network_all() -> Self {
        Self::raw("REMOVE_NETWORK all")
    }


    #[inline]
    ///Creates SAVE_CONFIG request
    pub fn save_config() -> Self {
        Self::raw("SAVE_CONFIG")
    }
}

impl fmt::Debug for WpaControlReq {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.buf, fmt)
    }
}


#[derive(Copy, Clone, Debug)]
///Indicates success of command
pub struct Success;

#[derive(Copy, Clone, Debug)]
///Indicates failure of command
pub struct Fail;

#[derive(Copy, Clone, Debug)]
///Pong Message
pub struct Pong;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize, serde_derive::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
///Network id
pub struct Id(pub u32);

#[derive(Copy, Clone, Debug)]
///Interface state
pub enum WpaState {
    ///Not recognized state
    Unknown,
    ///Disconnected state.
    ///
    ///This state indicates that client is not associated, but is likely to start looking for an
    ///access point. This state is entered when a connection is lost.
    Disconnected,
    ///Interface disabled.
    ///
    ///This state is entered if the network interface is disabled, e.g., due to rfkill.
    ///wpa_supplicant refuses any new operations that would use the radio until the interface has
    ///been enabled.
    InterfaceDisabled,
    ///Inactive state (wpa_supplicant disabled)
    ///
    ///This state is entered if there are no enabled networks in the configuration. wpa_supplicant
    ///is not trying to associate with a new network and external interaction (e.g., ctrl_iface
    ///call to add or enable a network) is needed to start association.
    Inactive,
    ///Scanning for a network.
    ///
    ///This state is entered when wpa_supplicant starts scanning for a network.
    Scanning,
    ///Trying to authenticate with a BSS/SSID.
    ///
    ///This state is entered when wpa_supplicant has found a suitable BSS to authenticate with and
    ///the driver is configured to try to authenticate with this BSS. This state is used only with
    ///drivers that use wpa_supplicant as the SME.
    Authenticating,
    ///Trying to associate with a BSS/SSID.
    ///
    ///This state is entered when wpa_supplicant has found a suitable BSS to associate with and the
    ///driver is configured to try to associate with this BSS in ap_scan=1 mode. When using
    ///ap_scan=2 mode, this state is entered when the driver is configured to try to associate with
    ///a network using the configured SSID and security policy.
    Associating,
    ///Association completed.
    ///
    ///This state is entered when the driver reports that association has been successfully
    ///completed with an AP. If IEEE 802.1X is used (with or without WPA/WPA2), wpa_supplicant
    ///remains in this state until the IEEE 802.1X/EAPOL authentication has been completed.
    Associated,
    ///WPA 4-Way Key Handshake in progress.
    ///
    ///This state is entered when WPA/WPA2 4-Way Handshake is started. In case of WPA-PSK, this
    ///happens when receiving the first EAPOL-Key frame after association. In case of WPA-EAP, this
    ///state is entered when the IEEE 802.1X/EAPOL authentication has been completed.
    Handshake,
    ///This state is entered when 4-Way Key Handshake has been completed (i.e., when the supplicant
    ///sends out message 4/4) and when Group Key rekeying is started by the AP (i.e., when
    ///supplicant receives message 1/2).
    GroupHandshake,
    ///Connected and authenticated.
    Completed
}

impl WpaState {
    ///Parses status from its textual representation
    pub fn from_str(text: &str) -> Self {
        if text.eq_ignore_ascii_case("COMPLETED") {
            Self::Completed
        } else if text.eq_ignore_ascii_case("GROUP_HANDSHAKE") {
            Self::GroupHandshake
        } else if text.eq_ignore_ascii_case("4WAY_HANDSHAKE") {
            Self::Handshake
        } else if text.eq_ignore_ascii_case("ASSOCIATED") {
            Self::Associated
        } else if text.eq_ignore_ascii_case("ASSOCIATING") {
            Self::Associating
        } else if text.eq_ignore_ascii_case("AUTHENTICATING") {
            Self::Authenticating
        } else if text.eq_ignore_ascii_case("SCANNING") {
            Self::Scanning
        } else if text.eq_ignore_ascii_case("INACTIVE") {
            Self::Inactive
        } else if text.eq_ignore_ascii_case("INTERFACE_DISABLED") {
            Self::InterfaceDisabled
        } else if text.eq_ignore_ascii_case("DISCONNECTED") {
            Self::Disconnected
        } else {
            Self::Unknown
        }
    }
}

#[derive(Clone, Debug)]
///Interface status
pub struct WpaStatus {
    ///Interface state
    pub state: WpaState,
    ///Interface IP address, available if connected
    pub ip: Option<net::IpAddr>,
    ///SSID used by interface on successful connection.
    pub ssid: Option<String>
}

impl WpaStatus {
    ///Attempts to parse WPA Status from string.
    ///
    ///Returning `None` if it is invalid format (not lines in format `<var>=<value>`) or missing `wpa_status`
    pub fn from_str(text: &str) -> Option<Self> {
        let mut state = None;
        let mut ip = None;
        let mut ssid = None;

        for line in text.lines() {
            if line.is_empty() {
                continue;
            }

            let mut split = line.splitn(2, '=');
            let var = split.next().unwrap();
            if let Some(value) = split.next() {
                if var.eq_ignore_ascii_case("wpa_state") {
                    state = Some(WpaState::from_str(value));
                } else if var.eq_ignore_ascii_case("ip_address") {
                    ip = value.parse().ok();
                } else if var.eq_ignore_ascii_case("ssid") {
                    ssid = Some(value.to_owned());
                } else {
                    //Not interested to us, so skip
                    continue;
                }
            } else {
                //STATUS output is always <var>=<value>
                return None;
            }
        }

        state.map(|state| Self {
            state,
            ip,
            ssid,
        })
    }
}


///Network's flag, describing its current state.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize, serde_derive::Deserialize))]
pub struct WpaNetworkFlags {
    ///Indicates that network is currently set to be used.
    pub current: bool,
    ///Indicates that network is disabled.
    pub disabled: bool,
    ///Network is part of p2p persistent group. Google what it means.
    pub p2p_persistent: bool
}

impl WpaNetworkFlags {
    #[inline(always)]
    ///Parses network flags from flags string
    pub fn from_str(mut text: &str) -> Self {
        let mut result = WpaNetworkFlags {
            current: false,
            disabled: false,
            p2p_persistent: false,
        };

        if !text.is_empty() {
            while let Some(start_flag) = text.strip_prefix('[') {
                if let Some(end) = start_flag.find(']') {
                    let flag = &start_flag[..end];
                    if flag.eq_ignore_ascii_case("CURRENT") {
                        result.current = true;
                    } else if flag.eq_ignore_ascii_case("DISABLED") {
                        result.disabled = true;
                    } else if flag.eq_ignore_ascii_case("P2P-PERSISTENT") {
                        result.p2p_persistent = true;
                    }
                    text = &start_flag[end..];
                } else {
                    break;
                }
            }
        }

        result
    }
}

///Network description
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize, serde_derive::Deserialize))]
pub struct WpaNetwork {
    ///Network id
    pub id: Id,
    ///Network's SSID. Can be empty string, when not set.
    pub ssid: String,
    ///Network's BSSID. Can be empty string, when not set.
    pub bssid: String,
    ///Network's flag
    pub flags: WpaNetworkFlags,
}

///Iterator over list of networks
pub struct WpaNetworkList<'a> {
    lines: str::Lines<'a>,
}

impl<'a> Iterator for WpaNetworkList<'a> {
    type Item = WpaNetwork;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let line = self.lines.next()?;
        let mut parts = line.splitn(4, '\t');
        let network = WpaNetwork {
            id: Id(parts.next().unwrap().parse().ok()?),
            ssid: parts.next()?.to_owned(),
            bssid: parts.next()?.to_owned(),
            flags: WpaNetworkFlags::from_str(parts.next().unwrap_or("")),
        };
        Some(network)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize, serde_derive::Deserialize))]
///Describes network's auth method
pub enum WpaAuth {
    ///WPA2-EAP
    Wpa2Eap,
    ///WPA-EAP
    WpaEap,
    ///WPA2-PSK
    Wpa2Psk,
    ///WPA-PSK
    WpaPsk,
    ///Open network
    Open
}

impl WpaAuth {
    ///Returns textual representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wpa2Eap => "WPA2-EAP",
            Self::WpaEap => "WPA-EAP",
            Self::Wpa2Psk => "WPA2-PSK",
            Self::WpaPsk => "WPA-PSK",
            Self::Open => "OPEN"
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize, serde_derive::Deserialize))]
///Describes network's encryption method
pub enum WpaEncryption {
    ///No encryption
    NONE,
    ///Wired Equivalent Privacy
    ///
    ///Obsolete WPA's encryption
    WEP,
    ///Temporal Key Integrity Protocol
    ///
    ///Old WPA's encryption
    TKIP,
    ///Modern AES based encryption for WPA2
    CCMP
}

impl WpaEncryption {
    ///Returns textual representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WEP => "WEP",
            Self::TKIP => "TKIP",
            Self::CCMP => "CCMP",
            Self::NONE => "",
        }
    }

    #[inline]
    ///Indicates no encryption present
    pub fn is_none(&self) -> bool {
        matches!(self, Self::NONE)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize, serde_derive::Deserialize))]
///Network's flags in scan results
pub struct WpaScanResultFlags {
    ///Auth method
    pub auth: WpaAuth,
    ///Encryption method
    pub encryption: WpaEncryption,
}

impl WpaScanResultFlags {
    ///Converts flag string into this struct
    pub fn from_str(text: &str) -> Self {
        WpaScanResultFlags {
            auth: if text.starts_with("[WPA2-EAP") {
                WpaAuth::Wpa2Eap
            } else if text.starts_with("[WPA-EAP") {
                WpaAuth::WpaEap
            } else if text.starts_with("[WPA2-PSK") {
                WpaAuth::Wpa2Psk
            } else if text.starts_with("[WPA-PSK") {
                WpaAuth::WpaPsk
            } else {
                WpaAuth::Open
            },
            encryption: if text.contains("-CCMP") {
                WpaEncryption::CCMP
            } else if text.contains("-TKIP") {
                WpaEncryption::TKIP
            } else if text.contains("WEP") {
                WpaEncryption::WEP
            } else {
                WpaEncryption::NONE
            }
        }
    }
}

impl fmt::Display for WpaScanResultFlags {
    #[inline]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.auth.as_str())?;
        if !self.encryption.is_none() {
            fmt.write_str("-")?;
            fmt.write_str(self.encryption.as_str())?
        }
        Ok(())
    }
}

///Scan result's item description
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize, serde_derive::Deserialize))]
pub struct WpaScanResult {
    ///Network's BSSID. Can be empty string, when not set.
    pub bssid: BssidStr,
    ///Network's frequency
    pub freq: u32,
    ///Network's signal level in decibel(dBm)
    pub level: i16,
    ///Network's flag
    pub flags: WpaScanResultFlags,
    ///Network's SSID. Should not be empty normally
    pub ssid: SsidStr,
}

impl WpaScanResult {
    ///Returns signal level in percentage of range 0..=100
    ///
    ///Calculates as following: 2 * (dBm + 100)  where dBm: [-100 to -50]
    pub fn singal_level_percent(&self) -> u8 {
        if self.level <= -100 {
            0u8
        } else if self.level >= -50 {
            100u8
        } else {
            2i16.saturating_mul(self.level.saturating_add(100)) as u8
        }
    }
}

///Iterator over list of networks
pub struct WpaScanResults<'a> {
    lines: str::Lines<'a>,
}

impl<'a> Iterator for WpaScanResults<'a> {
    type Item = WpaScanResult;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let line = self.lines.next()?;
        let mut parts = line.splitn(5, '\t');

        let mut bssid = BssidStr::new();
        bssid.push_str(parts.next()?);

        let result = WpaScanResult {
            bssid,
            freq: parts.next()?.parse().ok()?,
            //Assume quality is too bad if we cannot fit?
            level: parts.next()?.parse().unwrap_or(-100),
            flags: WpaScanResultFlags::from_str(parts.next().unwrap_or("")),
            ssid: {
                let mut ssid = SsidStr::new();
                ssid.push_str(parts.next()?);
                ssid
            }
        };

        Some(result)
    }
}

///Message.
pub struct WpaControlMessage<'a> {
    ///Raw content of message
    pub raw: &'a str,
}

impl<'a> WpaControlMessage<'a> {
    #[inline(always)]
    ///Returns whether message is unsolicited response, namely it means it is not reply to request.
    pub const fn is_unsolicited(&self) -> bool {
        !self.raw.is_empty() && self.raw.as_bytes()[0] == UNSOLICITED_PREFIX as u8
    }

    ///Attempts to reinterpret message as pong
    pub fn as_pong(&self) -> Option<Pong> {
        if self.raw.eq_ignore_ascii_case("pong") {
            Some(Pong)
        } else {
            None
        }
    }

    ///Attempts to reinterpret message as success of request
    pub fn as_success(&self) -> Option<Success> {
        if self.raw.eq_ignore_ascii_case("ok") {
            Some(Success)
        } else {
            None
        }
    }

    ///Attempts to reinterpret message as failure of request
    pub fn as_fail(&self) -> Option<Fail> {
        if self.raw.eq_ignore_ascii_case("fail") {
            Some(Fail)
        } else {
            None
        }
    }

    ///Attempts to reinterpret message as status
    pub fn as_status(&self) -> Option<WpaStatus> {
        WpaStatus::from_str(self.raw)
    }

    ///Attempts to reinterpret message as network id
    pub fn as_network_id(&self) -> Option<Id> {
        self.raw.parse().map(|id| Id(id)).ok()
    }

    ///Attempts to reinterpret message as network id
    pub fn as_network_list(&self) -> Option<WpaNetworkList<'_>> {
        let mut lines = self.raw.lines();
        let line = lines.next().unwrap();
        let header = utils::split::<4>(line, '/')?;
        if header[0] == "network id" && header[1] == "ssid" && header[2] == "bssid" && header[3] == "flags" {
            Some(WpaNetworkList {
                lines
            })
        } else {
            None
        }
    }

    ///Attempts to reinterpret message as scan results
    pub fn as_scan_results(&self) -> Option<WpaScanResults<'_>> {
        let mut lines = self.raw.lines();
        let line = lines.next().unwrap();
        let header = utils::split::<5>(line, '/')?;
        //bssid / frequency / signal level / flags / ssid
        if header[0] == "bssid" && header[1] == "frequency" && header[2] == "signal level" && header[3] == "flags" && header[4] == "ssid" {
            Some(WpaScanResults {
                lines
            })
        } else {
            None
        }

    }
}

impl<'a> fmt::Debug for WpaControlMessage<'a> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.raw, fmt)
    }
}

///WPA controller
///
///All methods require to provide buffer to temporary hold data from the socket.
///
///Use `WpaController::into_buffered` to create wrapped instance with own buffer
pub struct WpaController {
    socket: UnixDatagram,
    local: path::PathBuf,
}

impl WpaController {
    #[inline(always)]
    ///Attempts to connect to WPA controller at specified `path`
    pub fn open<P: AsRef<path::Path>>(path: P) -> Result<Self, io::Error> {
        Self::open_path(path.as_ref())
    }

    #[inline(always)]
    ///Attempts to connect to WPA controller at specified `path`
    pub fn open_path(path: &path::Path) -> Result<Self, io::Error> {
        Self::open_path_with(path, &DEFAULT_OPTIONS)
    }

    ///Attempts to connect to WPA controller at specified `path` with provided options
    pub fn open_path_with(path: &path::Path, options: &Options<impl SuffixGenerator>) -> Result<Self, io::Error> {
        let local_name = local_socket_name(&options.suffix);
        let local = path::Path::new(LOCAL_SOCKET_DIR).join(local_name.as_str());

        //Attempt to remove file, if for some reason it exists
        let _ = fs::remove_file(&local);

        let socket = UnixDatagram::bind(&local)?;
        let this = Self {
            socket,
            local,
        };
        this.socket.connect(path)?;
        Ok(this)
    }

    ///Wraps controller with builtin buffer.
    pub fn into_buffered(self) -> BufferedWpaController {
        BufferedWpaController {
            inner: self,
            buffer: [0; BUF_SIZE],
        }
    }

    #[inline]
    ///Sends request, returning number of bytes written.
    pub fn request(&self, req: WpaControlReq) -> Result<usize, io::Error> {
        self.socket.send(req.buf.as_bytes())
    }

    ///Attempts to receive message.
    pub fn recv<'a>(&self, buffer: &'a mut [u8]) -> Result<Option<WpaControlMessage<'a>>, io::Error> {
        loop {
            match self.socket.recv(buffer) {
                Ok(len) => {
                    let msg = match core::str::from_utf8(&buffer[..len]) {
                        Ok(msg) => msg.trim(),
                        Err(error) => break Err(io::Error::new(io::ErrorKind::InvalidData, error))
                    };

                    break Ok(Some(WpaControlMessage {
                        raw: msg,
                    }))
                },
                Err(error) => match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::TimedOut => break Ok(None),
                    _ => break Err(error),
                }
            }
        }
    }

    ///Attempts to receive reply for result of command.
    ///
    ///This method will continuously `recv` skipping `unsolicited` messages
    ///
    ///# Result
    ///
    ///- Returns `None` if neither success or fail are present among replies.
    ///
    ///- `Ok(())` indicates success.
    ///
    ///- `Err(())` indicates failure.
    pub fn recv_req_result(&self, buffer: &mut [u8]) -> Option<Result<Result<(), ()>, io::Error>> {
        loop {
            match self.recv(buffer) {
                Ok(Some(msg)) => {
                    if msg.as_success().is_some() {
                        break Some(Ok(Ok(())));
                    } else if msg.as_fail().is_some() {
                        break Some(Ok(Err(())));
                    } else {
                        continue
                    }
                },
                Ok(None) => break None,
                Err(error) => return Some(Err(error)),
            }
        }
    }

    ///Performs network add sequence
    ///
    ///# Arguments
    ///
    ///- `ssid` - Network identifier;
    ///- `wpa_pass` - Passkey for WPA auth, if `None` sets `key_mgmt` to `None`
    ///- `hidden` - Specifies whether you want to scan for SSID to connect to the network.
    ///
    ///# Result
    ///
    ///- `Ok(id)` - Newly created network id
    pub fn add_network(&self, ssid: &str, wpa_pass: Option<&str>, hidden: bool, buffer: &mut [u8]) -> Result<Id, io::Error> {
        self.request(WpaControlReq::add_network())?;
        let id = loop {
            match self.recv(buffer)? {
                Some(msg) => match msg.as_network_id() {
                    Some(id) => break id,
                    None => continue,
                },
                None => return Err(io::Error::new(io::ErrorKind::TimedOut, "no response to add_network")),
            }
        };

        self.request(WpaControlReq::set_network(id, "ssid", QuotedValue(ssid)))?;
        match self.recv_req_result(buffer) {
            Some(Ok(Ok(()))) => (),
            Some(Ok(Err(()))) => return Err(io::Error::new(io::ErrorKind::Other, format!("set_network id={} ssid {} failed", id.0, QuotedValue(ssid)))),
            Some(Err(error)) => return Err(error),
            None => return Err(io::Error::new(io::ErrorKind::Other, format!("set_network id={} ssid {} had no ok/fail reply", id.0, QuotedValue(ssid)))),
        }
        match wpa_pass {
            Some(wpa_pass) => {
                let wpa_pass = QuotedValue(wpa_pass);
                self.request(WpaControlReq::set_network(id, "psk", &wpa_pass))?;
                match self.recv_req_result(buffer) {
                    Some(Ok(Ok(()))) => (),
                    Some(Ok(Err(()))) => return Err(io::Error::new(io::ErrorKind::Other, format!("set_network id={} psk {} failed", id.0, wpa_pass))),
                    Some(Err(error)) => return Err(error),
                    None => return Err(io::Error::new(io::ErrorKind::Other, format!("set_network id={} psk {} had no ok/fail reply", id.0, wpa_pass))),
                }
            },
            None => {
                self.request(WpaControlReq::set_network(id, "key_mgmt", "NONE"))?;
                match self.recv_req_result(buffer) {
                    Some(Ok(Ok(()))) => (),
                    Some(Ok(Err(()))) => return Err(io::Error::new(io::ErrorKind::Other, format!("set_network id={} key_mgmt NONE failed", id.0))),
                    Some(Err(error)) => return Err(error),
                    None => return Err(io::Error::new(io::ErrorKind::Other, format!("set_network id={} key_mgmt NONE had no ok/fail reply", id.0))),
                }
            },
        }

        if hidden {
            self.request(WpaControlReq::set_network(id, "scan_ssid", 1))?;
            match self.recv_req_result(buffer) {
                Some(Ok(Ok(()))) => (),
                Some(Ok(Err(()))) => return Err(io::Error::new(io::ErrorKind::Other, format!("set_network id={} scan_ssid 1 failed", id.0))),
                Some(Err(error)) => return Err(error),
                None => return Err(io::Error::new(io::ErrorKind::Other, format!("set_network id={} scan_ssid 1 had no ok/fail reply", id.0))),
            }
        }

        Ok(id)
    }

    ///Performs removal of known network by `id`.
    pub fn remove_network(&self, id: Id, buffer: &mut [u8]) -> Result<(), io::Error> {
        self.request(WpaControlReq::remove_network(id))?;
        match self.recv_req_result(buffer) {
            Some(Ok(Ok(()))) => Ok(()),
            Some(Ok(Err(()))) => return Err(io::Error::new(io::ErrorKind::Other, format!("remove_network id={}", id.0))),
            Some(Err(error)) => return Err(error),
            None => return Err(io::Error::new(io::ErrorKind::Other, format!("remove_network id={} has no reply", id.0))),
        }
    }

    ///Select a network for use by `id`.
    pub fn select_network(&self, id: Id, buffer: &mut [u8]) -> Result<(), io::Error> {
        self.request(WpaControlReq::select_network(id))?;
        match self.recv_req_result(buffer) {
            Some(Ok(Ok(()))) => Ok(()),
            Some(Ok(Err(()))) => return Err(io::Error::new(io::ErrorKind::Other, format!("select_network id={}", id.0))),
            Some(Err(error)) => return Err(error),
            None => return Err(io::Error::new(io::ErrorKind::Other, format!("select_network id={} has no reply", id.0))),
        }
    }

    ///Reconfigure wpa, i.e. reload wpasupplicant from saved config.
    pub fn reconfigure(&self, buffer: &mut [u8]) -> Result<(), io::Error> {
        self.request(WpaControlReq::raw("RECONFIGURE"))?;
        match self.recv_req_result(buffer) {
            Some(Ok(Ok(()))) => Ok(()),
            Some(Ok(Err(r))) => return Err(io::Error::new(io::ErrorKind::Other, format!("reconfigure ret={:?}", r))),
            Some(Err(error)) => return Err(error),
            None => return Err(io::Error::new(io::ErrorKind::Other, "reconfigure has no reply".to_owned())),
        }
    }
}

impl Drop for WpaController {
    #[inline]
    fn drop(&mut self) {
        let _ = self.socket.shutdown(net::Shutdown::Both);
        let _ = fs::remove_file(&self.local);
    }
}

///WpaController with own buffer
pub struct BufferedWpaController {
    buffer: [u8; BUF_SIZE],
    inner: WpaController,
}

impl BufferedWpaController {
    #[inline]
    ///Sends request, returning number of bytes written.
    pub fn request(&self, req: WpaControlReq) -> Result<usize, io::Error> {
        self.inner.socket.send(req.buf.as_bytes())
    }

    ///Attempts to receive message.
    pub fn recv(&mut self) -> Result<Option<WpaControlMessage<'_>>, io::Error> {
        self.inner.recv(&mut self.buffer)
    }

    ///Attempts to receive reply for result of command.
    ///
    ///This method will continuously `recv` skipping `unsolicited` messages
    ///
    ///# Result
    ///
    ///- Returns `None` if neither success or fail are present among replies.
    ///
    ///- `Ok(())` indicates success.
    ///
    ///- `Err(())` indicates failure.
    pub fn recv_req_result(&mut self) -> Option<Result<Result<(), ()>, io::Error>> {
        self.inner.recv_req_result(&mut self.buffer)
    }

    ///Performs network add sequence
    ///
    ///# Arguments
    ///
    ///- `ssid` - Network identifier;
    ///- `wpa_pass` - Passkey for WPA auth, if `None` sets `key_mgmt` to `None`
    ///- `hidden` - Specifies whether you want to scan for SSID to connect to the network.
    ///
    ///# Result
    ///
    ///- `Ok(id)` - Newly created network id
    pub fn add_network(&mut self, ssid: &str, wpa_pass: Option<&str>, hidden: bool) -> Result<Id, io::Error> {
        self.inner.add_network(ssid, wpa_pass, hidden, &mut self.buffer)
    }

    ///Performs removal of known network by `id`.
    pub fn remove_network(&mut self, id: Id) -> Result<(), io::Error> {
        self.inner.remove_network(id, &mut self.buffer)
    }

    ///Select a network for use by `id`.
    pub fn select_network(&mut self, id: Id) -> Result<(), io::Error> {
        self.inner.select_network(id, &mut self.buffer)
    }

    ///Reconfigure wpa, i.e. reload wpasupplicant from saved config.
    pub fn reconfigure(&mut self) -> Result<(), io::Error> {
        self.inner.reconfigure(&mut self.buffer)
    }
}
