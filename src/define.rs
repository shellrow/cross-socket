// APP information
pub const CRATE_UPDATE_DATE: &str = "2023-05-12";
pub const CRATE_REPOSITORY: &str = "https://github.com/shellrow/nesmap";

// Setting
pub const DEFAULT_SRC_PORT: u16 = 53443;

// Database
pub const DEFAULT_PORTS_TXT: &str = include_str!("../resources/nesmap-default-ports.txt");
pub const HTTP_PORTS_TXT: &str = include_str!("../resources/nesmap-http-ports.txt");
pub const HTTPS_PORTS_TXT: &str = include_str!("../resources/nesmap-https-ports.txt");
pub const OS_FINGERPRINT_JSON: &str = include_str!("../resources/nesmap-os-fingerprint.json");
pub const OS_TTL_JSON: &str = include_str!("../resources/nesmap-os-ttl.json");
pub const OUI_JSON: &str = include_str!("../resources/nesmap-oui.json");
pub const SUBDOMAIN_TXT: &str = include_str!("../resources/nesmap-subdomain.txt");
pub const TCP_SERVICE_JSON: &str = include_str!("../resources/nesmap-tcp-service.json");
pub const WELLKNOWN_PORTS_TXT: &str = include_str!("../resources/nesmap-wellknown-ports.txt");

// MPSC(Multi Producer, Single Consumer) FIFO queue communication messages
pub const MESSAGE_START_PORTSCAN: &str = "START_PORTSCAN";
pub const MESSAGE_END_PORTSCAN: &str = "END_PORTSCAN";
pub const MESSAGE_START_SERVICEDETECTION: &str = "START_SERVICEDETECTION";
pub const MESSAGE_END_SERVICEDETECTION: &str = "END_SERVICEDETECTION";
pub const MESSAGE_START_OSDETECTION: &str = "START_OSDETECTION";
pub const MESSAGE_END_OSDETECTION: &str = "END_OSDETECTION";
pub const MESSAGE_START_HOSTSCAN: &str = "START_HOSTSCAN";
pub const MESSAGE_END_HOSTSCAN: &str = "END_HOSTSCAN";
pub const MESSAGE_START_LOOKUP: &str = "START_LOOKUP";
pub const MESSAGE_END_LOOKUP: &str = "END_LOOKUP";
pub const MESSAGE_START_DOMAINSCAN: &str = "START_DOMAINSCAN";
pub const MESSAGE_END_DOMAINSCAN: &str = "END_DOMAINSCAN";
