//! Static frontend assets, embedded at compile time.

pub const INDEX_HTML:  &str  = include_str!("../../helm-ui/index.html");
pub const HELM_JS:     &str  = include_str!("../../helm-ui/helm.js");
pub const GRAPH_JS:    &str  = include_str!("../../helm-ui/graph.js");
pub const BOARD_JS:    &str  = include_str!("../../helm-ui/board.js");
pub const HELM_CSS:    &str  = include_str!("../../helm-ui/helm.css");
pub const CRUX_ICON:   &[u8] = include_bytes!("../../helm-ui/crux_icon.png");
pub const CRUX_ICON_SVG: &[u8] = include_bytes!("../../helm-ui/crux_icon.svg");
