//! Deployment endpoint and public identity constants.
//!
//! The public key must remain compiled into both GUI and driver.  The URL and
//! application key are routing data; authenticity comes from Ed25519.

pub const DEPLOY_BASE_URL: &str = "http://154.201.74.23:7777";
pub const APP_KEY: &str = "app_c4ec0d637009b03e8851186de72e1d5727ff89173abc4a7d";
pub const DEPLOY_PUB_HEX: &str =
    "cbaba85d1652aa242c279f726413f993976200c2fa9baad0101b18a9fb206a45";
pub const SDK_VERSION: &str = "netr-gui-rs/0.1.0";
