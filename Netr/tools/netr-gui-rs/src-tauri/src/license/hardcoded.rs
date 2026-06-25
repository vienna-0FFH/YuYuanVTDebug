//! 部署端连接常量。
//!
//! 安全要点:
//! - **deploy 公钥**(64 hex)必须编译期内嵌,不能配置文件读
//! - 公钥被攻击者改 = 假部署端 = 握手时签名验不过 = ClientError::BadServerSignature
//! - 部署端 URL 和 app_key 公开无所谓,真正的防线是公钥验签 + driver 端二次验签

/// 部署端公网地址(终端用户机器能 reach)
pub const DEPLOY_BASE_URL: &str = "http://154.201.74.23:7777";

/// 部署端「应用」key,租户路由用
pub const APP_KEY: &str = "app_c4ec0d637009b03e8851186de72e1d5727ff89173abc4a7d";

/// 部署端 Ed25519 长期身份公钥(64 字符 hex)
///
/// 这把 = 部署端的"身份证"。Client::new 用它在握手期验证部署端签名。
/// 攻击者无私钥 → 伪造的部署端签名验不过 → BadServerSignature。
pub const DEPLOY_PUB_HEX: &str =
    "cbaba85d1652aa242c279f726413f993976200c2fa9baad0101b18a9fb206a45";

/// SDK 版本字符串,服务端记录(可做兼容性管控)
pub const SDK_VERSION: &str = "netr-gui-rs/0.1.0";
