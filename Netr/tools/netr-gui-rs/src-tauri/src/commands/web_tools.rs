//! Web 工具 (P89): web_search (DuckDuckGo lite) + web_fetch (URL → 文本)
//!
//! DuckDuckGo HTML 端点 (https://html.duckduckgo.com/html/?q=...) 不需 API key.
//! 失败时返回 ok:false + 提示.
//!
//! web_fetch: HEAD + GET 任意 https/http URL, 限制最大 256KB. HTML 用 scraper 抽正文.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::util::error::{AppError, AppResult};

const UA: &str = "GuardMetaVSP/1.0 (+https://github.com/anthropic)";
const MAX_FETCH_BYTES: usize = 256 * 1024;

fn client() -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(UA)
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| AppError::Internal(format!("reqwest build: {e}")))
}

#[derive(Debug, Deserialize)]
pub struct WebSearchReq { pub query: String, pub max_results: Option<u32> }

#[derive(Debug, Deserialize)]
pub struct WebFetchReq { pub url: String, pub max_kb: Option<u32> }

pub async fn do_web_search(args: &Value) -> Value {
    let req: WebSearchReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    let q = req.query.trim();
    if q.is_empty() {
        return json!({ "ok": false, "error": "query 不能为空" });
    }
    let max = req.max_results.unwrap_or(8).clamp(1, 20) as usize;

    let cli = match client() { Ok(c) => c, Err(e) => return json!({"ok":false,"error":e.to_string()}) };
    let url = format!("https://html.duckduckgo.com/html/?q={}", urlencoding_simple(q));
    let r = match cli.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("HTTP: {e}") }),
    };
    let status = r.status();
    if !status.is_success() {
        return json!({ "ok": false, "error": format!("DuckDuckGo 返 {}", status) });
    }
    let body = match r.text().await {
        Ok(s) => s,
        Err(e) => return json!({ "ok": false, "error": format!("body: {e}") }),
    };

    let results = parse_ddg_results(&body, max);
    if results.is_empty() {
        return json!({ "ok": true, "results": [], "note": "无结果, 可换个关键词重试" });
    }
    json!({
        "ok": true,
        "query": q,
        "count": results.len(),
        "results": results,
    })
}

/// 极简 percent-encoding (不引 url crate)
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// DuckDuckGo HTML lite 输出格式 — 简陋但够用. 用基础正则.
fn parse_ddg_results(html: &str, max: usize) -> Vec<Value> {
    let mut out = Vec::new();
    // 每条结果块大致结构:
    //   <a class="result__a" href="...">Title</a>
    //   <a class="result__snippet" ...>Snippet</a>
    // 这里用穷举不到 100 行的扫描:找 result__a 然后向后找 result__snippet
    let mut cursor = 0;
    while let Some(a_start) = html[cursor..].find("class=\"result__a\"") {
        let a_start = cursor + a_start;
        let href_start = html[..a_start].rfind("href=\"").map(|p| p + 6);
        let Some(href_start) = href_start else { cursor = a_start + 1; continue; };
        let Some(href_end_rel) = html[href_start..].find('"') else { cursor = a_start + 1; continue; };
        let href = &html[href_start..href_start + href_end_rel];
        // 标题: a_start 之后第一个 > 到 </a>
        let title_open = html[a_start..].find('>').map(|p| a_start + p + 1);
        let Some(title_open) = title_open else { cursor = a_start + 1; continue; };
        let Some(title_end_rel) = html[title_open..].find("</a>") else { cursor = a_start + 1; continue; };
        let title = strip_html(&html[title_open..title_open + title_end_rel]);
        // snippet
        let snippet_start = html[title_open..].find("class=\"result__snippet\"")
            .map(|p| title_open + p);
        let snippet = if let Some(s) = snippet_start {
            let s_open = html[s..].find('>').map(|p| s + p + 1);
            if let Some(so) = s_open {
                if let Some(se_rel) = html[so..].find("</a>") {
                    strip_html(&html[so..so + se_rel])
                } else { String::new() }
            } else { String::new() }
        } else { String::new() };

        let real_href = unwrap_ddg_redirect(href);
        if !real_href.is_empty() && !title.is_empty() {
            out.push(json!({
                "title": title.chars().take(160).collect::<String>(),
                "url": real_href,
                "snippet": snippet.chars().take(280).collect::<String>(),
            }));
            if out.len() >= max { break; }
        }
        cursor = title_open;
    }
    out
}

fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
        .replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#x27;", "'")
}

fn unwrap_ddg_redirect(href: &str) -> String {
    // DDG href 形如 //duckduckgo.com/l/?uddg=<urlencoded>&...
    if let Some(p) = href.find("uddg=") {
        let rest = &href[p + 5..];
        let end = rest.find('&').unwrap_or(rest.len());
        return urldecode(&rest[..end]);
    }
    if href.starts_with("//") {
        return format!("https:{}", href);
    }
    href.to_string()
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i+1]), hex_val(bytes[i+2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' { out.push(b' '); } else { out.push(bytes[i]); }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub async fn do_web_fetch(args: &Value) -> Value {
    let req: WebFetchReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    let url = req.url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return json!({ "ok": false, "error": "url 必须以 http:// 或 https:// 开头" });
    }
    let cap = (req.max_kb.unwrap_or(256).clamp(1, 1024) as usize) * 1024;
    let limit = cap.min(MAX_FETCH_BYTES);

    let cli = match client() { Ok(c) => c, Err(e) => return json!({"ok":false,"error":e.to_string()}) };
    let r = match cli.get(url).send().await {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("HTTP: {e}") }),
    };
    let status = r.status();
    let ct = r.headers().get("content-type")
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let final_url = r.url().to_string();
    let bytes = match r.bytes().await {
        Ok(b) => b,
        Err(e) => return json!({ "ok": false, "error": format!("body: {e}") }),
    };
    let truncated = bytes.len() > limit;
    let body_slice = &bytes[..bytes.len().min(limit)];

    let text = String::from_utf8_lossy(body_slice).to_string();
    // 如果是 html 抽正文
    let clean_text = if ct.contains("html") || text.trim_start().starts_with("<!") || text.trim_start().starts_with("<html") {
        html_to_text(&text)
    } else { text.clone() };

    json!({
        "ok": status.is_success(),
        "status": status.as_u16(),
        "url": final_url,
        "content_type": ct,
        "size": bytes.len(),
        "truncated": truncated,
        "text": clean_text.chars().take(16000).collect::<String>(),
        "text_truncated_for_ai": clean_text.chars().count() > 16000,
    })
}

fn html_to_text(html: &str) -> String {
    // 先把 <script>...</script> 和 <style>...</style> 整段干掉
    let stripped = strip_tag_block(html, "script");
    let stripped = strip_tag_block(&stripped, "style");
    let stripped = strip_tag_block(&stripped, "noscript");
    // 再 strip 所有 html 标签
    let txt = strip_html(&stripped);
    // 压缩多重空白
    txt.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn strip_tag_block(html: &str, tag: &str) -> String {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let mut out = String::with_capacity(html.len());
    let mut cur = 0;
    while let Some(p) = html[cur..].to_ascii_lowercase().find(&open) {
        let abs = cur + p;
        out.push_str(&html[cur..abs]);
        // 找到对应 close
        if let Some(end_rel) = html[abs..].to_ascii_lowercase().find(&close) {
            cur = abs + end_rel + close.len();
        } else {
            // 没闭合, 截掉剩余
            return out;
        }
    }
    out.push_str(&html[cur..]);
    out
}
