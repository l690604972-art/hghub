//! 媒体层：封面解密 + HLS 代理。
//!
//! 站点封面是 AES-128-CBC 密文，m3u8 内部分片/key 又可能被 WebView 的 CORS 拦住，
//! 所以图片与视频统一走本地自定义协议（Windows/Android 为 `http://hg.localhost`，
//! macOS 为 `hg://localhost`，见 [`LOCAL_ORIGIN`]）。

use crate::net::fetch_bytes;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use once_cell::sync::Lazy;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::http::{Response, StatusCode};

/// 本平台自定义协议的完整基址。
///
/// Tauri 的自定义协议地址随平台不同：Windows / Android 是 `http://<scheme>.localhost`，
/// macOS / Linux 是 `<scheme>://localhost`，iOS 走本地环回 `http://127.0.0.1:19820`
/// （iOS 原生 AVPlayer 无法读取 WKURLSchemeHandler 自定义 scheme）。
/// 前端 `src/api.ts` 的 `LOCAL` 必须与此一致，否则封面与视频全部加载失败。
#[cfg(target_os = "ios")]
pub const LOCAL_ORIGIN: &str = "http://127.0.0.1:19820";
#[cfg(any(target_os = "windows", target_os = "android"))]
pub const LOCAL_ORIGIN: &str = "http://hg.localhost";
#[cfg(not(any(target_os = "windows", target_os = "android", target_os = "ios")))]
pub const LOCAL_ORIGIN: &str = "hg://localhost";

pub const LOCAL_HTTP_ADDR: &str = "127.0.0.1:19820";
pub const LOCAL_HTTP_ORIGIN: &str = "http://127.0.0.1:19820";

const IMG_KEY: &[u8] = b"f5d965df75336270";
const IMG_IV: &[u8] = b"97b60394abc2fbe1";

static IMG_CACHE: Lazy<Mutex<HashMap<String, Arc<Vec<u8>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static PL_CACHE: Lazy<Mutex<HashMap<String, Arc<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const IMG_CACHE_MAX: usize = 240;
const PL_CACHE_MAX: usize = 60;

fn cache_put<V: Clone>(map: &Mutex<HashMap<String, V>>, key: String, val: V, max: usize) {
    let mut m = map.lock().unwrap();
    if m.len() >= max {
        if let Some(k) = m.keys().next().cloned() {
            m.remove(&k);
        }
    }
    m.insert(key, val);
}

/* ───────────────────────── AES ───────────────────────── */

fn aes_cbc_decrypt(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        return None;
    }
    let cipher = Aes128::new_from_slice(IMG_KEY).ok()?;
    let mut prev = [0u8; 16];
    prev.copy_from_slice(IMG_IV);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ct = [0u8; 16];
        ct.copy_from_slice(chunk);
        let mut block = ct;
        cipher.decrypt_block((&mut block).into());
        for i in 0..16 {
            out.push(block[i] ^ prev[i]);
        }
        prev = ct;
    }
    Some(out)
}

fn strip_padding(mut buf: Vec<u8>) -> Vec<u8> {
    let pad = *buf.last().unwrap_or(&0) as usize;
    if pad > 0 && pad <= 16 && buf.len() >= pad {
        if buf[buf.len() - pad..].iter().all(|b| *b as usize == pad) {
            buf.truncate(buf.len() - pad);
        }
    }
    buf
}

fn image_kind(buf: &[u8]) -> Option<&'static str> {
    if buf.len() < 12 {
        return None;
    }
    if buf[0] == 0xFF && buf[1] == 0xD8 {
        return Some("image/jpeg");
    }
    if buf.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        return Some("image/png");
    }
    if buf.starts_with(b"GIF8") {
        return Some("image/gif");
    }
    if buf.starts_with(b"RIFF") && &buf[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    None
}

/// 取封面：命中缓存直接返回，否则下载并按需解密。
pub async fn load_image(url: &str) -> Result<(String, Arc<Vec<u8>>), String> {
    if let Some(hit) = IMG_CACHE.lock().unwrap().get(url).cloned() {
        let kind = image_kind(&hit).unwrap_or("image/jpeg");
        return Ok((kind.to_string(), hit));
    }
    let (_, bytes) = fetch_bytes(url).await?;
    let plain = if image_kind(&bytes).is_some() {
        bytes
    } else {
        let dec = aes_cbc_decrypt(&bytes).ok_or_else(|| "封面解密失败".to_string())?;
        strip_padding(dec)
    };
    let kind = image_kind(&plain).unwrap_or("image/jpeg").to_string();
    let arc = Arc::new(plain);
    cache_put(&IMG_CACHE, url.to_string(), arc.clone(), IMG_CACHE_MAX);
    Ok((kind, arc))
}

/* ───────────────────────── HLS ───────────────────────── */

fn enc(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

fn dec(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().to_string()
}

fn absolutize(base: &str, target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_string();
    }
    if let Ok(b) = url::Url::parse(base) {
        if let Ok(j) = b.join(target) {
            return j.to_string();
        }
    }
    target.to_string()
}

fn rewrite_uri_attr(line: &str, prefix: &str) -> String {
    // #EXT-X-KEY:...URI="xxx" / #EXT-X-MAP:URI="xxx"
    if let Some(start) = line.find("URI=\"") {
        let rest = &line[start + 5..];
        if let Some(end) = rest.find('"') {
            let uri = &rest[..end];
            let new = format!("{prefix}/seg?u={}", enc(uri));
            return format!("{}{}{}", &line[..start + 5], new, &rest[end..]);
        }
    }
    line.to_string()
}

/// 取 m3u8 并把 key / 分片地址改写到本地协议。
pub async fn load_playlist(url: &str, prefix: &str) -> Result<Arc<String>, String> {
    let cache_key = format!("{prefix}|{url}");
    if let Some(hit) = PL_CACHE.lock().unwrap().get(&cache_key).cloned() {
        return Ok(hit);
    }
    let (_, bytes) = fetch_bytes(url).await?;
    let text = String::from_utf8_lossy(&bytes).to_string();

    let mut out = String::with_capacity(text.len() + 512);
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() {
            out.push('\n');
            continue;
        }
        if line.starts_with('#') {
            if line.starts_with("#EXT-X-KEY") || line.starts_with("#EXT-X-MAP") {
                // 先把相对 URI 绝对化再改写
                let absolute = absolutize_uri_in_attr(url, line);
                out.push_str(&rewrite_uri_attr(&absolute, prefix));
            } else {
                out.push_str(line);
            }
        } else {
            let absolute = absolutize(url, line);
            out.push_str(&format!("{prefix}/seg?u={}", enc(&absolute)));
        }
        out.push('\n');
    }

    let arc = Arc::new(out);
    cache_put(&PL_CACHE, cache_key, arc.clone(), PL_CACHE_MAX);
    Ok(arc)
}

fn absolutize_uri_in_attr(base: &str, line: &str) -> String {
    if let Some(start) = line.find("URI=\"") {
        let rest = &line[start + 5..];
        if let Some(end) = rest.find('"') {
            let uri = &rest[..end];
            let abs = absolutize(base, uri);
            return format!("{}{}{}", &line[..start + 5], abs, &rest[end..]);
        }
    }
    line.to_string()
}

/// 清空封面 / 播放列表内存缓存
pub fn clear_caches() {
    if let Ok(mut g) = IMG_CACHE.lock() { g.clear(); }
    if let Ok(mut g) = PL_CACHE.lock() { g.clear(); }
}

/* ───────────────────────── 协议响应 ───────────────────────── */

fn respond(
    status: u16,
    ctype: &str,
    body: Vec<u8>,
    cache: &str,
) -> Response<Vec<u8>> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
        .header("Content-Type", ctype)
        .header("Access-Control-Allow-Origin", "*")
        .header("Cache-Control", cache)
        .body(body)
        .unwrap_or_else(|_| Response::new(Vec::new()))
}

/// 统一入口：`<LOCAL_ORIGIN>/img?u=` / `hls?u=` / `seg?u=`
///
/// `origin` 是本平台自定义协议的完整基址，见 [`LOCAL_ORIGIN`]；用于改写 m3u8 里的
/// 分片与 key 地址。正常情况下调用方直接传 [`LOCAL_ORIGIN`]。
pub async fn handle(path: &str, query: &str, origin: &str) -> Response<Vec<u8>> {
    let target = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("u="))
        .map(dec)
        .unwrap_or_default();

    if target.is_empty() {
        return respond(400, "text/plain", b"missing u".to_vec(), "no-store");
    }

    match path {
        "/img" => match load_image(&target).await {
            Ok((kind, bytes)) => respond(200, &kind, bytes.as_ref().clone(), "public, max-age=86400"),
            Err(e) => respond(502, "text/plain", e.into_bytes(), "no-store"),
        },
        "/hls" => match load_playlist(&target, origin).await {
            Ok(text) => respond(
                200,
                "application/vnd.apple.mpegurl",
                text.as_bytes().to_vec(),
                "no-store",
            ),
            Err(e) => respond(502, "text/plain", e.into_bytes(), "no-store"),
        },
        "/seg" => match fetch_bytes(&target).await {
            Ok((ctype, bytes)) => respond(
                200,
                ctype.as_deref().unwrap_or("application/octet-stream"),
                bytes,
                "public, max-age=3600",
            ),
            Err(e) => respond(502, "text/plain", e.into_bytes(), "no-store"),
        },
        _ => respond(404, "text/plain", b"not found".to_vec(), "no-store"),
    }
}

fn parse_byte_range(header: &str, total: usize) -> Option<(usize, usize)> {
    if total == 0 {
        return None;
    }
    let spec = header.trim().strip_prefix("bytes=")?;
    let (start_s, end_s) = spec.split_once('-')?;
    let start_s = start_s.trim();
    let end_s = end_s.trim();
    if start_s.is_empty() {
        let suffix: usize = end_s.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        let start = total.saturating_sub(suffix);
        Some((start, total - 1))
    } else {
        let start: usize = start_s.parse().ok()?;
        if start >= total {
            return None;
        }
        let end = if end_s.is_empty() {
            total - 1
        } else {
            end_s.parse::<usize>().ok()?.min(total - 1)
        };
        if start > end {
            return None;
        }
        Some((start, end))
    }
}

/// 本地 HTTP 环回代理（127.0.0.1:19820），供 iOS WKWebView 原生 `<video>` (AVPlayer)
/// 读取 m3u8 / key / ts / mp4 与解密封面，支持 HEAD 与 Range 分片请求。
pub async fn serve_local_http() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = match tokio::net::TcpListener::bind(LOCAL_HTTP_ADDR).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[media] bind {LOCAL_HTTP_ADDR} failed: {e}");
            return;
        }
    };
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut filled = 0usize;
            while filled < buf.len() {
                match stream.read(&mut buf[filled..]).await {
                    Ok(0) => break,
                    Ok(n) => {
                        filled += n;
                        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }
            if filled == 0 {
                return;
            }
            let req_str = String::from_utf8_lossy(&buf[..filled]);
            let mut lines = req_str.lines();
            let req_line = lines.next().unwrap_or("");
            let mut parts = req_line.split_whitespace();
            let method = parts.next().unwrap_or("GET");
            let raw_target = parts.next().unwrap_or("/");

            if method.eq_ignore_ascii_case("OPTIONS") {
                let hdr = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, HEAD, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(hdr.as_bytes()).await;
                return;
            }

            let range_hdr = lines.find_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.trim().eq_ignore_ascii_case("range") {
                    Some(v.trim().to_string())
                } else {
                    None
                }
            });

            let (path, query) = raw_target.split_once('?').unwrap_or((raw_target, ""));
            let resp = handle(path, query, LOCAL_HTTP_ORIGIN).await;
            let status = resp.status().as_u16();
            let ctype = resp
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let cache = resp
                .headers()
                .get("Cache-Control")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("no-store")
                .to_string();
            let body = resp.into_body();
            let is_head = method.eq_ignore_ascii_case("HEAD");

            if status == 200 {
                if let Some(ref rh) = range_hdr {
                    if let Some((start, end)) = parse_byte_range(rh, body.len()) {
                        let slice = &body[start..=end];
                        let hdr = format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: {cache}\r\nConnection: close\r\n\r\n",
                            slice.len(),
                            body.len()
                        );
                        let _ = stream.write_all(hdr.as_bytes()).await;
                        if !is_head {
                            let _ = stream.write_all(slice).await;
                        }
                        return;
                    }
                }
            }

            let reason = match status {
                200 => "OK",
                400 => "Bad Request",
                404 => "Not Found",
                _ => "Bad Gateway",
            };
            let hdr = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: {cache}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(hdr.as_bytes()).await;
            if !is_head {
                let _ = stream.write_all(&body).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn live_play_chain() {
        use crate::net::edge;
        let play = edge("GET", "/api/videos/117/play?ep=3&page_texts=0", None, None).await
            .expect("play api");
        let url = play["video_url"].as_str().expect("video_url").to_string();
        println!("play url: {}", &url[..url.len().min(90)]);
        let (_, bytes) = fetch_bytes(&url).await.expect("fetch playlist");
        let text = String::from_utf8_lossy(&bytes);
        println!("raw playlist len={} head={}", text.len(), &text[..text.len().min(160)]);
        let q = format!("u={}", enc(&url));
        let resp = handle("/hls", &q, LOCAL_ORIGIN).await;
        let body = String::from_utf8_lossy(resp.body()).to_string();
        println!("proxied status={} len={}", resp.status(), body.len());
        assert!(body.contains("#EXTM3U"));
        // 取一个分片验证
        let seg_line = body.lines()
            .find(|l| !l.starts_with('#') && l.contains("/seg?u="))
            .expect("seg line").to_string();
        println!("seg line: {}", &seg_line[..seg_line.len().min(120)]);
        let seg_q = seg_line.split("?u=").nth(1).unwrap();
        let seg = handle("/seg", &format!("u={seg_q}"), LOCAL_ORIGIN).await;
        println!("segment status={} len={}", seg.status(), seg.body().len());
        assert_eq!(seg.status(), 200);
        assert!(seg.body().len() > 1000);
    }

    #[tokio::test]
    async fn playlist_rewrite_works() {
        let m3u8 = "https://yd-lphu-hls.hzjvlo.cn/videos5/247f3c9862e8e1537ade0b20c45ac962/247f3c9862e8e1537ade0b20c45ac962.m3u8?auth_key=1793700503-0-0-b9575bb11258cf40cd5499c052fc5820&v=3&time=0&via=hgdj&via_bm=dx";
        let q = format!("u={}", enc(m3u8));
        let resp = handle("/hls", &q, LOCAL_ORIGIN).await;
        let body = String::from_utf8_lossy(resp.body()).to_string();
        println!("status={} len={}", resp.status(), body.len());
        println!("--- head ---\n{}", &body[..body.len().min(600)]);
        assert!(body.contains("#EXTM3U"), "not a playlist: {body}");
        assert!(body.contains("hg.localhost/seg?u="), "segments not rewritten");
    }

    #[tokio::test]
    async fn cover_decrypt_works() {
        let url = "https://pic.drleao.cn/upload_01/upload/20261029/2026102918545028336.jpg?auth_key=1793707703-0-0-1cbd9389b0b69141dd741f16bb71397a";
        match load_image(url).await {
            Ok((kind, bytes)) => {
                println!("kind={kind} len={}", bytes.len());
                assert!(kind.starts_with("image/"));
            }
            Err(e) => panic!("image failed: {e}"),
        }
    }
}