//! 嵌入前端静态资源。

pub fn read(name: &str) -> Option<Vec<u8>> {
    match name {
        "index.html" => Some(include_bytes!("../static/index.html").to_vec()),
        "app.js" => Some(include_bytes!("../static/app.js").to_vec()),
        "style.css" => Some(include_bytes!("../static/style.css").to_vec()),
        _ => None,
    }
}
