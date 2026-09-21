//! DSL 词法分析。

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Num(u64),
    Sym(String),
    Newline,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
}

pub fn lex(src: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut line = 1usize;
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b' ' | b'\t' | b'\r' => i += 1,
            b'\n' => {
                out.push(Token {
                    tok: Tok::Newline,
                    line,
                });
                line += 1;
                i += 1;
            }
            b'0'..=b'9' => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let s = std::str::from_utf8(&bytes[start..i]).unwrap();
                let n = s
                    .parse::<u64>()
                    .map_err(|_| format!("第 {} 行: 数字 {} 超出 u64", line, s))?;
                out.push(Token {
                    tok: Tok::Num(n),
                    line,
                });
            }
            b'_' | b'a'..=b'z' | b'A'..=b'Z' => {
                let start = i;
                while i < bytes.len() {
                    match bytes[i] {
                        b'_' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => i += 1,
                        _ => break,
                    }
                }
                let s = std::str::from_utf8(&bytes[start..i]).unwrap().to_string();
                out.push(Token {
                    tok: Tok::Ident(s),
                    line,
                });
            }
            _ => {
                let three = |a: u8, b: u8, c: u8| {
                    bytes.get(i..i + 3) == Some(&[a, b, c])
                };
                let two = |a: u8, b: u8| bytes.get(i..i + 2) == Some(&[a, b]);
                if three(b'=', b'=', b'=')
                    || three(b'!', b'=', b'=')
                    || three(b'<', b'=', b'=')
                    || three(b'>', b'=', b'=')
                    || three(b'&', b'&', b'&')
                    || three(b'|', b'|', b'|')
                {
                    let s = std::str::from_utf8(&bytes[i..i + 3]).unwrap();
                    out.push(Token {
                        tok: Tok::Sym(s.to_string()),
                        line,
                    });
                    i += 3;
                } else if two(b'=', b'=')
                    || two(b'!', b'=')
                    || two(b'<', b'=')
                    || two(b'>', b'=')
                    || two(b'&', b'&')
                    || two(b'|', b'|')
                {
                    let s = std::str::from_utf8(&bytes[i..i + 2]).unwrap();
                    out.push(Token {
                        tok: Tok::Sym(s.to_string()),
                        line,
                    });
                    i += 2;
                } else {
                    let ok = matches!(
                        c,
                        b'{' | b'}'
                            | b'('
                            | b')'
                            | b';'
                            | b':'
                            | b','
                            | b'+'
                            | b'-'
                            | b'*'
                            | b'/'
                            | b'.'
                            | b'<'
                            | b'>'
                            | b'@'
                    );
                    if !ok {
                        return Err(format!("第 {} 行: 非法字符 {:?}", line, c as char));
                    }
                    out.push(Token {
                        tok: Tok::Sym((c as char).to_string()),
                        line,
                    });
                    i += 1;
                }
            }
        }
    }
    out.push(Token {
        tok: Tok::Newline,
        line,
    });
    Ok(out)
}
