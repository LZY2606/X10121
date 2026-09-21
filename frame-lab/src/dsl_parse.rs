//! DSL 语法分析：词法记号 -> Protocol（结构形状）。语义检查在 dsl_check。

use crate::dsl_lex::{lex, Tok, Token};
use crate::model::*;

struct Cursor {
    toks: Vec<Token>,
    pos: usize,
}

impl Cursor {
    fn new(toks: Vec<Token>) -> Self {
        Cursor { toks, pos: 0 }
    }

    fn cur(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }

    fn skip_nl(&mut self) {
        while matches!(self.cur().map(|t| &t.tok), Some(Tok::Newline)) {
            self.pos += 1;
        }
    }

    fn end_stmt(&mut self) -> Result<(), String> {
        match self.cur().map(|t| &t.tok) {
            Some(Tok::Newline) => {
                self.pos += 1;
                self.skip_nl();
                Ok(())
            }
            Some(Tok::Sym(s)) if s == ";" => {
                self.pos += 1;
                self.skip_nl();
                Ok(())
            }
            _ => Err(format!(
                "第 {} 行: 语句需要换行或分号结束",
                self.cur().map(|t| t.line).unwrap_or(0)
            )),
        }
    }

    fn line(&self) -> usize {
        self.cur().map(|t| t.line).unwrap_or(0)
    }

    fn expect_sym(&mut self, s: &str) -> Result<(), String> {
        match self.cur() {
            Some(Token {
                tok: Tok::Sym(x), ..
            }) if x == s => {
                self.pos += 1;
                Ok(())
            }
            t => Err(format!(
                "第 {} 行: 期望符号 {:?}，实际为 {}",
                t.map(|t| t.line).unwrap_or(0),
                s,
                t.map(|t| tok_name(&t.tok)).unwrap_or_else(|| "文件结束".into())
            )),
        }
    }

    fn expect_ident(&mut self) -> Result<(String, usize), String> {
        match self.cur().cloned() {
            Some(Token {
                tok: Tok::Ident(s),
                line,
            }) => {
                self.pos += 1;
                Ok((s, line))
            }
            t => Err(format!(
                "第 {} 行: 期望标识符，实际为 {}",
                t.as_ref().map(|t| t.line).unwrap_or(0),
                t.as_ref()
                    .map(|t| tok_name(&t.tok))
                    .unwrap_or_else(|| "文件结束".into())
            )),
        }
    }

    fn eat_sym(&mut self, s: &str) -> bool {
        if matches!(self.cur(), Some(Token { tok: Tok::Sym(x), .. }) if x == s) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
}

fn tok_name(t: &Tok) -> String {
    match t {
        Tok::Ident(s) => format!("标识符 {:?}", s),
        Tok::Num(n) => format!("数字 {}", n),
        Tok::Sym(s) => format!("符号 {:?}", s),
        Tok::Newline => "换行".to_string(),
    }
}

// ---------- 表达式 ----------

fn parse_expr(c: &mut Cursor) -> Result<Expr, String> {
    parse_or(c)
}

fn parse_or(c: &mut Cursor) -> Result<Expr, String> {
    let mut left = parse_and(c)?;
    while matches!(c.cur(), Some(Token { tok: Tok::Sym(s), .. }) if s == "||") {
        let line = c.line();
        c.pos += 1;
        let right = parse_and(c)?;
        left = Expr::Bin(
            Box::new(left),
            BinOp::Or,
            Box::new(right),
        );
        let _ = line;
    }
    Ok(left)
}

fn parse_and(c: &mut Cursor) -> Result<Expr, String> {
    let mut left = parse_cmp(c)?;
    while matches!(c.cur(), Some(Token { tok: Tok::Sym(s), .. }) if s == "&&") {
        c.pos += 1;
        let right = parse_cmp(c)?;
        left = Expr::Bin(Box::new(left), BinOp::And, Box::new(right));
    }
    Ok(left)
}

fn parse_cmp(c: &mut Cursor) -> Result<Expr, String> {
    let mut left = parse_add(c)?;
    loop {
        let op = match c.cur() {
            Some(Token { tok: Tok::Sym(s), .. }) => match s.as_str() {
                "==" => Some(BinOp::Eq),
                "!=" => Some(BinOp::Ne),
                "<=" => Some(BinOp::Le),
                ">=" => Some(BinOp::Ge),
                "<" => Some(BinOp::Lt),
                ">" => Some(BinOp::Gt),
                _ => None,
            },
            _ => None,
        };
        if let Some(op) = op {
            c.pos += 1;
            let right = parse_add(c)?;
            left = Expr::Bin(Box::new(left), op, Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_add(c: &mut Cursor) -> Result<Expr, String> {
    let mut left = parse_mul(c)?;
    loop {
        let op = match c.cur() {
            Some(Token { tok: Tok::Sym(s), .. }) if s == "+" => BinOp::Add,
            Some(Token { tok: Tok::Sym(s), .. }) if s == "-" => BinOp::Sub,
            _ => break,
        };
        c.pos += 1;
        let right = parse_mul(c)?;
        left = Expr::Bin(Box::new(left), op, Box::new(right));
    }
    Ok(left)
}

fn parse_mul(c: &mut Cursor) -> Result<Expr, String> {
    let mut left = parse_unary(c)?;
    loop {
        let op = match c.cur() {
            Some(Token { tok: Tok::Sym(s), .. }) if s == "*" => BinOp::Mul,
            Some(Token { tok: Tok::Sym(s), .. }) if s == "/" => BinOp::Div,
            _ => break,
        };
        c.pos += 1;
        let right = parse_unary(c)?;
        left = Expr::Bin(Box::new(left), op, Box::new(right));
    }
    Ok(left)
}

fn parse_unary(c: &mut Cursor) -> Result<Expr, String> {
    parse_primary(c)
}

fn parse_primary(c: &mut Cursor) -> Result<Expr, String> {
    // 支持负整数字面量：- 数字
    if matches!(c.cur(), Some(Token { tok: Tok::Sym(s), .. }) if s == "-")
        && matches!(c.toks.get(c.pos + 1), Some(Token { tok: Tok::Num(_), .. }))
    {
        c.pos += 1;
        if let Some(Token { tok: Tok::Num(n), .. }) = c.cur().cloned() {
            c.pos += 1;
            return Ok(Expr::Lit(n.wrapping_neg()));
        }
    }
    match c.cur().cloned() {
        Some(Token {
            tok: Tok::Num(n), ..
        }) => {
            c.pos += 1;
            Ok(Expr::Lit(n))
        }
        Some(Token {
            tok: Tok::Sym(s), ..
        }) if s == "(" => {
            c.pos += 1;
            let e = parse_expr(c)?;
            c.expect_sym(")")?;
            Ok(e)
        }
        Some(Token {
            tok: Tok::Sym(s),
            line,
        }) if s == "@" => {
            c.pos += 1;
            let (name, _) = c.expect_ident()?;
            if c.eat_sym(".") {
                let (tail, end_line) = c.expect_ident()?;
                if tail != "end" {
                    return Err(format!("第 {} 行: @{} 后只支持 .end", end_line, name));
                }
                Ok(Expr::EndOf(name))
            } else {
                let _ = line;
                Ok(Expr::StartOf(name))
            }
        }
        Some(Token {
            tok: Tok::Ident(s),
            line,
        }) => {
            c.pos += 1;
            let _ = line;
            Ok(Expr::Var(s))
        }
        t => Err(format!(
            "第 {} 行: 表达式中出现意外的 {}",
            t.as_ref().map(|t| t.line).unwrap_or(0),
            t.as_ref()
                .map(|t| tok_name(&t.tok))
                .unwrap_or_else(|| "文件结束".into())
        )),
    }
}

// ---------- 结构与字段 ----------

fn int_kind(name: &str) -> Option<IntKind> {
    Some(match name {
        "u8" => IntKind::U8,
        "u16be" => IntKind::U16Be,
        "u16le" => IntKind::U16Le,
        "u24be" => IntKind::U24Be,
        "u32be" => IntKind::U32Be,
        "u32le" => IntKind::U32Le,
        _ => return None,
    })
}

/// 解析字段类型（不含名称）。
fn parse_field_kind(c: &mut Cursor, keyword: &str) -> Result<FieldKind, String> {
    if let Some(kind) = int_kind(keyword) {
        return Ok(FieldKind::Int(kind));
    }
    match keyword {
        "bytes" => {
            let nxt = c.cur().cloned();
            match nxt {
                Some(Token {
                    tok: Tok::Num(n), ..
                }) => {
                    c.pos += 1;
                    Ok(FieldKind::FixedBytes(n as usize))
                }
                _ => {
                    let e = parse_expr(c)?;
                    Ok(FieldKind::VarBytes(e))
                }
            }
        }
        "checksum" => {
            let spec = parse_check_spec(c)?;
            Ok(FieldKind::Checksum(spec))
        }
        "assert" => {
            let e = parse_expr(c)?;
            Ok(FieldKind::Assert(e))
        }
        other => {
            let size = if c.eat_sym("<") {
                let e = parse_expr(c)?;
                c.expect_sym(">")?;
                Some(e)
            } else {
                None
            };
            Ok(FieldKind::StructRef(other.to_string(), size))
        }
    }
}

fn parse_bound(c: &mut Cursor) -> Result<RangeBound, String> {
    if c.eat_sym("@") {
        let (name, _) = c.expect_ident()?;
        if c.eat_sym(".") {
            let (tail, line) = c.expect_ident()?;
            if tail != "end" {
                return Err(format!("第 {} 行: 偏移标记只支持 @字段.end", line));
            }
            Ok(RangeBound::EndOf(name))
        } else {
            Ok(RangeBound::StartOf(name))
        }
    } else if matches!(c.cur(), Some(Token { tok: Tok::Ident(s), .. }) if s == "start") {
        c.pos += 1;
        Ok(RangeBound::StructStart)
    } else if matches!(c.cur(), Some(Token { tok: Tok::Ident(s), .. }) if s == "end") {
        c.pos += 1;
        Ok(RangeBound::StructEnd)
    } else {
        match c.cur().cloned() {
            Some(Token {
                tok: Tok::Num(n), ..
            }) => {
                c.pos += 1;
                Ok(RangeBound::Const(n))
            }
            t => Err(format!(
                "第 {} 行: 校验区间边界应为 start/end/@字段/@字段.end/常量",
                t.as_ref().map(|t| t.line).unwrap_or(0)
            )),
        }
    }
}

fn parse_check_spec(c: &mut Cursor) -> Result<CheckSpec, String> {
    let mut spec = CheckSpec {
        algo: CheckAlgo::Sum8,
        from: None,
        to: None,
        skip_self: true,
    };
    if c.eat_sym(":") {
        let (algo, line) = c.expect_ident()?;
        spec.algo = match algo.as_str() {
            "sum8" => CheckAlgo::Sum8,
            "xor8" => CheckAlgo::Xor8,
            "sum16be" => CheckAlgo::Sum16Be,
            _ => return Err(format!("第 {} 行: 未知校验算法 {}", line, algo)),
        };
    }
    loop {
        match c.cur().map(|t| &t.tok) {
            Some(Tok::Ident(s)) if s == "from" => {
                c.pos += 1;
                spec.from = Some(parse_bound(c)?);
            }
            Some(Tok::Ident(s)) if s == "to" => {
                c.pos += 1;
                spec.to = Some(parse_bound(c)?);
            }
            Some(Tok::Ident(s)) if s == "include_self" => {
                c.pos += 1;
                spec.skip_self = false;
            }
            _ => break,
        }
    }
    Ok(spec)
}

/// 解析 `repeat` 块内的一个体类型。
fn parse_repeat_body(c: &mut Cursor, keyword: &str) -> Result<RepeatBody, String> {
    if keyword == "bytes" {
        return Ok(RepeatBody::Raw);
    }
    if keyword == "struct" {
        let body = parse_struct_block(c, None)?;
        return Ok(RepeatBody::StructDef(body));
    }
    if int_kind(keyword).is_some() || keyword == "checksum" || keyword == "assert" {
        return Err(format!("repeat 体内不允许字段类型 {}", keyword));
    }
    let size = if c.eat_sym("<") {
        let e = parse_expr(c)?;
        c.expect_sym(">")?;
        Some(e)
    } else {
        None
    };
    let _ = size;
    Ok(RepeatBody::StructRef(keyword.to_string()))
}

fn parse_when_clause(c: &mut Cursor) -> Result<Option<Expr>, String> {
    if matches!(c.cur(), Some(Token { tok: Tok::Ident(s), .. }) if s == "when") {
        c.pos += 1;
        Ok(Some(parse_expr(c)?))
    } else {
        Ok(None)
    }
}

/// 解析字段序列，直到 `}`。允许 `repeat { ... } count <expr>` 块。
fn parse_struct_fields(c: &mut Cursor) -> Result<Vec<Field>, String> {
    let mut fields = Vec::new();
    loop {
        match c.cur().cloned() {
            Some(Token {
                tok: Tok::Sym(s), ..
            }) if s == "}" => {
                c.pos += 1;
                break;
            }
            Some(Token { tok: Tok::Newline, .. }) => {
                c.pos += 1;
            }
            Some(Token {
                tok: Tok::Ident(kw),
                line,
            }) => {
                c.pos += 1;
                if kw == "repeat" {
                    let (rep_name, rep_line) = c.expect_ident()?;
                    c.expect_sym("{")?;
                    c.skip_nl();
                    let (body_kw, body_line) = c.expect_ident()?;
                    let body = parse_repeat_body(c, &body_kw)?;
                    let _ = body_line;
                    // 体声明结束（repeat 体是单行）
                    c.end_stmt()?;
                    c.skip_nl();
                    c.expect_sym("}")?;
                    if !matches!(c.cur(), Some(Token { tok: Tok::Ident(s), .. }) if s == "count")
                    {
                        return Err(format!("第 {} 行: repeat 块后需要 count <表达式>", c.line()));
                    }
                    c.pos += 1;
                    let count = parse_expr(c)?;
                    let when = parse_when_clause(c)?;
                    c.end_stmt()?;
                    fields.push(Field {
                        name: rep_name,
                        kind: FieldKind::Repeat(count, body),
                        when,
                        line: rep_line,
                    });
                } else if kw == "checksum" {
                    let (cname, _) = c.expect_ident()?;
                    let mut spec = CheckSpec {
                        algo: CheckAlgo::Sum8,
                        from: None,
                        to: None,
                        skip_self: true,
                    };
                    if c.eat_sym(":") {
                        let (algo, aline) = c.expect_ident()?;
                        spec.algo = match algo.as_str() {
                            "sum8" => CheckAlgo::Sum8,
                            "xor8" => CheckAlgo::Xor8,
                            "sum16be" => CheckAlgo::Sum16Be,
                            _ => return Err(format!("第 {} 行: 未知校验算法 {}", aline, algo)),
                        };
                    }
                    loop {
                        match c.cur().map(|t| &t.tok) {
                            Some(Tok::Ident(k)) if k == "from" => {
                                c.pos += 1;
                                spec.from = Some(parse_bound(c)?);
                            }
                            Some(Tok::Ident(k)) if k == "to" => {
                                c.pos += 1;
                                spec.to = Some(parse_bound(c)?);
                            }
                            Some(Tok::Ident(k)) if k == "include_self" => {
                                c.pos += 1;
                                spec.skip_self = false;
                            }
                            _ => break,
                        }
                    }
                    let when = parse_when_clause(c)?;
                    c.end_stmt()?;
                    fields.push(Field {
                        name: cname,
                        kind: FieldKind::Checksum(spec),
                        when,
                        line,
                    });
                } else {
                    let kind = parse_field_kind(c, &kw)?;
                    let name = if matches!(kind, FieldKind::Assert(_)) {
                        kw.clone()
                    } else {
                        c.expect_ident()?.0
                    };
                    let when = parse_when_clause(c)?;
                    c.end_stmt()?;
                    fields.push(Field {
                        name,
                        kind,
                        when,
                        line,
                    });
                }
            }
            t => {
                return Err(format!(
                    "第 {} 行: 结构体内出现意外的 {}",
                    t.as_ref().map(|t| t.line).unwrap_or(0),
                    t.as_ref()
                        .map(|t| tok_name(&t.tok))
                        .unwrap_or_else(|| "'}'".into())
                ));
            }
        }
    }
    Ok(fields)
}

fn parse_struct_block(c: &mut Cursor, name: Option<String>) -> Result<StructDef, String> {
    c.expect_sym("{")?;
    c.skip_nl();
    let fields = parse_struct_fields(c)?;
    Ok(StructDef { name, fields })
}

// ---------- 顶层 ----------

pub fn build_protocol(src: &str) -> Result<Protocol, String> {
    let toks = lex(src)?;
    let mut c = Cursor::new(toks);
    c.skip_nl();

    let mut name = None;
    let mut root = None;
    let mut max_depth = 16usize;
    let mut structs = Vec::new();

    loop {
        match c.cur().cloned() {
            None => break,
            Some(Token { tok: Tok::Newline, .. }) => {
                c.pos += 1;
            }
            Some(Token {
                tok: Tok::Ident(kw),
                line,
            }) => {
                c.pos += 1;
                match kw.as_str() {
                    "protocol" => {
                        let (n, _) = c.expect_ident()?;
                        c.end_stmt()?;
                        name = Some(n);
                    }
                    "root" => {
                        let (r, _) = c.expect_ident()?;
                        c.end_stmt()?;
                        root = Some(r);
                    }
                    "max_depth" => {
                        match c.cur().cloned() {
                            Some(Token {
                                tok: Tok::Num(n), ..
                            }) => {
                                c.pos += 1;
                                max_depth = n as usize;
                            }
                            _ => return Err(format!("第 {} 行: max_depth 后需要数字", line)),
                        }
                        c.end_stmt()?;
                    }
                    "struct" => {
                        let (sname, _) = c.expect_ident()?;
                        let s = parse_struct_block(&mut c, Some(sname))?;
                        structs.push(s);
                    }
                    other => {
                        return Err(format!(
                            "第 {} 行: 顶层只允许 protocol/root/max_depth/struct，遇到 {}",
                            line, other
                        ));
                    }
                }
            }
            Some(Token { line, .. }) => {
                return Err(format!("第 {} 行: 顶层出现意外记号", line));
            }
        }
    }

    let name = name.ok_or_else(|| "缺少 protocol <名称> 声明".to_string())?;
    let root = root.ok_or_else(|| "缺少 root <结构名> 声明".to_string())?;
    Ok(Protocol {
        name,
        root,
        max_depth,
        structs,
    })
}
