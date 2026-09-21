//! 表达式求值（运行期：引用此前已解析的同结构整数字段）。

use crate::model::*;

#[derive(Debug, Clone)]
pub enum Val {
    Int(u64),
    Bool(bool),
}

#[derive(Debug, Clone)]
pub struct ResolvedField {
    pub value: u64,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub fields: Vec<(String, ResolvedField)>,
}

impl Scope {
    pub fn lookup(&self, name: &str) -> Option<&ResolvedField> {
        self.fields.iter().rev().find(|(n, _)| n == name).map(|(_, f)| f)
    }
}

#[derive(Debug)]
pub struct EvalError {
    pub message: String,
}

pub fn eval(e: &Expr, scope: &Scope, struct_start: usize) -> Result<Val, EvalError> {
    match e {
        Expr::Lit(n) => Ok(Val::Int(*n)),
        Expr::Var(name) => scope
            .lookup(name)
            .map(|f| Val::Int(f.value))
            .ok_or_else(|| EvalError {
                message: format!("字段 {} 尚未解析或不存在", name),
            }),
        Expr::StartOf(name) => scope
            .lookup(name)
            .map(|f| Val::Int(f.start as u64))
            .ok_or_else(|| EvalError {
                message: format!("字段 {} 的起始偏移不可用", name),
            }),
        Expr::EndOf(name) => scope
            .lookup(name)
            .map(|f| Val::Int(f.end as u64))
            .ok_or_else(|| EvalError {
                message: format!("字段 {} 的结束偏移不可用", name),
            }),
        Expr::Bin(a, op, b) => {
            let av = eval(a, scope, struct_start)?;
            let bv = eval(b, scope, struct_start)?;
            match op {
                BinOp::And => match (av, bv) {
                    (Val::Bool(x), Val::Bool(y)) => Ok(Val::Bool(x && y)),
                    _ => Err(EvalError {
                        message: "&& 两侧必须为布尔值".into(),
                    }),
                },
                BinOp::Or => match (av, bv) {
                    (Val::Bool(x), Val::Bool(y)) => Ok(Val::Bool(x || y)),
                    _ => Err(EvalError {
                        message: "|| 两侧必须为布尔值".into(),
                    }),
                },
                _ => {
                    let (x, y) = match (av, bv) {
                        (Val::Int(x), Val::Int(y)) => (x, y),
                        _ => {
                            return Err(EvalError {
                                message: "算术/比较运算需要整数".into(),
                            })
                        }
                    };
                    Ok(match op {
                        BinOp::Add => Val::Int(x.wrapping_add(y)),
                        BinOp::Sub => Val::Int(x.wrapping_sub(y)),
                        BinOp::Mul => Val::Int(x.wrapping_mul(y)),
                        BinOp::Div => {
                            if y == 0 {
                                return Err(EvalError {
                                    message: "表达式除以 0".into(),
                                });
                            }
                            Val::Int(x / y)
                        }
                        BinOp::Eq => Val::Bool(x == y),
                        BinOp::Ne => Val::Bool(x != y),
                        BinOp::Lt => Val::Bool(x < y),
                        BinOp::Le => Val::Bool(x <= y),
                        BinOp::Gt => Val::Bool(x > y),
                        BinOp::Ge => Val::Bool(x >= y),
                        BinOp::And | BinOp::Or => unreachable!(),
                    })
                }
            }
        }
    }
}

pub fn eval_usize(e: &Expr, scope: &Scope, struct_start: usize) -> Result<usize, EvalError> {
    match eval(e, scope, struct_start)? {
        Val::Int(n) => Ok(n as usize),
        Val::Bool(_) => Err(EvalError {
            message: "期望整数，得到布尔值".into(),
        }),
    }
}

pub fn eval_bool(e: &Expr, scope: &Scope, struct_start: usize) -> Result<bool, EvalError> {
    match eval(e, scope, struct_start)? {
        Val::Bool(b) => Ok(b),
        Val::Int(_) => Err(EvalError {
            message: "when/assert 条件必须为布尔表达式".into(),
        }),
    }
}

pub fn resolve_bound(
    b: &RangeBound,
    scope: &Scope,
    struct_start: usize,
    struct_end: Option<usize>,
) -> Result<usize, EvalError> {
    Ok(match b {
        RangeBound::StartOf(n) => scope
            .lookup(n)
            .map(|f| f.start)
            .ok_or_else(|| EvalError {
                message: format!("字段 {} 的偏移不可用", n),
            })?,
        RangeBound::EndOf(n) => scope
            .lookup(n)
            .map(|f| f.end)
            .ok_or_else(|| EvalError {
                message: format!("字段 {} 的偏移不可用", n),
            })?,
        RangeBound::StructStart => struct_start,
        RangeBound::StructEnd => struct_end
            .ok_or_else(|| EvalError {
                message: "end 边界不能用于无界结构".into(),
            })?,
        RangeBound::Const(n) => *n as usize,
    })
}
