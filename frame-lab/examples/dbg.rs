fn main() {
    let src = framelab::seeds::TLV_RECURSIVE;
    for (i,l) in src.lines().enumerate(){println!("{}: {}",i+1,l);}
    let toks = framelab::dsl_lex::lex(src).unwrap();
    for t in &toks { println!("{:?} @ {}", t.tok, t.line); }
}
