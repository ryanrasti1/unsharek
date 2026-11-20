//! `compile!(policy(args…))`: the seccomp policy `policy`, a plain Rust function of this file
//!
//! ```ignore
//! pub fn policy(pid: u64, strict: bool) -> impl Fn(&libc::seccomp_data) -> u32 {
//!     move |d| { /* the subset */ }
//! }
//! pub fn filter(pid: u64, strict: bool) -> Vec<libc::sock_filter> {
//!     seccomp_fn::compile!(policy(pid, strict))
//! }
//! ```
//!
//! compiled to classic BPF: the macro reads its call's own file (`Span::local_file`), finds
//! `fn policy` there (at the top level or in an inline `mod`), and compiles the closure it
//! returns, its params bound to the call's arguments. No macro touches `policy`: rustc compiles
//! it as written.
//!
//! **Not trusted.** Nothing here is part of the claim: `seccomp-fn-validate` proves (Kani) that
//! the program gives the function's verdict on every input. This crate is only the compiler.
//!
//! The output: each condition without `d` (`if threads`, a guard's `fork && …`) is decided when
//! the program is built, so the program has one shape per combination of their values; each
//! shape is a constant array of instructions whose `k` fields are the params' values (patched
//! in: computed from the arguments as the array is built). No runtime library: the types are
//! libc's (`libc::sock_filter`), so the calling crate depends on `libc`.
//!
//! The subset (anything else is a compile error naming it): `if`/`else`, `return`, `match` on
//! `d.nr` (or `d.nr as i64`; literal or const patterns, `|`, `_`, guards), `let` of an
//! expression without `d`; conditions are `&&`, `||`, `!`, parentheses, comparisons of a field
//! of `d` (`d.nr` and `d.nr as u32`, `d.arch`, `d.instruction_pointer`, `d.args[i]`) with an
//! expression without `d`, and expressions without `d`. Values returned are expressions
//! without `d`.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as Ts, TokenTree};
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{BinOp, Block, Expr, FnArg, Ident, ItemFn, Lit, Pat, Stmt, UnOp};

type R<T> = syn::Result<T>;

fn err<T>(s: impl Spanned, what: &str) -> R<T> {
    Err(syn::Error::new(s.span(), format!("seccomp_fn::compile!: {what} is outside the subset")))
}

#[proc_macro]
pub fn compile(input: TokenStream) -> TokenStream {
    let call = syn::parse_macro_input!(input as syn::ExprCall);
    match expand(&call) {
        Ok(t) => t.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Every `fn name` in `items` and the inline `mod`s among them, at any depth.
fn find_all<'a>(items: &'a [syn::Item], name: &Ident, out: &mut Vec<&'a ItemFn>) {
    for i in items {
        match i {
            syn::Item::Fn(f) if f.sig.ident == *name => out.push(f),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    find_all(inner, name, out);
                }
            }
            _ => {}
        }
    }
}

/// The `fn` the call names in the file: by its path from the file's root through inline `mod`s
/// (`compile!(table::policy(…))`: `mod table`'s `fn policy`), or, a bare name, the one `fn` of
/// that name anywhere in the file (two are an error: the call must name its module). A proc
/// macro can't see where it is called from, so the path, not the call's place, says.
fn find<'a>(items: &'a [syn::Item], path: &syn::Path) -> R<&'a ItemFn> {
    let segs: Vec<&Ident> = path.segments.iter().map(|s| &s.ident).filter(|i| *i != "self" && *i != "crate").collect();
    let (name, mods) = segs.split_last().expect("a path has a name");
    let mut items = items;
    for m in mods {
        items = items
            .iter()
            .find_map(|i| match i {
                syn::Item::Mod(x) if x.ident == **m => x.content.as_ref().map(|(_, inner)| &inner[..]),
                _ => None,
            })
            .ok_or_else(|| syn::Error::new(m.span(), format!("seccomp_fn::compile!: no inline `mod {m}` in the file on the call's path")))?;
    }
    if !mods.is_empty() {
        return items
            .iter()
            .find_map(|i| match i {
                syn::Item::Fn(f) if f.sig.ident == **name => Some(f),
                _ => None,
            })
            .ok_or_else(|| syn::Error::new(name.span(), format!("seccomp_fn::compile!: no `fn {name}` at the call's path in the file")));
    }
    let mut all = vec![];
    find_all(items, name, &mut all);
    match all.as_slice() {
        [f] => Ok(f),
        [] => Err(syn::Error::new(name.span(), format!("seccomp_fn::compile!: no `fn {name}` in the call's file (a plain fn of that file)"))),
        _ => Err(syn::Error::new(
            name.span(),
            format!("seccomp_fn::compile!: {} `fn {name}`s in the call's file: name its module from the file's root (`compile!(m::{name}(…))`)", all.len()),
        )),
    }
}

fn expand(call: &syn::ExprCall) -> R<Ts> {
    let Expr::Path(p) = &*call.func else { return err(&call.func, "a call of anything but a function by name") };
    let name = p.path.segments.last().map(|s| s.ident.clone()).expect("a path has a name");
    let file = Span::call_site().unwrap().local_file().ok_or_else(|| {
        syn::Error::new(Span::call_site(), "seccomp_fn::compile!: the call's file isn't known (macro expanded from no file)")
    })?;
    let src = std::fs::read_to_string(&file)
        .map_err(|e| syn::Error::new(Span::call_site(), format!("seccomp_fn::compile!: reading {}: {e}", file.display())))?;
    let ast = syn::parse_file(&src).map_err(|e| syn::Error::new(Span::call_site(), format!("seccomp_fn::compile!: parsing {}: {e}", file.display())))?;
    let f = find(&ast.items, &p.path)?;
    // the params, bound to the call's arguments
    let (mut binds, mut params) = (vec![], vec![]);
    if f.sig.inputs.len() != call.args.len() {
        return err(&call.args, &format!("a call with {} arguments of `{name}`, which takes {}", call.args.len(), f.sig.inputs.len()));
    }
    for (a, v) in f.sig.inputs.iter().zip(&call.args) {
        let FnArg::Typed(t) = a else { return err(a, "a receiver") };
        let Pat::Ident(i) = &*t.pat else { return err(&t.pat, "a parameter pattern") };
        let (n, ty) = (&i.ident, &t.ty);
        binds.push(quote!(let #n: #ty = #v;));
        params.push(n.clone());
    }
    // the closure it returns: its block's only expression
    let closure = match f.block.stmts.as_slice() {
        [Stmt::Expr(Expr::Closure(c), None)] => c,
        _ => return err(&f.block, &format!("`fn {name}` whose body isn't a closure (`move |d| {{ … }}`)")),
    };
    let d = match closure.inputs.first() {
        Some(Pat::Ident(i)) => i.ident.clone(),
        Some(Pat::Type(t)) => match &*t.pat {
            Pat::Ident(i) => i.ident.clone(),
            p => return err(p, "a closure parameter other than `d`"),
        },
        _ => return err(closure, "a closure without its one parameter `d`"),
    };
    if closure.inputs.len() != 1 {
        return err(&closure.inputs, "a closure of more than `d`");
    }
    let body: Block = match &*closure.body {
        Expr::Block(b) => b.block.clone(),
        e => syn::parse_quote!({ #e }),
    };
    // First pass: the lets (hoisted: each is an expression without `d`) and the switches (each
    // distinct condition without `d`, by its text).
    let mut cx = Cx { d, switches: vec![], values: None, lets: vec![], asm: Asm::default() };
    cx.block(&body, &Pos::Tail)?;
    let switches = cx.switches.clone();
    if switches.len() > 6 {
        return err(&body, "more than 6 conditions without `d`");
    }
    let lets = std::mem::take(&mut cx.lets);
    let mut arms = vec![];
    for bits in 0..(1u32 << switches.len()) {
        let values: Vec<bool> = (0..switches.len()).map(|i| bits >> i & 1 == 1).collect();
        cx.values = Some(values.clone());
        cx.asm = Asm::default();
        cx.block(&body, &Pos::Tail)?;
        let insns = cx.asm.insns.iter().rev().map(|i| {
            let (code, jt, jf, k) = (i.code, i.jt, i.jf, &i.k);
            quote!(::libc::sock_filter { code: #code, jt: #jt, jf: #jf, k: #k })
        });
        arms.push(quote!((#(#values,)*) => ::std::vec![#(#insns),*],));
    }
    let names: Vec<Ident> = (0..switches.len()).map(|i| format_ident!("__switch{}", i)).collect();
    let conds: Vec<&Expr> = switches.iter().map(|(_, e)| e).collect();
    Ok(quote! {{
        #[allow(unused_variables, unused_parens, non_snake_case, clippy::all)]
        let __prog: ::std::vec::Vec<::libc::sock_filter> = {
            #(#binds)*
            #(#lets)*
            #(let #names: bool = #conds;)*
            match (#(#names,)*) {
                #(#arms)*
            }
        };
        __prog
    }})
}

/// An instruction, its `k` an expression of the params (a u32).
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: Ts,
}

/// Where a jump goes: an instruction already emitted, counted from the program's end.
type Label = usize;

/// The program, emitted backwards from its last instruction: every jump is forward, so its
/// targets are already there and its offsets known as it is written. One fixed template per
/// construct.
#[derive(Default)]
struct Asm {
    insns: Vec<Insn>,
}

// libc's offsets in seccomp_data, little-endian halves (x86-64; checked by the proof anyway)
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_IP: u32 = 8;
const OFF_ARGS: u32 = 16;
const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGT_K: u16 = 0x25;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;
const JA: u16 = 0x05;

impl Asm {
    fn push(&mut self, code: u16, jt: usize, jf: usize, k: Ts) -> R<Label> {
        assert!(jt <= 255 && jf <= 255, "a jump over 255 instructions not through a JA");
        self.insns.push(Insn { code, jt: jt as u8, jf: jf as u8, k });
        Ok(self.insns.len())
    }
    fn dist(&self, to: Label) -> usize {
        self.insns.len() - to
    }
    fn ret(&mut self, k: Ts) -> R<Label> {
        self.push(RET_K, 0, 0, k)
    }
    /// A conditional jump: a target over 255 instructions away is reached through a JA.
    fn jump(&mut self, code: u16, k: Ts, t: Label, f: Label) -> R<Label> {
        let t = if self.dist(t) > 255 { self.far(t)? } else { t };
        let f = if self.dist(f) > 255 { self.far(f)? } else { f };
        let (jt, jf) = (self.dist(t), self.dist(f));
        self.push(code, jt, jf, k)
    }
    fn far(&mut self, to: Label) -> R<Label> {
        let k = self.dist(to) as u32;
        self.push(JA, 0, 0, quote!(#k))
    }
    fn load(&mut self, off: u32) -> R<Label> {
        self.push(LD_W_ABS, 0, 0, quote!(#off))
    }
}

#[derive(Clone, Copy)]
enum Field {
    /// `d.nr` (libc's: an i32, compared as its bits), or `d.nr as u32`
    Nr { signed: bool },
    Arch,
    Ip,
    Arg(u32),
}

impl Field {
    fn wide(self) -> bool {
        matches!(self, Field::Ip | Field::Arg(_))
    }
    /// (low half, high half)
    fn offsets(self) -> (u32, u32) {
        match self {
            Field::Nr { .. } => (OFF_NR, OFF_NR),
            Field::Arch => (OFF_ARCH, OFF_ARCH),
            Field::Ip => (OFF_IP, OFF_IP + 4),
            Field::Arg(i) => (OFF_ARGS + 8 * i, OFF_ARGS + 8 * i + 4),
        }
    }
}

#[derive(Clone)]
enum Pos {
    Tail,
    Next(Label),
}

struct Cx {
    d: Ident,
    /// conditions without `d`, by their text, in the order first met
    switches: Vec<(String, Expr)>,
    /// this pass's value of each (None: the first pass, which only collects them)
    values: Option<Vec<bool>>,
    lets: Vec<Ts>,
    asm: Asm,
}

impl Cx {
    fn mentions(&self, t: &Ts) -> bool {
        t.clone().into_iter().any(|tt| match tt {
            TokenTree::Ident(i) => i == self.d,
            TokenTree::Group(g) => self.mentions(&g.stream()),
            _ => false,
        })
    }

    fn pure(&self, e: &Expr) -> bool {
        !self.mentions(&quote!(#e))
    }

    /// A condition without `d`: its value in this pass (true in the first, which only collects).
    fn switch(&mut self, e: &Expr) -> bool {
        let key = quote!(#e).to_string();
        let i = match self.switches.iter().position(|(k, _)| *k == key) {
            Some(i) => i,
            None => {
                self.switches.push((key, e.clone()));
                self.switches.len() - 1
            }
        };
        self.values.as_ref().is_none_or(|v| v[i])
    }

    fn block(&mut self, b: &Block, pos: &Pos) -> R<Label> {
        self.stmts(&b.stmts, pos)
    }

    fn stmts(&mut self, stmts: &[Stmt], pos: &Pos) -> R<Label> {
        let Some((s, rest)) = stmts.split_first() else {
            return match pos {
                Pos::Next(n) => Ok(*n),
                Pos::Tail => Err(syn::Error::new(Span::call_site(), "seccomp_fn::compile!: a block without a value")),
            };
        };
        match s {
            Stmt::Local(l) => {
                let Some(init) = &l.init else { return err(l, "`let` without a value") };
                if init.diverge.is_some() || !self.pure(&init.expr) {
                    return err(l, "`let` of an expression of `d`");
                }
                if self.values.is_none() {
                    self.lets.push(quote!(#l));
                }
                self.stmts(rest, pos)
            }
            Stmt::Expr(e, _) if rest.is_empty() => self.expr(e, pos),
            Stmt::Expr(e, _) => {
                let next = self.stmts(rest, pos)?;
                self.expr(e, &Pos::Next(next))
            }
            Stmt::Item(i) => err(i, "an item"),
            Stmt::Macro(m) => err(m, "a macro"),
        }
    }

    fn ret(&mut self, v: &Expr) -> R<Label> {
        if !self.pure(v) {
            return err(v, "a verdict computed from `d`");
        }
        self.asm.ret(quote!({ let __v: u32 = #v; __v }))
    }

    fn expr(&mut self, e: &Expr, pos: &Pos) -> R<Label> {
        match e {
            Expr::Paren(p) => self.expr(&p.expr, pos),
            Expr::Group(g) => self.expr(&g.expr, pos),
            Expr::Return(r) => match &r.expr {
                Some(v) => self.ret(v),
                None => err(r, "`return` without a value"),
            },
            Expr::Block(b) if b.label.is_none() => self.block(&b.block, pos),
            Expr::If(i) => {
                let c = &*i.cond;
                if self.pure(c) {
                    // decided when the program is built: only the branch taken is emitted (the
                    // first pass, which collects the switches, walks both)
                    if self.values.is_none() {
                        if let Some((_, e)) = &i.else_branch {
                            self.expr(e, pos)?;
                        }
                    }
                    return if self.switch(c) {
                        self.block(&i.then_branch, pos)
                    } else {
                        match (&i.else_branch, pos) {
                            (Some((_, e)), _) => self.expr(e, pos),
                            (None, Pos::Next(n)) => Ok(*n),
                            (None, Pos::Tail) => err(i, "`if` without `else` as the value"),
                        }
                    };
                }
                let f = match (&i.else_branch, pos) {
                    (Some((_, e)), _) => self.expr(e, pos)?,
                    (None, Pos::Next(n)) => *n,
                    (None, Pos::Tail) => return err(i, "`if` without `else` as the value"),
                };
                let t = self.block(&i.then_branch, pos)?;
                self.cond(c, t, f)
            }
            Expr::Match(m) => self.matches(m, pos),
            _ if matches!(pos, Pos::Tail) => self.ret(e),
            _ => err(e, &format!("the statement `{}`", quote!(#e))),
        }
    }

    /// `match d.nr`: arms in order; each its own test (a load of `nr`, a JEQ per pattern), so a
    /// guard may load what it likes. A guard's leading conjuncts without `d` are decided when
    /// the program is built.
    fn matches(&mut self, m: &syn::ExprMatch, pos: &Pos) -> R<Label> {
        let scrutinee = match &*m.expr {
            Expr::Cast(c) if matches!(&*c.ty, syn::Type::Path(p) if p.path.get_ident().is_some_and(|i| ["i64", "i128"].iter().any(|s| i == s))) => &*c.expr,
            e => e,
        };
        match self.field(scrutinee)? {
            Some(Field::Nr { signed: true }) => {}
            _ => return err(&m.expr, "`match` on anything but `d.nr` (or `d.nr as i64`)"),
        }
        let mut arms = vec![];
        let mut default = None;
        for arm in &m.arms {
            let (pat, guard) = match &arm.pat {
                Pat::Guard(g) => (&*g.pat, Some(&*g.guard)),
                p => (p, None),
            };
            let pats: Vec<&Pat> = match pat {
                Pat::Or(o) => o.cases.iter().collect(),
                p => vec![p],
            };
            let wild = pats.iter().any(|p| matches!(p, Pat::Wild(_)));
            for p in &pats {
                match p {
                    Pat::Wild(_) | Pat::Lit(_) | Pat::Path(_) => {}
                    Pat::Ident(i) if i.by_ref.is_none() && i.mutability.is_none() && i.subpat.is_none() => {}
                    p => return err(p, "a pattern other than a literal, a const or `_`"),
                }
            }
            if wild && guard.is_none() {
                default = Some(arm);
                break;
            }
            arms.push((pats, wild, guard, arm));
        }
        let mut next = match (default, pos) {
            (Some(arm), _) => self.expr(&arm.body, pos)?,
            (None, Pos::Next(l)) => *l,
            (None, Pos::Tail) => return err(m, "a `match` without `_` as the value"),
        };
        for (pats, wild, guard, arm) in arms.into_iter().rev() {
            let mut parts = vec![];
            if let Some(g) = guard {
                conjuncts(g, &mut parts);
            }
            let n_pure = parts.iter().take_while(|c| self.pure(c)).count();
            let mut taken = true;
            for c in &parts[..n_pure] {
                // (each collected, even after one is false: every pass sees the same switches)
                taken &= self.switch(c);
            }
            if !taken && self.values.is_some() {
                continue;
            }
            let body = self.expr(&arm.body, pos)?;
            let rest = &parts[n_pure..];
            let entry = if rest.is_empty() {
                body
            } else {
                let g: Expr = syn::parse_quote!(#(#rest)&&*);
                self.cond(&g, body, next)?
            };
            next = if wild {
                entry
            } else {
                let mut miss = next;
                for p in pats.iter().rev() {
                    miss = self.asm.jump(JEQ_K, quote!({ (#p) as u32 }), entry, miss)?;
                }
                self.asm.load(OFF_NR)?
            };
        }
        Ok(next)
    }

    fn field(&self, e: &Expr) -> R<Option<Field>> {
        let mut e = e;
        while let Expr::Paren(p) = e {
            e = &p.expr;
        }
        let (e, cast) = match e {
            Expr::Cast(c) => (&*c.expr, Some(&c.ty)),
            e => (e, None),
        };
        let on_d = |b: &Expr| matches!(b, Expr::Path(p) if p.path.is_ident(&self.d));
        let f = match e {
            Expr::Field(f) if on_d(&f.base) => {
                let name = match &f.member {
                    syn::Member::Named(n) => n.to_string(),
                    _ => return err(f, "a field of `d` by number"),
                };
                match name.as_str() {
                    "nr" => Field::Nr { signed: true },
                    "arch" => Field::Arch,
                    "instruction_pointer" => Field::Ip,
                    _ => return err(f, &format!("the field `d.{name}` alone")),
                }
            }
            Expr::Index(i) => {
                let Expr::Field(f) = &*i.expr else { return err(i, "an index of anything but `d.args`") };
                if !on_d(&f.base) || !matches!(&f.member, syn::Member::Named(n) if n == "args") {
                    return err(i, "an index of anything but `d.args`");
                }
                match &*i.index {
                    Expr::Lit(syn::ExprLit { lit: Lit::Int(n), .. }) if n.base10_parse::<u32>().is_ok_and(|n| n < 6) => Field::Arg(n.base10_parse()?),
                    x => return err(x, "an index into `d.args` other than a literal below 6"),
                }
            }
            _ => return Ok(None),
        };
        match (f, cast) {
            (f, None) => Ok(Some(f)),
            (Field::Nr { .. }, Some(t)) if quote!(#t).to_string() == "u32" => Ok(Some(Field::Nr { signed: false })),
            (Field::Nr { .. }, Some(t)) if ["i64", "i128"].contains(&quote!(#t).to_string().as_str()) => Ok(Some(Field::Nr { signed: true })),
            (_, Some(t)) => err(t, "a cast of a field of `d` (but `d.nr as u32` and `as i64`)"),
        }
    }

    /// A condition: code going to `t` if it holds, else `f`.
    fn cond(&mut self, c: &Expr, t: Label, f: Label) -> R<Label> {
        if self.pure(c) {
            return Ok(if self.switch(c) { t } else { f });
        }
        match c {
            Expr::Paren(p) => self.cond(&p.expr, t, f),
            Expr::Group(g) => self.cond(&g.expr, t, f),
            Expr::Unary(u) if matches!(u.op, UnOp::Not(_)) => self.cond(&u.expr, f, t),
            Expr::Binary(b) if matches!(b.op, BinOp::And(_)) => {
                let m = self.cond(&b.right, t, f)?;
                self.cond(&b.left, m, f)
            }
            Expr::Binary(b) if matches!(b.op, BinOp::Or(_)) => {
                let m = self.cond(&b.right, t, f)?;
                self.cond(&b.left, t, m)
            }
            Expr::Binary(b) => {
                // (op, the op with the sides swapped): Eq Ne Lt Le Gt Ge
                let (op, flipped) = match b.op {
                    BinOp::Eq(_) => (0, 0),
                    BinOp::Ne(_) => (1, 1),
                    BinOp::Lt(_) => (2, 4),
                    BinOp::Le(_) => (3, 5),
                    BinOp::Gt(_) => (4, 2),
                    BinOp::Ge(_) => (5, 3),
                    _ => return err(b, "an operator other than a comparison on `d`"),
                };
                let (field, v, op) = match (self.field(&b.left)?, self.field(&b.right)?) {
                    (Some(fl), None) if self.pure(&b.right) => (fl, &*b.right, op),
                    (None, Some(fl)) if self.pure(&b.left) => (fl, &*b.left, flipped),
                    _ => return err(b, "a comparison other than a field of `d` with a value without `d`"),
                };
                if matches!(field, Field::Nr { signed: true }) && op > 1 {
                    return err(b, "an ordering of `d.nr`, which is signed (write `d.nr as u32`)");
                }
                // Ne, Lt, Le: Eq, Ge, Gt with the targets swapped
                let (code, t, f) = match op {
                    0 => (JEQ_K, t, f),
                    1 => (JEQ_K, f, t),
                    2 => (JGE_K, f, t),
                    3 => (JGT_K, f, t),
                    4 => (JGT_K, t, f),
                    _ => (JGE_K, t, f),
                };
                let (lo_off, hi_off) = field.offsets();
                let lit = matches!(v, Expr::Lit(_));
                if !field.wide() {
                    let k = match (field, lit) {
                        (Field::Nr { signed: true }, _) => quote!({ let __v: i32 = #v; __v as u32 }),
                        (_, true) => quote!({ let __v: u32 = #v; __v }),
                        _ => quote!(u32::from(#v)),
                    };
                    self.asm.jump(code, k, t, f)?;
                    return self.asm.load(lo_off);
                }
                let v64 = if lit { quote!({ let __v: u64 = #v; __v }) } else { quote!(u64::from(#v)) };
                let (lo, hi) = (quote!({ (#v64) as u32 }), quote!({ ((#v64) >> 32) as u32 }));
                self.asm.jump(code, lo, t, f)?;
                let low = self.asm.load(lo_off)?;
                if code == JEQ_K {
                    self.asm.jump(JEQ_K, hi, low, f)?;
                } else {
                    // high above: holds; below: doesn't; equal: the low halves decide
                    let eq = self.asm.jump(JEQ_K, hi.clone(), low, f)?;
                    self.asm.jump(JGT_K, hi, t, eq)?;
                }
                self.asm.load(hi_off)
            }
            Expr::MethodCall(m) => err(m, &format!("the call `.{}()`", m.method)),
            Expr::Call(m) => err(m, "a call"),
            c => err(c, &format!("the condition `{}`", quote!(#c))),
        }
    }
}

/// `e`'s conjuncts, left to right.
fn conjuncts<'e>(e: &'e Expr, out: &mut Vec<&'e Expr>) {
    match e {
        Expr::Binary(b) if matches!(b.op, BinOp::And(_)) => {
            conjuncts(&b.left, out);
            conjuncts(&b.right, out);
        }
        e => out.push(e),
    }
}
