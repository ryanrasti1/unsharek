//! `#[seccomp]`: a function `fn name(d: &SeccompData, <params>) -> u32` kept as written, and
//! beside it
//! - `name_bpf(<params>) -> Vec<SockFilter>`: the same function as a classic-BPF program, built
//!   at run time from the params' values by `seccomp_fn::Builder`;
//! - `name_constants(<params>)`: every comparison's field and value, for the sampled check;
//! - under `cfg(kani)`, `name_is_its_bpf`: Kani's proof that the two agree, for every
//!   `SeccompData` and every value of every param.
//!
//! The subset (anything else is a compile error naming it): `if`/`else`, `return`, `match d.nr`
//! (literal or const patterns, `|`, `_`), `let` of an expression without `d`; conditions are
//! `&&`, `||`, `!`, parentheses, comparisons of a field of `d` with an expression without `d`,
//! and expressions without `d` (decided when the program is built). Values returned are
//! expressions without `d`.
//!
//! Code is generated backwards (see `Builder`): each construct's code is an expression for its
//! first instruction's label, given the labels it continues to.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as Ts, TokenTree};
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{BinOp, Block, Expr, FnArg, Ident, ItemFn, Lit, Pat, Stmt, UnOp};

type R<T> = syn::Result<T>;

fn err<T>(s: impl Spanned, what: &str) -> R<T> {
    Err(syn::Error::new(s.span(), format!("#[seccomp]: {what} is outside the subset")))
}

/// `e`'s conjuncts, left to right: `a && b && c` gives `a`, `b`, `c`.
fn conjuncts<'e>(e: &'e Expr, out: &mut Vec<&'e Expr>) {
    match e {
        Expr::Binary(b) if matches!(b.op, BinOp::And(_)) => {
            conjuncts(&b.left, out);
            conjuncts(&b.right, out);
        }
        e => out.push(e),
    }
}

#[proc_macro_attribute]
pub fn seccomp(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let f = syn::parse_macro_input!(item as ItemFn);
    match expand(&f) {
        Ok(t) => t.into(),
        Err(e) => {
            let e = e.to_compile_error();
            quote!(#f #e).into()
        }
    }
}

/// Where a construct's code goes on to: it is the function's value (`Tail`), or falls through to
/// a label (a statement followed by more).
#[derive(Clone)]
enum Pos {
    Tail,
    Next(Ident),
}

struct Cx {
    d: Ident,
    n: usize,
    /// An upper bound on the program's length, for Kani's unwinding.
    insns: usize,
    jumps: usize,
}

impl Cx {
    fn fresh(&mut self, s: &str) -> Ident {
        self.n += 1;
        format_ident!("__{}{}", s, self.n)
    }

    /// Whether `t` names `d`.
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

    fn block(&mut self, b: &Block, pos: &Pos) -> R<Ts> {
        self.stmts(&b.stmts, pos)
    }

    fn stmts(&mut self, stmts: &[Stmt], pos: &Pos) -> R<Ts> {
        let Some((s, rest)) = stmts.split_first() else {
            return match pos {
                Pos::Next(n) => Ok(quote!(#n)),
                Pos::Tail => Err(syn::Error::new(Span::call_site(), "#[seccomp]: a block without a value")),
            };
        };
        match s {
            Stmt::Local(l) => {
                let Some(init) = &l.init else { return err(l, "`let` without a value") };
                if init.diverge.is_some() || !self.pure(&init.expr) {
                    return err(l, "`let` of an expression of `d`");
                }
                let rest = self.stmts(rest, pos)?;
                let (pat, e) = (&l.pat, &init.expr);
                Ok(quote!({ let #pat = #e; #rest }))
            }
            Stmt::Expr(e, _) if rest.is_empty() => self.expr(e, pos),
            Stmt::Expr(e, _) => {
                let n = self.fresh("next");
                let rest = self.stmts(rest, pos)?;
                let e = self.expr(e, &Pos::Next(n.clone()))?;
                Ok(quote!({ let #n = #rest; #e }))
            }
            Stmt::Item(i) => err(i, "an item"),
            Stmt::Macro(m) => err(m, "a macro"),
        }
    }

    /// A value returned: an expression without `d`.
    fn ret(&mut self, v: &Expr) -> R<Ts> {
        if !self.pure(v) {
            return err(v, "a verdict computed from `d`");
        }
        self.insns += 1;
        Ok(quote!(__b.ret(#v)))
    }

    fn expr(&mut self, e: &Expr, pos: &Pos) -> R<Ts> {
        match e {
            Expr::Paren(p) => self.expr(&p.expr, pos),
            Expr::Group(g) => self.expr(&g.expr, pos),
            Expr::Return(r) => match &r.expr {
                Some(v) => self.ret(v),
                None => err(r, "`return` without a value"),
            },
            Expr::Block(b) if b.label.is_none() => self.block(&b.block, pos),
            Expr::If(i) => {
                let then = self.block(&i.then_branch, pos)?;
                let els = match (&i.else_branch, pos) {
                    (Some((_, e)), _) => self.expr(e, pos)?,
                    (None, Pos::Next(n)) => quote!(#n),
                    (None, Pos::Tail) => return err(i, "`if` without `else` as the value"),
                };
                let c = &i.cond;
                if self.pure(c) {
                    // decided at build time: only the branch taken is emitted
                    return Ok(quote!(if #c { #then } else { #els }));
                }
                let (t, f) = (self.fresh("then"), self.fresh("else"));
                let cond = self.cond(c, &t, &f)?;
                Ok(quote!({ let #f = #els; let #t = #then; #cond }))
            }
            Expr::Match(m) => self.matches(m, pos),
            _ if matches!(pos, Pos::Tail) => self.ret(e),
            _ => err(e, &format!("the statement `{}`", quote!(#e))),
        }
    }

    /// `match d.nr`, as Rust runs it: arms in order, the first whose pattern matches and whose
    /// guard holds wins; a guard that fails goes on to the next arm. Each arm is its own test
    /// (a load of `nr`, a JEQ per pattern), so a guard may load what it likes. A guard's leading
    /// conjuncts without `d` (`threads && ...`) are decided at build time: an arm they rule out
    /// is not emitted.
    fn matches(&mut self, m: &syn::ExprMatch, pos: &Pos) -> R<Ts> {
        match self.field(&m.expr)? {
            Some(f) if f.to_string() == quote!(::seccomp_fn::Field::Nr).to_string() => {}
            _ => return err(&m.expr, "`match` on anything but `d.nr`"),
        }
        // The arms up to the first `_` without a guard (the rest are unreachable).
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
                    // A bare name is a const here (a binding would name no value: the
                    // generated code wouldn't compile).
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
        let next = self.fresh("next");
        let mut code = match (default, pos) {
            (Some(arm), _) => self.expr(&arm.body, pos)?,
            (None, Pos::Next(l)) => quote!(#l),
            (None, Pos::Tail) => return err(m, "a `match` without `_` as the value"),
        };
        // Backwards: each arm's code is given the next arm's label.
        for (pats, wild, guard, arm) in arms.into_iter().rev() {
            let body = self.expr(&arm.body, pos)?;
            let (entry, then) = (self.fresh("body"), self.fresh("entry"));
            // the guard's leading conjuncts without `d` (`a && b && c` is `(a && b) && c`: its
            // conjuncts flattened), and the rest, rejoined
            let mut parts = vec![];
            if let Some(g) = guard {
                conjuncts(g, &mut parts);
            }
            let n_pure = parts.iter().take_while(|c| self.pure(c)).count();
            let pure: Vec<&Expr> = parts[..n_pure].to_vec();
            let rest = &parts[n_pure..];
            let guarded = if rest.is_empty() {
                quote!(#entry)
            } else {
                let g: Expr = syn::parse_quote!(#(#rest)&&*);
                self.cond(&g, &entry, &next)?
            };
            let test = if wild {
                quote!(#then)
            } else {
                let nrs: Vec<&&Pat> = pats.iter().collect();
                self.insns += 1 + nrs.len();
                self.jumps += nrs.len();
                quote!(__b.nr_in(&[#(#nrs),*], #then, #next))
            };
            let arm_code = quote!({ let #entry = #body; let #then = #guarded; #test });
            code = if pure.is_empty() {
                quote!({ let #next = #code; #arm_code })
            } else {
                quote!({ let #next = #code; if #(#pure)&&* { #arm_code } else { #next } })
            };
        }
        Ok(code)
    }

    /// `d.nr`, `d.arch`, `d.instruction_pointer`, `d.args[i]` (a literal `i`): its `Field`.
    fn field(&self, e: &Expr) -> R<Option<Ts>> {
        let e = match e {
            Expr::Paren(p) => &*p.expr,
            e => e,
        };
        let on_d = |b: &Expr| matches!(b, Expr::Path(p) if p.path.is_ident(&self.d));
        match e {
            Expr::Field(f) if on_d(&f.base) => {
                let name = match &f.member {
                    syn::Member::Named(n) => n.to_string(),
                    _ => return err(f, "a field of `d` by number"),
                };
                Ok(Some(match name.as_str() {
                    "nr" => quote!(::seccomp_fn::Field::Nr),
                    "arch" => quote!(::seccomp_fn::Field::Arch),
                    "instruction_pointer" => quote!(::seccomp_fn::Field::InstructionPointer),
                    _ => return err(f, &format!("the field `d.{name}` alone")),
                }))
            }
            Expr::Index(i) => {
                let Expr::Field(f) = &*i.expr else { return err(i, "an index of anything but `d.args`") };
                if !on_d(&f.base) || !matches!(&f.member, syn::Member::Named(n) if n == "args") {
                    return err(i, "an index of anything but `d.args`");
                }
                match &*i.index {
                    Expr::Lit(syn::ExprLit { lit: Lit::Int(n), .. }) if n.base10_parse::<usize>().is_ok_and(|n| n < 6) => {
                        let n: usize = n.base10_parse()?;
                        Ok(Some(quote!(::seccomp_fn::Field::Arg(#n))))
                    }
                    x => err(x, "an index into `d.args` other than a literal below 6"),
                }
            }
            _ => Ok(None),
        }
    }

    /// A condition: code jumping to `t` if it holds, else `f`.
    fn cond(&mut self, c: &Expr, t: &Ident, f: &Ident) -> R<Ts> {
        if self.pure(c) {
            return Ok(quote!(if #c { #t } else { #f }));
        }
        match c {
            Expr::Paren(p) => self.cond(&p.expr, t, f),
            Expr::Group(g) => self.cond(&g.expr, t, f),
            Expr::Unary(u) if matches!(u.op, UnOp::Not(_)) => self.cond(&u.expr, f, t),
            Expr::Binary(b) if matches!(b.op, BinOp::And(_) | BinOp::Or(_)) => {
                let m = self.fresh("m");
                let rhs = self.cond(&b.right, t, f)?;
                let lhs = if matches!(b.op, BinOp::And(_)) { self.cond(&b.left, &m, f)? } else { self.cond(&b.left, t, &m)? };
                Ok(quote!({ let #m = #rhs; #lhs }))
            }
            Expr::Binary(b) => {
                let ops = ["Eq", "Ne", "Lt", "Le", "Gt", "Ge"];
                let (op, flipped) = match b.op {
                    BinOp::Eq(_) => (0, 0),
                    BinOp::Ne(_) => (1, 1),
                    BinOp::Lt(_) => (2, 4),
                    BinOp::Le(_) => (3, 5),
                    BinOp::Gt(_) => (4, 2),
                    BinOp::Ge(_) => (5, 3),
                    _ => return err(b, &format!("the operator `{}` on `d`", quote!(#b.op))),
                };
                let (field, v, op) = match (self.field(&b.left)?, self.field(&b.right)?) {
                    (Some(fl), None) if self.pure(&b.right) => (fl, &b.right, ops[op]),
                    (None, Some(fl)) if self.pure(&b.left) => (fl, &b.left, ops[flipped]),
                    _ => return err(b, "a comparison other than a field of `d` with a value without `d`"),
                };
                let wide = !field.to_string().contains("Nr") && !field.to_string().contains("Arch");
                self.insns += if wide { 5 } else { 2 };
                self.jumps += if wide { 3 } else { 1 };
                let op = Ident::new(op, Span::call_site());
                // typed as the field is, as in the function: a literal is a u32 or a u64
                // BPF compares unsigned: a literal is typed as the field is; anything else must be
                // an unsigned integer (`seccomp_fn::Unsigned`), widened.
                let v = match (&**v, wide) {
                    (Expr::Lit(_), true) => quote!({ let v: u64 = #v; v }),
                    (Expr::Lit(_), false) => quote!({ let v: u32 = #v; v as u64 }),
                    _ => quote!(::seccomp_fn::Unsigned::widen(#v)),
                };
                Ok(quote!(__b.cmp(#field, ::seccomp_fn::Cmp::#op, #v, #t, #f)))
            }
            Expr::MethodCall(m) => err(m, &format!("the call `.{}()`", m.method)),
            Expr::Call(m) => err(m, "a call"),
            Expr::ForLoop(l) => err(l, "a loop"),
            Expr::While(l) => err(l, "a loop"),
            Expr::Loop(l) => err(l, "a loop"),
            c => err(c, &format!("the condition `{}`", quote!(#c))),
        }
    }
}

fn expand(f: &ItemFn) -> R<Ts> {
    let sig = &f.sig;
    let mut inputs = sig.inputs.iter();
    let d = match inputs.next() {
        Some(FnArg::Typed(t)) => match &*t.pat {
            Pat::Ident(i) => i.ident.clone(),
            p => return err(p, "a first parameter other than `d: &SeccompData`"),
        },
        _ => return err(sig, "a function without `d: &SeccompData` first"),
    };
    let (mut names, mut tys) = (vec![], vec![]);
    for a in inputs {
        let FnArg::Typed(t) = a else { return err(a, "a receiver") };
        let Pat::Ident(i) = &*t.pat else { return err(&t.pat, "a parameter pattern") };
        if let syn::Type::Path(p) = &*t.ty
            && let Some(id) = p.path.get_ident()
            && ["i8", "i16", "i32", "i64", "i128", "isize", "usize", "f32", "f64", "char"].iter().any(|s| id == s)
        {
            return Err(syn::Error::new(id.span(), "#[seccomp]: BPF compares unsigned: a param is u64, u32, u16, u8, bool or a fieldless enum"));
        }
        names.push(i.ident.clone());
        tys.push(t.ty.clone());
    }
    let mut cx = Cx { d, n: 0, insns: 0, jumps: 0 };
    let body = cx.block(&f.block, &Pos::Tail)?;
    // Each jump may need two JAs once the program is longer than a jump reaches.
    let bound = if cx.insns > 255 { cx.insns + 2 * cx.jumps } else { cx.insns };
    // (and the harness's loop over the shapes: at most MAX_SHAPES)
    let unwind = bound.max(8) + 2;
    let (vis, name) = (&f.vis, &sig.ident);
    let bpf = format_ident!("{}_bpf", name);
    let builder = format_ident!("{}_builder", name);
    let constants = format_ident!("{}_constants", name);
    let proof = format_ident!("{}_is_its_bpf", name);
    let params = quote!(#(#names: #tys),*);
    let sampled = format_ident!("{}_matches_its_bpf_sampled", name);
    // every combination of the params' samples, as a tuple
    let mut sample_loops = quote!(__configs.push((#(#names),*)););
    for (n, t) in names.iter().zip(&tys).rev() {
        sample_loops = quote!(for #n in <#t as ::seccomp_fn::Sample>::samples() { #sample_loops });
    }
    // The proof: one harness per combination of the params that shape the program (bools,
    // enums: their `Sample` values, which another harness checks are all of them), so that each
    // harness's program has one length; integers (which only change constants) and `d` are
    // symbolic. Up to MAX_SHAPES combinations, one harness each.
    const MAX_SHAPES: usize = 8;
    let is_int = |t: &syn::Type| matches!(t, syn::Type::Path(p) if p.path.get_ident().is_some_and(|i| ["u8", "u16", "u32", "u64"].iter().any(|s| i == s)));
    let (mut shape_names, mut shape_tys) = (vec![], vec![]);
    let mut ints = vec![];
    for (n, t) in names.iter().zip(&tys) {
        if is_int(t) {
            ints.push(quote!(let #n: #t = kani::any();));
        } else {
            shape_names.push(n.clone());
            shape_tys.push(t.clone());
        }
    }
    let mut shape_loops = quote!(__shapes.push((#(#shape_names),*)););
    for (n, t) in shape_names.iter().zip(&shape_tys).rev() {
        shape_loops = quote!(for #n in <#t as ::seccomp_fn::Sample>::samples() { #shape_loops });
    }
    let shapes = if shape_names.is_empty() { 1 } else { MAX_SHAPES };
    let proofs = (0..shapes).map(|i| {
        let h = if shape_names.is_empty() { proof.clone() } else { format_ident!("{}_{}", proof, i) };
        let most = (i == 0).then(|| quote!(assert!(__shapes.len() <= #MAX_SHAPES, "#[seccomp]: more than 8 combinations of bool and enum params");));
        quote! {
            /// The function and its program agree on every input, for every integer param, in
            /// one combination of the others.
            #[cfg(kani)]
            #[kani::proof]
            #[kani::unwind(#unwind)]
            fn #h() {
                let mut __shapes = vec![];
                #shape_loops
                #most
                if __shapes.len() <= #i {
                    return;
                }
                let (#(#shape_names),*) = __shapes[#i];
                #(#ints)*
                let __d: ::seccomp_fn::SeccompData = kani::any();
                let __prog = #bpf(#(#names),*);
                assert_eq!(::seccomp_fn::run_bpf(&__prog, &__d), #name(&__d, #(#names),*));
            }
        }
    });
    let complete = format_ident!("{}_samples_are_complete", name);
    let complete = (!shape_names.is_empty()).then(|| quote! {
        /// Each bool and enum param's `Sample` values are all of its values: the harnesses
        /// above cover every combination.
        #[cfg(kani)]
        #[kani::proof]
        fn #complete() {
            #(
                let __x: #shape_tys = kani::any();
                assert!(<#shape_tys as ::seccomp_fn::Sample>::samples().contains(&__x));
            )*
        }
    });
    Ok(quote! {
        #f

        #[allow(unused_variables, unused_braces, clippy::all)]
        fn #builder(#params) -> ::seccomp_fn::Builder {
            let mut __b = ::seccomp_fn::Builder::with_capacity(#bound);
            let _: ::seccomp_fn::Label = #body;
            __b
        }

        /// The function's program (`#[seccomp]`), for these params.
        #vis fn #bpf(#params) -> ::std::vec::Vec<::seccomp_fn::SockFilter> {
            #builder(#(#names),*).finish()
        }

        /// Every comparison the function's program makes for these params: its field and value.
        #vis fn #constants(#params) -> ::std::vec::Vec<(::seccomp_fn::Field, u64)> {
            #builder(#(#names),*).constants
        }

        /// The proof's assertion, sampled, in seconds: for each param's `Sample` values, the
        /// program against the function on calls around the constants it compares with.
        #[cfg(test)]
        #[test]
        fn #sampled() {
            let mut __configs = vec![];
            #sample_loops
            let __n = ::seccomp_fn::sampled_budget(__configs.len());
            for (#(#names),*) in __configs {
                let __prog = #bpf(#(#names),*);
                let __k = #constants(#(#names),*);
                ::seccomp_fn::check_sampled(&__prog, &__k, __n, |__d| #name(__d, #(#names),*));
            }
        }

        #(#proofs)*
        #complete
    })
}
