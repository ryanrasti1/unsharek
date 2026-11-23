//! `cargo xtask calls`: the typed view of the host's syscalls that seccomp-fn-verify's compiler
//! reads (the submodule's seccomp-fn-verify/src/calls.rs),
//! generated from mainline Linux's own sources (`UNSHAREK_LINUX_SYSCALLS`: v7.0's x86-64 table
//! and its `SYSCALL_DEFINE`s, nix/linux-syscalls.nix), for the syscalls in [`WANTED`]. Each
//! argument's width and sign is its C type's, as the kernel reads it: an `int` fd is an `i32`,
//! high bits ignored. Not trusted to be right by itself: the tests check the file is what the
//! sources give (no hand edit) and each row against the running kernel's own record of its types
//! (tracefs).

use std::collections::HashMap;
use std::path::Path;

/// The syscalls the table has: unsharek-tcb's rows' (the table is trusted: only the rows used).
pub const WANTED: &[&str] = &[
    "read", "write", "close", "fstat", "rt_sigreturn", "pread64", "pwrite64", "socket", "connect", "shutdown", "bind", "listen",
    "getsockname", "getpeername", "setsockopt", "getsockopt", "clone", "exit", "fsync", "ftruncate", "getdents64", "exit_group",
    "openat", "mkdirat", "unlinkat", "symlinkat", "readlinkat", "fchmodat", "ppoll", "utimensat", "accept4", "renameat2",
];

/// A C type, as `rust_ty` reads it (qualifiers dropped), and its Rust type.
const TYPES: &[(&str, &str)] = &[
    ("int", "i32"),
    ("unsigned int", "u32"),
    ("unsigned", "u32"),
    ("long", "i64"),
    ("unsigned long", "u64"),
    ("size_t", "usize"),
    ("ssize_t", "isize"),
    ("loff_t", "i64"),
    ("off_t", "i64"),
    ("umode_t", "u16"),
    ("pid_t", "i32"),
    ("uid_t", "u32"),
    ("gid_t", "u32"),
    ("old_uid_t", "u16"),
    ("old_gid_t", "u16"),
    ("key_serial_t", "i32"),
    ("clockid_t", "i32"),
    ("timer_t", "i32"),
    ("mqd_t", "i32"),
    ("qid_t", "u32"),
    ("u32", "u32"),
    ("__u32", "u32"),
    ("u64", "u64"),
    ("__u64", "u64"),
    ("aio_context_t", "u64"),
    ("rwf_t", "i32"),
    ("key_t", "i32"),
    ("unsigned short", "u16"),
    ("short", "i16"),
    ("u16", "u16"),
    ("__s32", "i32"),
    ("s32", "i32"),
    ("int32_t", "i32"),
    ("unsigned char", "u8"),
    ("char", "i8"),
    ("old_sigset_t", "u64"),
    ("cap_user_header_t", "Ptr"),
    ("cap_user_data_t", "Ptr"),
    ("__kernel_old_time_t", "i64"),
    ("time_t", "i64"),
];

/// Entry points that aren't a `SYSCALL_DEFINE` the scan finds (x86 code's own), x86-64's
/// arguments by hand. Those the tcb uses (`rt_sigreturn`, `clone`) are checked against the
/// running kernel by the tests, as every row is.
const OVERRIDES: &[(&str, &[(&str, &str)])] = &[
    ("rt_sigreturn", &[]),
    // x86-64's order (CLONE_BACKWARDS2 is s390's): flags, stack, parent tid, child tid, tls.
    ("clone", &[("clone_flags", "u64"), ("newsp", "u64"), ("parent_tidptr", "Ptr"), ("child_tidptr", "Ptr"), ("tls", "u64")]),
    ("mmap", &[("addr", "u64"), ("len", "u64"), ("prot", "u64"), ("flags", "u64"), ("fd", "u64"), ("off", "u64")]),
    ("modify_ldt", &[("func", "i32"), ("ptr", "Ptr"), ("bytecount", "u64")]),
    ("arch_prctl", &[("option", "i32"), ("arg2", "u64")]),
    ("iopl", &[("level", "u32")]),
    ("ioperm", &[("from", "u64"), ("num", "u64"), ("turn_on", "i32")]),
];

/// `ctype` (a C parameter's type) as Rust: a pointer is [`Ptr`]-typed, a C `enum` 32 bits
/// unsigned (GCC's, with no negative enumerator), anything else by [`TYPES`].
pub fn rust_ty(ctype: &str) -> Option<&'static str> {
    if ctype.contains('*') {
        return Some("Ptr");
    }
    if ctype.split_whitespace().any(|w| w == "enum") {
        return Some("u32");
    }
    let norm = norm(ctype);
    TYPES.iter().find(|t| t.0 == norm).map(|t| t.1)
}

fn norm(ctype: &str) -> String {
    ctype
        .split_whitespace()
        .filter(|w| !matches!(*w, "const" | "volatile" | "__user" | "struct" | "union" | "enum" | "__force"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A syscall's row: number, name, arguments (name, Rust type).
pub struct Row {
    pub nr: u32,
    pub name: String,
    pub args: Vec<(String, &'static str)>,
    pub over: bool,
}

/// The rows for `want`, from the sources under `linux`.
pub fn rows(linux: &Path, want: &[&str]) -> Result<Vec<Row>, String> {
    let tbl = std::fs::read_to_string(linux.join("arch/x86/entry/syscalls/syscall_64.tbl")).map_err(|e| format!("syscall_64.tbl: {e}"))?;
    let defs = defines(linux)?;
    let mut out = vec![];
    for line in tbl.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[0].starts_with('#') || !matches!(f[1], "common" | "64") || !want.contains(&f[2]) {
            continue;
        }
        let (nr, name, entry) = (f[0].parse::<u32>().map_err(|e| format!("{line}: {e}"))?, f[2], f[3]);
        let key = entry.trim_start_matches("__x64_").trim_start_matches("sys_");
        let (args, over) = if let Some(o) = OVERRIDES.iter().find(|o| o.0 == name) {
            (o.1.iter().map(|&(a, t)| (a.to_owned(), t)).collect(), true)
        } else if let Some(cargs) = defs.get(key) {
            let mut args = vec![];
            for (a, ct) in cargs {
                args.push((a.clone(), rust_ty(ct).ok_or_else(|| format!("{name}: {a}'s C type {ct:?} isn't in the table (xtask/src/calls.rs)"))?));
            }
            (args, false)
        } else {
            return Err(format!("{name} (entry {entry}): no SYSCALL_DEFINE, and no override"));
        };
        out.push(Row { nr, name: name.to_owned(), args, over });
    }
    if let Some(w) = want.iter().find(|w| !out.iter().any(|r| r.name == **w)) {
        return Err(format!("{w}: not in syscall_64.tbl"));
    }
    Ok(out)
}

/// Every `SYSCALL_DEFINEn(name, type, arg, ...)` under `linux`: name to (arg, C type); x86's own
/// win over another arch's of the same name.
fn defines(linux: &Path) -> Result<HashMap<String, Vec<(String, String)>>, String> {
    let mut defs: HashMap<String, (Vec<(String, String)>, bool)> = HashMap::new();
    let mut stack = vec![linux.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().is_none_or(|x| x != "c") {
                continue;
            }
            let Ok(src) = std::fs::read(&p) else { continue };
            let src = String::from_utf8_lossy(&src);
            let x86 = p.to_string_lossy().contains("arch/x86");
            for (name, args) in scan(&src) {
                if defs.get(&name).is_some_and(|d| d.1 && !x86) {
                    continue;
                }
                defs.insert(name, (args, x86));
            }
        }
    }
    Ok(defs.into_iter().map(|(k, v)| (k, v.0)).collect())
}

/// The `SYSCALL_DEFINEn(...)`s of one file: the parenthesised text read to its balancing `)`,
/// split at its top-level commas: name, then (type, arg) pairs.
fn scan(src: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = vec![];
    let mut rest = src;
    while let Some(i) = rest.find("SYSCALL_DEFINE") {
        // A word of its own: not `COMPAT_SYSCALL_DEFINE`'s (a 32-bit ABI's).
        let own = rest[..i].chars().next_back().is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        rest = &rest[i + "SYSCALL_DEFINE".len()..];
        if !own {
            continue;
        }
        let b = rest.as_bytes();
        if b.len() < 2 || !b[0].is_ascii_digit() || b[1] != b'(' {
            continue;
        }
        let n = (b[0] - b'0') as usize;
        let (mut depth, mut parts, mut cur) = (0i32, vec![], String::new());
        let mut end = None;
        for (j, c) in rest[2..].char_indices() {
            match c {
                '(' => {
                    depth += 1;
                    cur.push(c);
                }
                ')' if depth == 0 => {
                    end = Some(j);
                    break;
                }
                ')' => {
                    depth -= 1;
                    cur.push(c);
                }
                ',' if depth == 0 => parts.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
        if end.is_none() {
            break;
        }
        parts.push(cur);
        let parts: Vec<String> = parts.iter().map(|p| p.split_whitespace().collect::<Vec<_>>().join(" ")).collect();
        if parts.len() != 1 + 2 * n || parts[0].is_empty() || !parts[0].chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let args = (0..n).map(|k| (parts[2 + 2 * k].clone(), parts[1 + 2 * k].clone())).collect();
        out.push((parts[0].clone(), args));
    }
    out
}

/// A Rust field name for C argument `a` (a keyword raw).
fn field(a: &str) -> String {
    if matches!(a, "type" | "fn" | "mod" | "ref" | "move" | "match" | "use" | "loop" | "in" | "impl" | "where") { format!("r#{a}") } else { a.to_owned() }
}

/// The file's text for `rows`: seccomp-fn-verify's `src/calls.rs` (the enum, its decode, and
/// the table its compiler reads).
pub fn render(rows: &[Row]) -> String {
    let camel = |n: &str| -> String { n.split('_').map(|w| w[..1].to_uppercase() + &w[1..]).collect() };
    let ty = |t: &str| match t {
        "u16" => "U16",
        "u32" => "U32",
        "i32" => "I32",
        "u64" => "U64",
        "i64" => "I64",
        "usize" => "Usize",
        "Ptr" => "Ptr",
        t => panic!("{t}: no Ty of seccomp-fn-verify's"),
    };
    let conv = |t: &str, i: usize| match t {
        "u64" => format!("a[{i}]"),
        "Ptr" => format!("Ptr(a[{i}])"),
        t => format!("a[{i}] as {t}"),
    };
    let mut s = String::from(PRE);
    s.push('\n');
    for r in rows {
        let v = camel(&r.name);
        s.push_str(&format!("    /// {}\n", r.nr));
        if r.args.is_empty() {
            s.push_str(&format!("    {v},\n"));
        } else {
            let f: Vec<String> = r.args.iter().map(|(a, t)| format!("{}: {t}", field(a))).collect();
            s.push_str(&format!("    {v} {{ {} }},\n", f.join(", ")));
        }
    }
    s.push_str("    Other { nr: i32 },\n}\n\n");
    s.push_str("/// Each row: the variant, its number, its arguments (name, type) in order.\n");
    s.push_str("pub const CALLS: &[(&str, i64, &[(&str, Ty)])] = &[\n");
    for r in rows {
        let a: Vec<String> = r.args.iter().map(|(a, t)| format!("(\"{a}\", Ty::{})", ty(t))).collect();
        s.push_str(&format!("    (\"{}\", {}, &[{}]),\n", camel(&r.name), r.nr, a.join(", ")));
    }
    s.push_str("];\n\n");
    s.push_str(DECODE);
    for r in rows {
        let v = camel(&r.name);
        if r.args.is_empty() {
            s.push_str(&format!("            {} => Call::{v},\n", r.nr));
        } else {
            let f: Vec<String> = r.args.iter().enumerate().map(|(i, (a, t))| format!("{}: {}", field(a), conv(t, i))).collect();
            s.push_str(&format!("            {} => Call::{v} {{ {} }},\n", r.nr, f.join(", ")));
        }
    }
    s.push_str(POST);
    s
}

const PRE: &str = "//! The typed view of a call: [`Call`], each argument as the kernel reads it (its C type's
//! width and sign), from Linux v7.0's x86-64 syscall table and `SYSCALL_DEFINE`s. Generated (from
//! unsharek's `cargo xtask calls`): do not edit. Trusted: the compiler takes each bound field's
//! argument number and type from [`CALLS`] (`expr::Field::typed`), never from the macro.

use libc::seccomp_data;

/// An argument's C type: its width and sign as the kernel reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    U16,
    U32,
    I32,
    U64,
    I64,
    Usize,
    Ptr,
}

/// An argument the kernel reads as a pointer. A filter can't follow it (the program chooses it,
/// and may change the memory after the check), so the only meaningful test is null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ptr(pub u64);

impl Ptr {
    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    /// The raw number: comparing it is visibly deliberate.
    pub fn addr(self) -> u64 {
        self.0
    }
}

/// A call of the table's, its arguments typed; any other number is [`Call::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {";

const DECODE: &str = "/// `d.call()`: the call, typed (each argument truncated to its type, as the kernel reads it).
pub trait CallExt {
    fn call(&self) -> Call;
}

impl CallExt for seccomp_data {
    fn call(&self) -> Call {
        let a = &self.args;
        match self.nr as i64 {
";

const POST: &str = "            _ => Call::Other { nr: self.nr },
        }
    }
}

/// The number of `call` (a variant's name).
pub fn nr(call: &str) -> Option<i64> {
    CALLS.iter().find(|r| r.0 == call).map(|r| r.1)
}

/// Argument `name` of `call`: its index and type (a raw identifier's `r#` dropped).
pub fn field(call: &str, name: &str) -> Option<(u8, Ty)> {
    let name = name.strip_prefix(\"r#\").unwrap_or(name);
    let row = CALLS.iter().find(|r| r.0 == call)?;
    row.2.iter().position(|f| f.0 == name).map(|i| (i as u8, row.2[i].1))
}
";

/// Where the file goes.
pub const OUT: &str = "seccomp-fn-verify/src/calls.rs";

/// The task: the file written from `UNSHAREK_LINUX_SYSCALLS`.
pub fn run(root: &Path) -> Result<(), String> {
    let linux = std::env::var_os("UNSHAREK_LINUX_SYSCALLS").ok_or("UNSHAREK_LINUX_SYSCALLS isn't set: the devshell sets it (nix/linux-syscalls.nix)")?;
    let rows = rows(Path::new(&linux), WANTED)?;
    std::fs::write(root.join(OUT), render(&rows)).map_err(|e| format!("{OUT}: {e}"))?;
    let by_hand: Vec<&str> = rows.iter().filter(|r| r.over).map(|r| r.name.as_str()).collect();
    eprintln!("xtask calls: {} rows into {OUT} (by hand, x86's own entry points: {})", rows.len(), by_hand.join(", "));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    /// The checked-in file is what the sources give: no hand edit, no drift. Without the sources
    /// (outside the devshell), skipped with a message.
    #[test]
    fn calls_rs_is_generated() {
        let Some(linux) = std::env::var_os("UNSHAREK_LINUX_SYSCALLS") else {
            eprintln!("skipped: UNSHAREK_LINUX_SYSCALLS isn't set");
            return;
        };
        let want = render(&rows(Path::new(&linux), WANTED).unwrap());
        let have = std::fs::read_to_string(root().join(OUT)).unwrap();
        assert!(want == have, "{OUT} isn't what `cargo xtask calls` makes: run it");
    }

    /// The parser, on a multi-line definition; a 32-bit ABI's `COMPAT_SYSCALL_DEFINE` isn't one.
    #[test]
    fn scan_reads_a_define() {
        let src = "COMPAT_SYSCALL_DEFINE1(openat, compat_int_t, x)\nSYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename,\n\t\tint, flags, umode_t, mode)\n{";
        let d = scan(src);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].0, "openat");
        assert_eq!(d[0].1, vec![("dfd".into(), "int".into()), ("filename".into(), "const char __user *".into()), ("flags".into(), "int".into()), ("mode".into(), "umode_t".into())]);
    }

    /// Each row against the running kernel's own record (tracefs's `sys_enter_<name>/format`:
    /// each argument's C type): the same Rust type by the same mapping. Skipped with a message
    /// where tracefs can't be read (it is root's).
    #[test]
    fn rows_match_the_running_kernel() {
        let src = std::fs::read_to_string(root().join(OUT)).unwrap();
        let start = src.find("pub const CALLS").unwrap();
        let end = start + src[start..].find("];").unwrap();
        let mut checked = 0;
        for line in src[start..end].lines().filter(|l| l.trim_start().starts_with("(\"")) {
            // `("ExitGroup", 231, &[("error_code", Ty::I32)]),`: the kernel's name is snake case
            let camel = line.split('"').nth(1).unwrap();
            let mut name = String::new();
            for (i, c) in camel.char_indices() {
                if c.is_ascii_uppercase() && i > 0 {
                    name.push('_');
                }
                name.push(c.to_ascii_lowercase());
            }
            let ours: Vec<String> = line.split("Ty::").skip(1).map(|t| t.split(')').next().unwrap().to_lowercase()).collect();
            let ours: Vec<&str> = ours.iter().map(|t| if t == "ptr" { "Ptr" } else { t.as_str() }).collect();
            let Ok(fmt) = std::fs::read_to_string(format!("/sys/kernel/tracing/events/syscalls/sys_enter_{name}/format")) else {
                continue;
            };
            // `field:int dfd;	offset:16;	size:8;	signed:0;` after the common ones and `__syscall_nr`.
            let theirs: Vec<&'static str> = fmt
                .lines()
                .filter_map(|l| l.trim().strip_prefix("field:"))
                .map(|f| f.split(';').next().unwrap())
                .filter(|f| !f.contains("common_") && !f.contains("__syscall_nr"))
                .map(|f| {
                    let ty = f.rsplit_once(' ').map_or(f, |(t, _)| t);
                    rust_ty(ty).unwrap_or_else(|| panic!("{name}: tracefs's {ty:?} isn't in the table"))
                })
                .collect();
            assert_eq!(ours, theirs, "{name}: the table's types against the running kernel's");
            checked += 1;
        }
        if checked == 0 {
            eprintln!("skipped: /sys/kernel/tracing/events/syscalls isn't readable here");
        }
    }
}
