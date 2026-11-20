//! That `run_bpf` refuses what the kernel refuses (a proof that runs a program also proves the
//! kernel takes it).

use libc::{seccomp_data, sock_filter as SockFilter};
use seccomp_fn_verify::run_bpf;

fn none() -> seccomp_data {
    seccomp_data { nr: 0, arch: 0, instruction_pointer: 0, args: [0; 6] }
}

#[test]
#[should_panic(expected = "isn't a return")]
fn run_bpf_refuses_no_return() {
    run_bpf(&[SockFilter { code: 0x20, jt: 0, jf: 0, k: 0 }], &none());
}

#[test]
#[should_panic(expected = "refuses")]
fn run_bpf_refuses_a_jump_out() {
    let p = [SockFilter { code: 0x15, jt: 1, jf: 0, k: 0 }, SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 }];
    run_bpf(&p, &none());
}

#[test]
#[should_panic(expected = "refuses")]
fn run_bpf_refuses_a_load_past_seccomp_data() {
    let p = [SockFilter { code: 0x20, jt: 0, jf: 0, k: 64 }, SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 }];
    run_bpf(&p, &none());
}
