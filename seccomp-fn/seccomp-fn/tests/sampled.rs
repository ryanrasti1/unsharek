//! What the macro's own sampled tests (`<name>_matches_its_bpf_sampled`, in the examples) don't
//! say: that `run_bpf` refuses what the kernel refuses.

use seccomp_fn::*;

#[test]
#[should_panic(expected = "isn't a return")]
fn run_bpf_refuses_no_return() {
    run_bpf(&[SockFilter { code: 0x20, jt: 0, jf: 0, k: 0 }], &SeccompData::default());
}

#[test]
#[should_panic(expected = "refuses")]
fn run_bpf_refuses_a_jump_out() {
    let p = [SockFilter { code: 0x15, jt: 1, jf: 0, k: 0 }, SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 }];
    run_bpf(&p, &SeccompData::default());
}

#[test]
#[should_panic(expected = "refuses")]
fn run_bpf_refuses_a_load_past_seccomp_data() {
    let p = [SockFilter { code: 0x20, jt: 0, jf: 0, k: 64 }, SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 }];
    run_bpf(&p, &SeccompData::default());
}
