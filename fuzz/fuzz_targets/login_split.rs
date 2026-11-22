//! `login_split` fuzz target: libFuzzer entry under `cargo fuzz`, stdin replay
//! otherwise. The body lives in `proxyx_fuzz::login_split`.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| proxyx_fuzz::login_split(data));

#[cfg(not(fuzzing))]
fn main() {
    proxyx_fuzz::run_stdin(proxyx_fuzz::login_split);
}
