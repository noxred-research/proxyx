//! `password_verify` fuzz target: libFuzzer entry under `cargo fuzz`, stdin replay
//! otherwise. The body lives in `proxyx_fuzz::password_verify`.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| proxyx_fuzz::password_verify(data));

#[cfg(not(fuzzing))]
fn main() {
    proxyx_fuzz::run_stdin(proxyx_fuzz::password_verify);
}
