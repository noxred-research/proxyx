//! `basic_header` fuzz target: libFuzzer entry under `cargo fuzz`, stdin replay
//! otherwise. The body lives in `proxyx_fuzz::basic_header`.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| proxyx_fuzz::basic_header(data));

#[cfg(not(fuzzing))]
fn main() {
    proxyx_fuzz::run_stdin(proxyx_fuzz::basic_header);
}
