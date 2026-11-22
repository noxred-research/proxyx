//! `pool_api_body` fuzz target: libFuzzer entry under `cargo fuzz`, stdin replay
//! otherwise. The body lives in `proxyx_fuzz::pool_api_body`.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| proxyx_fuzz::pool_api_body(data));

#[cfg(not(fuzzing))]
fn main() {
    proxyx_fuzz::run_stdin(proxyx_fuzz::pool_api_body);
}
