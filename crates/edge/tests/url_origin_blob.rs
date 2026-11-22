//! RUSTSEC-2026-0592: `Url::origin()` on a deeply nested `blob:` URL recursed once per prefix in `url`
//! 2.5.8 and earlier and overflowed the stack, which aborts the whole process. `url` 2.5.9 returns an
//! opaque origin without recursing. The 256 KiB thread stack makes the old behavior fail every time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use url::Url;

#[test]
fn the_origin_of_nested_blob_urls_is_opaque_and_does_not_overflow_the_stack() {
    let nested = format!("{}https://example.com/", "blob:".repeat(10_000));
    let url = Url::parse(&nested).expect("a nested blob URL parses");
    let origin = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || url.origin())
        .expect("spawn")
        .join()
        .expect("origin() returned instead of overflowing");
    assert!(!origin.is_tuple(), "a nested blob URL has an opaque origin");
}

#[test]
fn the_origin_of_a_single_blob_url_is_its_inner_origin() {
    let url = Url::parse("blob:https://example.com/0c8b5e7e-0000-4000-8000-000000000000").unwrap();
    assert_eq!(url.origin().ascii_serialization(), "https://example.com");
}
