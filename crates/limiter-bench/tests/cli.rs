//! Argument errors are reported before anything connects: the tool never falls back to a default for
//! a value it could not read, and never panics on bad input.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_limiter-bench"))
        .args(args)
        .output()
        .expect("run limiter-bench")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_prints_the_usage_and_exits_zero() {
    let output = run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("usage: limiter-bench"));
}

#[test]
fn a_value_that_is_not_a_positive_integer_is_a_usage_error() {
    // Port 1 would refuse a connection, so exit status 2 proves the value was rejected first.
    for (args, name) in [
        (&["127.0.0.1:1", "abc"][..], "OPS"),
        (&["127.0.0.1:1", "0"], "OPS"),
        (&["127.0.0.1:1", "-5"], "OPS"),
        (&["127.0.0.1:1", "100", "0"], "CLIENTS"),
        (&["127.0.0.1:1", "100", "5000"], "CLIENTS"),
        (&["127.0.0.1:1", "100", "2", "4097"], "BATCH"),
        (
            &["127.0.0.1:1", "100", "2", "8", "all", "x"],
            "PIPELINE_DEPTH",
        ),
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(
            stderr(&output).contains(name),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn fewer_operations_than_clients_is_refused() {
    let output = run(&["127.0.0.1:1", "5", "32"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("at least CLIENTS"));
}

#[test]
fn an_unknown_workload_or_extra_argument_is_refused_before_connecting() {
    let output = run(&["127.0.0.1:1", "100", "2", "8", "bogus"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unknown workload"));
    let output = run(&["127.0.0.1:1", "100", "2", "8", "all", "1", "extra"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn an_unreachable_limiter_is_an_error_not_a_panic() {
    let output = run(&["127.0.0.1:1", "100", "2"]);
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(text.contains("cannot connect to 127.0.0.1:1"), "{text}");
    assert!(!text.contains("panicked"), "{text}");
}
