#[test]
fn aaa_require_nextest() {
    assert!(
        std::env::var_os("NEXTEST").is_some(),
        "run tests with `cargo nextest run`, not plain `cargo test` (each test must run in its own process)"
    );
}
