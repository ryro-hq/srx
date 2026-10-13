//! A deliberately stalled libtest process for timeout and child-cleanup checks.

#[test]
fn unbounded_test_fixture() {
    std::thread::sleep(std::time::Duration::from_mins(5));
}
