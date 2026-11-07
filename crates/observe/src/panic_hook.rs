// Forked from cowprotocol/services@dc906ab: crates/observe/src/panic_hook.rs
// Upstream licence: MIT OR Apache-2.0. Changes: kept `install` only; the tests
// re-run this test binary as a child instead of being `#[ignore]`d manual runs.
// Copyright (c) 2021 Gnosis Ltd
// Copyright (c) 2022 Cow Service Lda

/// Install a panic hook that first calls the previous panic hook and then exits
/// the process.
///
/// This prevents the situation where a background task/thread unexpectedly or
/// unnoticed panics which can affect the rest of the process in unpredictable
/// ways like a cache never getting updated.
///
/// The downside of this approach is that it prevents use of
/// expected/intentional panics. We do not use those so this isn't a problem. See https://github.com/cowprotocol/services/issues/514 for
/// alternatives.
pub fn install() {
    let previous_hook = std::panic::take_hook();
    let new_hook = move |info: &std::panic::PanicHookInfo| {
        previous_hook(info);
        std::process::exit(1);
    };
    std::panic::set_hook(Box::new(new_hook));
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Output};

    /// Set in the child process only; its value names what the child does.
    const CHILD: &str = "PANIC_HOOK_TEST_CHILD";

    /// Run this test binary again with `test` alone selected and `CHILD` set to
    /// `mode`. Output is not captured there, so the previous hook's report
    /// reaches the child's stderr before the process exits.
    fn child(test: &str, mode: &str) -> Output {
        // Test names are paths below the crate root, wherever this module
        // lives.
        let (_, module) = module_path!()
            .split_once("::")
            .expect("a module below the crate root");
        let name = format!("{module}::{test}");
        Command::new(std::env::current_exe().expect("test binary path"))
            .args([
                name.as_str(),
                "--exact",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env(CHILD, mode)
            .output()
            .expect("child test process")
    }

    /// What the child does: panic on another thread or in a tokio task, with
    /// or without the hook. It exits 0 only if the panic let it live.
    fn run_child(mode: &str) -> ! {
        if mode.ends_with("+hook") {
            super::install();
        }
        if mode.starts_with("thread") {
            let _ = std::thread::spawn(|| panic!("background thread panicked")).join();
        } else {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let _ = tokio::spawn(async { panic!("background task panicked") }).await;
            });
        }
        std::process::exit(0)
    }

    #[test]
    fn a_panicking_thread_exits_the_process_and_keeps_its_report() {
        if let Ok(mode) = std::env::var(CHILD) {
            run_child(&mode);
        }
        let test = "a_panicking_thread_exits_the_process_and_keeps_its_report";

        let hooked = child(test, "thread+hook");
        assert_eq!(hooked.status.code(), Some(1), "{hooked:?}");
        assert!(
            String::from_utf8_lossy(&hooked.stderr).contains("background thread panicked"),
            "the previous hook still reports the panic: {hooked:?}"
        );

        // Without the hook the process outlives the thread, which is the
        // failure the hook exists to end.
        let unhooked = child(test, "thread");
        assert_eq!(unhooked.status.code(), Some(0), "{unhooked:?}");
    }

    #[test]
    fn a_panicking_tokio_task_exits_the_process() {
        if let Ok(mode) = std::env::var(CHILD) {
            run_child(&mode);
        }
        let test = "a_panicking_tokio_task_exits_the_process";

        let hooked = child(test, "task+hook");
        assert_eq!(hooked.status.code(), Some(1), "{hooked:?}");
        assert!(
            String::from_utf8_lossy(&hooked.stderr).contains("background task panicked"),
            "{hooked:?}"
        );

        // tokio catches a task's panic into its JoinError, so without the hook
        // a detached task dies and the process carries on.
        let unhooked = child(test, "task");
        assert_eq!(unhooked.status.code(), Some(0), "{unhooked:?}");
    }
}
