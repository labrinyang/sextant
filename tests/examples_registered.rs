//! Anti-drift checks for the examples. The root package sets
//! `autoexamples = false`, so Cargo builds only the example files that
//! Cargo.toml registers: an unregistered one silently never builds. And a
//! comment or doc that cites an example file that is gone points nowhere.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Every example path starts with this, relative to the package root.
const EXAMPLES: &str = "examples/";
/// What `referenced_example_files_exist` reads: these files, and the files
/// with these extensions anywhere under these directories.
const SCANNED_FILES: [&str; 1] = ["README.md"];
/// Every published tree has these. A missing one fails the test, so a rename
/// cannot silently stop the scan.
const REQUIRED_DIRS: [&str; 4] = ["src", "crates", "examples", "tests"];
/// Maintainers' notes: absent from the published repository, scanned only
/// when present.
const OPTIONAL_DIRS: [&str; 1] = ["docs"];
const SCANNED_EXTENSIONS: [&str; 3] = ["rs", "md", "toml"];
/// Records of the code as it was when they were written: the architecture
/// rewrite's plan and its design records. They quote files that later changed
/// or never existed and are not kept current, so their citations are skipped.
const RECORDS: [&str; 2] = ["docs/rewrite/PLAN.md", "docs/rewrite/design"];

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `path` values of the root Cargo.toml that lie under the examples
/// directory, as written there.
fn registered_example_paths() -> BTreeSet<String> {
    read(&root().join("Cargo.toml"))
        .lines()
        .filter_map(|line| {
            let value = line.trim().strip_prefix("path")?.trim_start();
            let value = value.strip_prefix('=')?.trim();
            let value = value.strip_prefix('"')?.strip_suffix('"')?;
            value.starts_with(EXAMPLES).then(|| value.to_owned())
        })
        .collect()
}

/// The top-level `.rs` files of the examples directory, in the same form.
/// Subdirectories are shared modules such as `support`, not examples.
fn example_files() -> BTreeSet<String> {
    let dir = root().join(EXAMPLES);
    fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.unwrap_or_else(|e| panic!("read {}: {e}", dir.display())))
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rs"))
        .map(|name| format!("{EXAMPLES}{name}"))
        .collect()
}

/// Pushes every file under `dir` with a scanned extension, skipping build
/// output (`target`).
fn collect_scanned(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        let path = entry.path();
        let kind = entry
            .file_type()
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()));
        if kind.is_dir() {
            if entry.file_name() != "target" {
                collect_scanned(&path, out);
            }
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| SCANNED_EXTENSIONS.contains(&ext))
        {
            out.push(path);
        }
    }
}

/// Each substring of `line` that is the examples prefix, then an identifier
/// (a non-empty run of ASCII letters, digits and underscores), then `.rs`.
fn cited_example_files(line: &str) -> impl Iterator<Item = &str> {
    line.match_indices(EXAMPLES).filter_map(move |(at, _)| {
        let stem = at + EXAMPLES.len();
        let stem_len = line[stem..]
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        let end = stem + stem_len;
        if stem_len > 0 && line[end..].starts_with(".rs") {
            Some(&line[at..end + ".rs".len()])
        } else {
            None
        }
    })
}

#[test]
fn every_example_file_is_registered() {
    let registered = registered_example_paths();
    let on_disk = example_files();
    let unregistered: Vec<_> = on_disk.difference(&registered).collect();
    let missing: Vec<_> = registered.difference(&on_disk).collect();
    assert!(
        unregistered.is_empty() && missing.is_empty(),
        "Cargo.toml's [[example]] paths must be exactly the top-level example files.\n\
         files with no [[example]] entry (autoexamples = false, so they never build): \
         {unregistered:?}\n\
         [[example]] paths with no such file: {missing:?}"
    );
}

#[test]
fn referenced_example_files_exist() {
    let root = root();
    let mut files: Vec<PathBuf> = SCANNED_FILES.iter().map(|file| root.join(file)).collect();
    for dir in REQUIRED_DIRS {
        collect_scanned(&root.join(dir), &mut files);
    }
    for dir in OPTIONAL_DIRS {
        let dir = root.join(dir);
        if dir.is_dir() {
            collect_scanned(&dir, &mut files);
        }
    }
    let mut dangling = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(root).unwrap_or(file);
        if RECORDS.iter().any(|record| relative.starts_with(record)) {
            continue;
        }
        let text = read(file);
        let shown = relative.display();
        for (index, line) in text.lines().enumerate() {
            for cited in cited_example_files(line) {
                if !root.join(cited).is_file() {
                    dangling.push(format!("{shown}:{}: {cited}", index + 1));
                }
            }
        }
    }
    assert!(
        dangling.is_empty(),
        "these cite example files that do not exist:\n{}",
        dangling.join("\n")
    );
}
