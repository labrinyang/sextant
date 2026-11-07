//! Anti-drift check for adding a chain: a manifest must be embedded, given a
//! compose service, and named in `.env.example`, or the build says so.

use std::fs;
use std::path::Path;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn every_manifest_is_embedded_deployed_and_documented() {
    let keys: Vec<&str> = sextant::manifest::SOURCES
        .iter()
        .map(|(key, _)| *key)
        .collect();

    // A manifest file that no SOURCES entry embeds is silently never loaded.
    let mut embedded: Vec<String> = keys.iter().map(|key| format!("{key}.json")).collect();
    let dir = root().join("crates/chain/manifest");
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let name = entry.expect("manifest entry").file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".json") {
            embedded.retain(|candidate| candidate != name.as_ref());
        }
    }
    assert!(
        embedded.is_empty(),
        "these manifests are not embedded in manifest::SOURCES: {embedded:?}"
    );

    let compose = read(&root().join("deploy/docker-compose.yml"));
    let env = read(&root().join(".env.example"));
    let chain_line = env
        .lines()
        .find(|line| line.starts_with("# Which chain"))
        .expect(".env.example names the chains on its SOLVER_CHAIN line");
    for key in &keys {
        assert!(
            compose.contains(&format!("sextant-{key}:")),
            "deploy/docker-compose.yml has no sextant-{key} service"
        );
        assert!(
            compose.contains(&format!("profiles: [{key}]")),
            "deploy/docker-compose.yml has no {key} profile"
        );
        assert!(
            chain_line.contains(key),
            ".env.example's SOLVER_CHAIN line does not name {key}"
        );
    }
}
