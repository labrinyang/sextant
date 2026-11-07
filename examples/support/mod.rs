use anyhow::{Context, bail};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const RPC_ALIAS: &str = "solver_predeploy";
static CONFIG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct AnvilConfig {
    path: PathBuf,
}

impl Drop for AnvilConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn create_config(fork_url: &str) -> anyhow::Result<AnvilConfig> {
    let directory = std::env::var_os("SOLVER_ANVIL_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let encoded_url = serde_json::to_string(fork_url).context("encoding Anvil RPC URL")?;
    for _ in 0..100 {
        let sequence = CONFIG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("anvil-{}-{sequence}.toml", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path);
        let mut file = match file {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("creating private Anvil config"),
        };
        let config = AnvilConfig { path };
        if let Err(error) = writeln!(file, "[rpc_endpoints]\n{RPC_ALIAS} = {encoded_url}") {
            drop(file);
            drop(config);
            return Err(error).context("writing private Anvil config");
        }
        return Ok(config);
    }
    bail!("could not allocate a private Anvil config")
}

/// An Anvil child whose paid fork URL is supplied through a mode-0600 Foundry
/// config, never argv. Drop is the final cleanup boundary for every `?` path.
pub struct ManagedAnvil {
    child: Child,
    _config: AnvilConfig,
}

impl ManagedAnvil {
    pub fn spawn(fork_url: &str, block: u64, port: u16) -> anyhow::Result<Self> {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            bail!("Anvil port {port} is already in use")
        }
        let config = create_config(fork_url)?;
        let child = Command::new("anvil")
            .env("FOUNDRY_CONFIG", &config.path)
            .env_remove("SOLVER_RPC")
            .args([
                "--fork-url",
                RPC_ALIAS,
                "--fork-block-number",
                &block.to_string(),
                "--port",
                &port.to_string(),
                "--auto-impersonate",
                "--silent",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawning anvil")?;
        Ok(Self {
            child,
            _config: config,
        })
    }

    pub fn ensure_running(&mut self) -> anyhow::Result<()> {
        if let Some(status) = self.child.try_wait().context("checking Anvil process")? {
            bail!("Anvil exited before becoming ready: {status}")
        }
        Ok(())
    }

    fn terminate(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let interrupted = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status()
            .is_ok_and(|status| status.success());
        if !interrupted {
            let _ = self.child.kill();
            let _ = self.child.wait();
            return;
        }
        for _ in 0..50 {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ManagedAnvil {
    fn drop(&mut self) {
        self.terminate();
    }
}
