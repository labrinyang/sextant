use sextant::config::Config;
use sextant::server::serve;
use sextant_observe::tracing::LogFormat;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A panic anywhere, a background refresher included, ends the process
    // instead of leaving it half alive.
    sextant_observe::panic_hook::install();
    let format = match std::env::var("SOLVER_LOG_FORMAT") {
        Ok(value) => LogFormat::parse(&value).ok_or_else(|| {
            anyhow::anyhow!("SOLVER_LOG_FORMAT must be compact or json, got {value:?}")
        })?,
        Err(std::env::VarError::NotPresent) => LogFormat::Compact,
        Err(error) => anyhow::bail!("SOLVER_LOG_FORMAT is not valid Unicode: {error}"),
    };
    sextant_observe::tracing::init(format, "sextant")?;
    serve(Config::from_env()?).await
}
