// Forked from cowprotocol/services@dc906ab: crates/observe/src/tracing/init.rs
// Upstream licence: MIT OR Apache-2.0. Changes: one fmt layer on stdout,
// compact or JSON by the caller's choice, passing only the events of the crate
// the caller names; no OpenTelemetry, request ids, stderr split, filter reload
// or tracing panic hook.
// Copyright (c) 2021 Gnosis Ltd
// Copyright (c) 2022 Cow Service Lda
//
// A line carries the event's message exactly as the caller formatted it, in
// both formats: whatever the caller redacted stays redacted.

use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::TryInitError;
use tracing_subscriber::{Layer, registry::LookupSpan};

/// How a line is written: `compact` for a person reading `docker logs`,
/// `json` for a collector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogFormat {
    Compact,
    Json,
}

impl LogFormat {
    /// `compact` or `json`, spelled exactly.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "compact" => Some(Self::Compact),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// A layer writing `crate_name`'s events at INFO and above to `writer`. The
/// crate's dependencies log through `tracing` too; their events are not
/// written.
pub fn layer<S, W>(
    format: LogFormat,
    crate_name: &str,
    writer: W,
) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let events = Targets::new().with_target(crate_name, Level::INFO);
    let layer = tracing_subscriber::fmt::layer().with_writer(writer);
    match format {
        LogFormat::Compact => layer
            .compact()
            .with_target(false)
            .with_filter(events)
            .boxed(),
        LogFormat::Json => layer
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_filter(events)
            .boxed(),
    }
}

/// Install the process's subscriber, writing `crate_name`'s events to stdout.
/// Call it once, before anything logs; until then events go nowhere.
pub fn init(format: LogFormat, crate_name: &str) -> Result<(), TryInitError> {
    tracing_subscriber::registry()
        .with(layer(format, crate_name, std::io::stdout))
        .try_init()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The lines `format` writes for one INFO, one WARN and one event from a
    /// dependency.
    fn lines(format: LogFormat) -> Vec<String> {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::registry().with(layer(
            format,
            env!("CARGO_CRATE_NAME"),
            buffer.clone(),
        ));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("pool {:#x} skipped (balance below reserve)", 0x5151u64);
            tracing::warn!("readiness: ready=false (transport)");
            tracing::warn!(target: "hyper", "a dependency's line");
        });
        let bytes = buffer.0.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The binary names its own crate, `sextant`. A target matches by prefix,
    /// so the workspace's member crates (`sextant_discovery`,
    /// `sextant_market`, ...) are written under that name too, and a
    /// dependency's events still are not.
    #[test]
    fn member_crates_are_written_under_the_binary_s_name() {
        let buffer = Buffer::default();
        let subscriber =
            tracing_subscriber::registry().with(layer(LogFormat::Json, "sextant", buffer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "sextant::server", "server");
            tracing::info!(target: "sextant_discovery::state::indexed", "discovery");
            tracing::info!(target: "sextant_market::resident", "market");
            tracing::info!(target: "hyper::client", "dependency");
        });
        let bytes = buffer.0.lock().unwrap().clone();
        let messages: Vec<String> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| {
                let event: serde_json::Value = serde_json::from_str(line).unwrap();
                event["message"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(messages, ["server", "discovery", "market"]);
    }

    const POOL: &str = "pool 0x5151 skipped (balance below reserve)";
    const READINESS: &str = "readiness: ready=false (transport)";

    #[test]
    fn a_format_is_spelled_exactly() {
        assert_eq!(LogFormat::parse("compact"), Some(LogFormat::Compact));
        assert_eq!(LogFormat::parse("json"), Some(LogFormat::Json));
        for refused in ["", "JSON", "text", "pretty"] {
            assert_eq!(LogFormat::parse(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn a_compact_line_ends_with_the_message_it_was_given() {
        let lines = lines(LogFormat::Compact);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains(" INFO "), "{}", lines[0]);
        assert!(lines[0].ends_with(&format!(" {POOL}")), "{}", lines[0]);
        assert!(lines[1].contains(" WARN "), "{}", lines[1]);
        assert!(lines[1].ends_with(&format!(" {READINESS}")), "{}", lines[1]);
    }

    #[test]
    fn a_json_line_carries_the_message_it_was_given() {
        let lines = lines(LogFormat::Json);
        assert_eq!(lines.len(), 2, "{lines:?}");
        let events: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events[0]["level"], "INFO");
        assert_eq!(events[0]["message"], POOL);
        assert_eq!(events[1]["level"], "WARN");
        assert_eq!(events[1]["message"], READINESS);
        assert!(events.iter().all(|event| {
            event["target"]
                .as_str()
                .unwrap()
                .starts_with(env!("CARGO_CRATE_NAME"))
        }));
    }
}
