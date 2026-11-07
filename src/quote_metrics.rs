//! What the quote endpoint has done since the process started: each request's
//! outcome, and how long quotes, their snapshots and their simulations took.
//! `/health` carries it as JSON and `/metrics` in Prometheus text, so a shadow
//! run can be read without parsing logs. Counters only grow; a restart resets
//! them, as Prometheus expects of a counter.

use serde_json::{Value, json};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuoteOutcome {
    Ok,
    NoRoute,
    SimulationFailed,
    BadRequest,
    Rejected,
    NotReady,
    Overloaded,
    RpcCapacity,
    NativeBusy,
    Timeout,
    Error,
}

impl QuoteOutcome {
    const ALL: [Self; 11] = [
        Self::Ok,
        Self::NoRoute,
        Self::SimulationFailed,
        Self::BadRequest,
        Self::Rejected,
        Self::NotReady,
        Self::Overloaded,
        Self::RpcCapacity,
        Self::NativeBusy,
        Self::Timeout,
        Self::Error,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoRoute => "no_route",
            Self::SimulationFailed => "simulation_failed",
            Self::BadRequest => "bad_request",
            Self::Rejected => "rejected",
            Self::NotReady => "not_ready",
            Self::Overloaded => "overloaded",
            Self::RpcCapacity => "rpc_capacity",
            Self::NativeBusy => "native_busy",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|outcome| *outcome == self)
            .expect("every outcome is listed")
    }
}

/// Upper bounds, in milliseconds, of the histogram buckets; one more bucket
/// holds everything slower.
const BUCKETS_MS: [u64; 11] = [5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];

#[derive(Default)]
struct Histogram {
    buckets: [AtomicU64; BUCKETS_MS.len() + 1],
    count: AtomicU64,
    sum_ms: AtomicU64,
}

impl Histogram {
    fn observe(&self, ms: u64) {
        let bucket = BUCKETS_MS
            .iter()
            .position(|&bound| ms <= bound)
            .unwrap_or(BUCKETS_MS.len());
        self.buckets[bucket].fetch_add(1, Relaxed);
        self.count.fetch_add(1, Relaxed);
        self.sum_ms.fetch_add(ms, Relaxed);
    }

    /// Cumulative counts at each bound, as Prometheus reads a histogram.
    fn cumulative(&self) -> Vec<(Option<u64>, u64)> {
        let mut running = 0;
        self.buckets
            .iter()
            .enumerate()
            .map(|(index, bucket)| {
                running += bucket.load(Relaxed);
                (BUCKETS_MS.get(index).copied(), running)
            })
            .collect()
    }

    fn json(&self) -> Value {
        json!({
            "count": self.count.load(Relaxed),
            "sumMs": self.sum_ms.load(Relaxed),
            "buckets": self.cumulative().into_iter().map(|(bound, count)| json!({
                "leMs": bound.map_or_else(|| json!("+Inf"), |bound| json!(bound)),
                "count": count,
            })).collect::<Vec<_>>(),
        })
    }

    fn prometheus(&self, out: &mut String, name: &str, help: &str) {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} histogram");
        for (bound, count) in self.cumulative() {
            let le = bound.map_or_else(|| "+Inf".to_string(), |bound| bound.to_string());
            let _ = writeln!(out, "{name}_bucket{{le=\"{le}\"}} {count}");
        }
        let _ = writeln!(out, "{name}_sum {}", self.sum_ms.load(Relaxed));
        let _ = writeln!(out, "{name}_count {}", self.count.load(Relaxed));
    }
}

#[derive(Default)]
pub(crate) struct QuoteMetrics {
    outcomes: [AtomicU64; QuoteOutcome::ALL.len()],
    /// Every request, whatever its outcome.
    duration: Histogram,
    /// Quotes answered with a route.
    served: Histogram,
    snapshot: Histogram,
    simulate: Histogram,
    /// Quotes waiting for a slot now, and every quote that has had to wait.
    waiting: AtomicU64,
    queued: AtomicU64,
}

/// Counts one quote as waiting for a slot until it is dropped.
pub(crate) struct Waiting<'a>(&'a QuoteMetrics);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Relaxed);
    }
}

impl QuoteMetrics {
    pub(crate) fn record(&self, outcome: QuoteOutcome, ms: u64) {
        self.outcomes[outcome.index()].fetch_add(1, Relaxed);
        self.duration.observe(ms);
        if outcome == QuoteOutcome::Ok {
            self.served.observe(ms);
        }
    }

    /// The stages of a quote answered with a route.
    pub(crate) fn record_stages(&self, snapshot_ms: u64, simulate_ms: u64) {
        self.snapshot.observe(snapshot_ms);
        self.simulate.observe(simulate_ms);
    }

    pub(crate) fn waiting(&self) -> Waiting<'_> {
        self.queued.fetch_add(1, Relaxed);
        self.waiting.fetch_add(1, Relaxed);
        Waiting(self)
    }

    pub(crate) fn count(&self, outcome: QuoteOutcome) -> u64 {
        self.outcomes[outcome.index()].load(Relaxed)
    }

    pub(crate) fn json(&self) -> Value {
        let outcomes: serde_json::Map<String, Value> = QuoteOutcome::ALL
            .iter()
            .map(|&outcome| (outcome.label().to_string(), json!(self.count(outcome))))
            .collect();
        json!({
            "outcomes": outcomes,
            "waiting": self.waiting.load(Relaxed),
            "queued": self.queued.load(Relaxed),
            "durationMs": self.duration.json(),
            "servedMs": self.served.json(),
            "snapshotMs": self.snapshot.json(),
            "simulateMs": self.simulate.json(),
        })
    }

    pub(crate) fn prometheus(&self, out: &mut String) {
        let _ = writeln!(out, "# HELP solver_quotes_total Quote requests by outcome.");
        let _ = writeln!(out, "# TYPE solver_quotes_total counter");
        for outcome in QuoteOutcome::ALL {
            let _ = writeln!(
                out,
                "solver_quotes_total{{outcome=\"{}\"}} {}",
                outcome.label(),
                self.count(outcome)
            );
        }
        let _ = writeln!(
            out,
            "# HELP solver_quotes_waiting Quotes waiting for a slot now."
        );
        let _ = writeln!(out, "# TYPE solver_quotes_waiting gauge");
        let _ = writeln!(out, "solver_quotes_waiting {}", self.waiting.load(Relaxed));
        let _ = writeln!(
            out,
            "# HELP solver_quotes_queued_total Quotes that waited for a slot."
        );
        let _ = writeln!(out, "# TYPE solver_quotes_queued_total counter");
        let _ = writeln!(
            out,
            "solver_quotes_queued_total {}",
            self.queued.load(Relaxed)
        );
        self.duration.prometheus(
            out,
            "solver_quote_duration_ms",
            "Time to answer a quote request, any outcome.",
        );
        self.served.prometheus(
            out,
            "solver_quote_served_ms",
            "Time to answer a quote request with a route.",
        );
        self.snapshot.prometheus(
            out,
            "solver_quote_snapshot_ms",
            "Snapshot time of quotes answered with a route.",
        );
        self.simulate.prometheus(
            out,
            "solver_quote_simulate_ms",
            "Simulation time of quotes answered with a route.",
        );
    }
}

/// The caller's `x-request-id` when it is a plain token, so a quote can be
/// followed from the backend's logs into these; otherwise one made here.
pub(crate) fn request_id(header: Option<&str>) -> String {
    match header {
        Some(id)
            if (1..=64).contains(&id.len())
                && id.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')
                }) =>
        {
            id.to_string()
        }
        _ => {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos() as u64);
            format!("solver-{:x}-{:x}", nanos, NEXT.fetch_add(1, Relaxed))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_outcomes_and_buckets_durations_cumulatively() {
        let metrics = QuoteMetrics::default();
        metrics.record(QuoteOutcome::Ok, 4);
        metrics.record(QuoteOutcome::Ok, 120);
        metrics.record(QuoteOutcome::NoRoute, 30);
        metrics.record(QuoteOutcome::Timeout, 60_000);
        metrics.record_stages(2, 110);
        assert_eq!(metrics.count(QuoteOutcome::Ok), 2);
        assert_eq!(metrics.count(QuoteOutcome::NoRoute), 1);
        assert_eq!(metrics.count(QuoteOutcome::Overloaded), 0);

        let json = metrics.json();
        assert_eq!(json["outcomes"]["timeout"], 1);
        assert_eq!(json["durationMs"]["count"], 4);
        assert_eq!(json["durationMs"]["sumMs"], 60_154);
        assert_eq!(json["servedMs"]["count"], 2);
        let buckets = json["durationMs"]["buckets"].as_array().unwrap();
        assert_eq!(buckets[0], json!({ "leMs": 5, "count": 1 }));
        assert_eq!(buckets[2], json!({ "leMs": 25, "count": 1 }));
        assert_eq!(buckets[3], json!({ "leMs": 50, "count": 2 }));
        assert_eq!(buckets[5], json!({ "leMs": 250, "count": 3 }));
        assert_eq!(
            buckets.last().unwrap(),
            &json!({ "leMs": "+Inf", "count": 4 })
        );

        let mut text = String::new();
        metrics.prometheus(&mut text);
        assert!(text.contains("solver_quotes_total{outcome=\"ok\"} 2\n"));
        assert!(text.contains("solver_quote_duration_ms_bucket{le=\"+Inf\"} 4\n"));
        assert!(text.contains("solver_quote_simulate_ms_sum 110\n"));
        assert!(text.contains("# TYPE solver_quote_served_ms histogram\n"));

        let first = metrics.waiting();
        let second = metrics.waiting();
        assert_eq!(metrics.json()["waiting"], 2);
        drop(first);
        drop(second);
        let json = metrics.json();
        assert_eq!(
            (json["waiting"].clone(), json["queued"].clone()),
            (json!(0), json!(2))
        );
        let mut text = String::new();
        metrics.prometheus(&mut text);
        assert!(text.contains("solver_quotes_waiting 0\n"));
        assert!(text.contains("solver_quotes_queued_total 2\n"));
    }

    #[test]
    fn keeps_a_plain_request_id_and_replaces_anything_else() {
        assert_eq!(
            request_id(Some("6f2c7a1e-0b4d-4f6a-9a3e-2b1c0d9e8f7a")),
            "6f2c7a1e-0b4d-4f6a-9a3e-2b1c0d9e8f7a"
        );
        for bad in [
            None,
            Some(""),
            Some("has space"),
            Some("new\nline"),
            Some(&"x".repeat(65) as &str),
        ] {
            let id = request_id(bad);
            assert!(id.starts_with("solver-"), "{bad:?} -> {id}");
        }
        assert_ne!(request_id(None), request_id(None));
    }
}
