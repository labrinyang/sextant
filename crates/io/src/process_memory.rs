//! Actual process RSS sampling and conservative new-work admission. This is
//! an admission threshold, not a promise to cap allocator or process memory.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySample {
    pub rss_bytes: Option<u64>,
    pub sampled_age_ms: u64,
    pub admission_threshold_bytes: Option<u64>,
    /// Estimated working-set headroom per newly admitted request, not a bound.
    pub estimated_request_headroom_bytes: u64,
    pub reserved_new_work_bytes: u64,
    pub admitted: u64,
    pub rejected: u64,
}
struct State {
    rss: Option<u64>,
    at: Instant,
    reserved: u64,
    admitted: u64,
    rejected: u64,
}
pub struct ProcessMemory {
    threshold: Option<u64>,
    per_request: u64,
    state: Mutex<State>,
}
pub struct MemoryAdmission {
    owner: Arc<ProcessMemory>,
    bytes: u64,
}
impl Drop for MemoryAdmission {
    fn drop(&mut self) {
        let mut s = self.owner.state.lock().expect("memory admission");
        s.reserved -= self.bytes;
    }
}
impl ProcessMemory {
    pub fn new(threshold: Option<u64>, per_request: u64) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            threshold.is_none_or(|n| n > 0) && (threshold.is_none() || per_request > 0),
            "invalid process memory admission settings"
        );
        Ok(Arc::new(Self {
            threshold,
            per_request,
            state: Mutex::new(State {
                rss: resident_bytes().ok(),
                at: Instant::now(),
                reserved: 0,
                admitted: 0,
                rejected: 0,
            }),
        }))
    }
    pub fn from_env() -> anyhow::Result<Arc<Self>> {
        let threshold = match std::env::var("SOLVER_RSS_ADMISSION_BYTES") {
            Ok(value) => Some(value.parse::<u64>()?),
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(error.into()),
        };
        let per = match std::env::var("SOLVER_REQUEST_MEMORY_RESERVE_BYTES") {
            Ok(value) => value.parse()?,
            // Headroom for VM memory, pinned facts, optional checkpoints and
            // payloads. Other allocations can grow beyond this estimate.
            Err(std::env::VarError::NotPresent) => 32 * 1024 * 1024,
            Err(error) => return Err(error.into()),
        };
        Self::new(threshold, per)
    }
    pub fn start(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            loop {
                interval.tick().await;
                let Some(owner) = weak.upgrade() else { break };
                owner.refresh();
            }
        });
    }
    pub fn refresh(&self) {
        let value = resident_bytes().ok();
        let mut s = self.state.lock().expect("RSS sample");
        s.rss = value;
        s.at = Instant::now();
    }
    pub fn admit(self: &Arc<Self>) -> anyhow::Result<MemoryAdmission> {
        let mut s = self.state.lock().expect("memory admission");
        let bytes = if self.threshold.is_some() {
            self.per_request
        } else {
            0
        };
        let permitted = self.threshold.is_none_or(|threshold| {
            s.at.elapsed() <= Duration::from_secs(2)
                && s.rss.is_some_and(|rss| {
                    rss.saturating_add(s.reserved).saturating_add(bytes) <= threshold
                })
        });
        if !permitted {
            s.rejected += 1;
            anyhow::bail!("overloaded: process memory admission threshold");
        }
        s.reserved = s
            .reserved
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("memory reservation overflow"))?;
        s.admitted += 1;
        Ok(MemoryAdmission {
            owner: self.clone(),
            bytes,
        })
    }
    pub fn sample(&self) -> MemorySample {
        let s = self.state.lock().expect("RSS sample");
        MemorySample {
            rss_bytes: s.rss,
            sampled_age_ms: s.at.elapsed().as_millis() as u64,
            admission_threshold_bytes: self.threshold,
            estimated_request_headroom_bytes: self.per_request,
            reserved_new_work_bytes: s.reserved,
            admitted: s.admitted,
            rejected: s.rejected,
        }
    }
}
#[cfg(target_os = "linux")]
fn resident_bytes() -> anyhow::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .ok_or_else(|| anyhow::anyhow!("VmRSS unavailable"))?;
    let kb = value
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("VmRSS empty"))?
        .parse::<u64>()?;
    kb.checked_mul(1024)
        .ok_or_else(|| anyhow::anyhow!("VmRSS overflow"))
}
#[cfg(target_os = "macos")]
fn resident_bytes() -> anyhow::Result<u64> {
    #[repr(C)]
    #[derive(Default)]
    struct TaskInfo {
        virtual_size: u64,
        resident_size: u64,
        total_user: u64,
        total_system: u64,
        threads_user: u64,
        threads_system: u64,
        counters: [i32; 12],
    }
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut std::ffi::c_void,
            size: i32,
        ) -> i32;
    }
    let mut info = TaskInfo::default();
    let size = std::mem::size_of::<TaskInfo>() as i32;
    // PROC_PIDTASKINFO. Kernel copies the exact repr(C) task-info structure.
    // SAFETY: `info` is a valid, aligned, writable buffer of exactly `size`
    // bytes, and `proc_pidinfo` writes at most `size` bytes into it; the
    // kernel fills the layout's leading fields, which are plain integers.
    let read = unsafe {
        proc_pidinfo(
            std::process::id() as i32,
            4,
            0,
            &mut info as *mut _ as *mut std::ffi::c_void,
            size,
        )
    };
    anyhow::ensure!(read == size, "process RSS unavailable");
    Ok(info.resident_size)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn resident_bytes() -> anyhow::Result<u64> {
    anyhow::bail!("RSS measurement unsupported on this platform")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_real_rss_and_admission_reservations_are_shared() {
        let rss = resident_bytes().unwrap();
        assert!(rss > 0);
        let owner = ProcessMemory::new(Some(120), 10).unwrap();
        {
            let mut state = owner.state.lock().unwrap();
            state.rss = Some(100);
        }
        let first = owner.admit().unwrap();
        let second = owner.clone().admit().unwrap();
        assert!(owner.admit().is_err());
        assert_eq!(owner.sample().reserved_new_work_bytes, 20);
        drop(first);
        assert!(owner.admit().is_ok());
        drop(second);
        assert_eq!(owner.sample().reserved_new_work_bytes, 0);
    }
    #[test]
    fn missing_or_stale_measurement_fails_closed_only_when_configured() {
        let owner = ProcessMemory::new(Some(1024), 10).unwrap();
        {
            let mut state = owner.state.lock().unwrap();
            state.rss = None;
        }
        assert!(owner.admit().is_err());
        let disabled = ProcessMemory::new(None, 0).unwrap();
        disabled.state.lock().unwrap().rss = None;
        assert!(disabled.admit().is_ok());
        {
            let mut state = owner.state.lock().unwrap();
            state.rss = Some(1);
            state.at = Instant::now() - Duration::from_secs(3);
        }
        assert!(owner.admit().is_err());
    }
}
