use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize},
};

use dashmap::DashMap;
use tokio::time::Duration;

use crate::scan_utils::shared::types_and_config::{ScanErr, ScannerErrWithMsg};

type IpV4DashMap = Vec<DashMap<([u8; 4], [u8; 2]), ()>>;
type IpV6DashMap = Vec<DashMap<([u8; 16], [u8; 2]), ()>>;

#[derive(Debug)]
pub struct TimedBuckets {
    // no universal bucket because this would cost performance
    buckets_ipv4: IpV4DashMap,
    buckets_ipv6: IpV6DashMap,
    current: AtomicUsize,
    bucket_count: usize, // 8, max_ack_time = 1
}

impl TimedBuckets {
    pub fn create(bucket_count: usize) -> Self {
        let bucket_count = if bucket_count < 1 { 4 } else { bucket_count };
        let mut buckets_ipv4 = Vec::with_capacity(bucket_count);
        for _ in 0..bucket_count {
            buckets_ipv4.push(DashMap::new());
        }
        let mut buckets_ipv6 = Vec::with_capacity(bucket_count);
        for _ in 0..bucket_count {
            buckets_ipv6.push(DashMap::new());
        }
        Self {
            buckets_ipv4,
            buckets_ipv6,
            current: AtomicUsize::new(0),
            bucket_count,
        }
    }

    pub fn insert_ipv4(self: Arc<Self>, key: ([u8; 4], [u8; 2])) {
        let idx = self.current.load(std::sync::atomic::Ordering::Acquire);
        self.buckets_ipv4[idx].insert(key, ());
    }

    pub fn insert_ipv6(self: Arc<Self>, key: ([u8; 16], [u8; 2])) {
        let idx = self.current.load(std::sync::atomic::Ordering::Acquire);
        self.buckets_ipv6[idx].insert(key, ());
    }

    pub fn browse_ipv4(&self, key: &([u8; 4], [u8; 2])) -> bool {
        for bucket in &self.buckets_ipv4 {
            if bucket.get(key).is_some() {
                return true;
            }
        }
        false
    }

    pub fn browse_ipv6(&self, key: &([u8; 16], [u8; 2])) -> bool {
        for bucket in &self.buckets_ipv6 {
            if bucket.get(key).is_some() {
                return true;
            }
        }
        false
    }

    pub fn calculate_ticks(
        max_ack_time: u64,
        bucket_count: usize,
    ) -> Result<Duration, ScannerErrWithMsg> {
        let divisor = max_ack_time
            .checked_add(bucket_count as u64)
            .ok_or(ScannerErrWithMsg {
                err: ScanErr::DuplicationBucket,
                msg: String::from("max_ack_time + bucket_count is too big for u64"),
            })?;
        let tick = divisor / bucket_count as u64 * 1000;
        if tick < 50 {
            return Err(ScannerErrWithMsg {
                err: ScanErr::DuplicationBucket,
                msg: String::from("tick < 50ms: increase max_ack_time or decrease bucket_count"),
            });
        }
        Ok(Duration::from_millis(tick))
    }

    pub fn start_ticker(self: Arc<Self>, tick: Duration, ipv6: bool, done: Arc<AtomicBool>) {
        if ipv6 {
            loop {
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(tick);
                self.advance_ipv6();
            }
        } else {
            loop {
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(tick);
                self.advance_ipv4();
            }
        }
    }

    fn advance_ipv4(&self) {
        let prev = self
            .current
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let i = (prev + 1) % self.bucket_count;
        self.current.store(i, std::sync::atomic::Ordering::Release);
        self.buckets_ipv4[i].clear();
    }

    fn advance_ipv6(&self) {
        let prev = self
            .current
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let i = (prev + 1) % self.bucket_count;
        self.current.store(i, std::sync::atomic::Ordering::Release);
        self.buckets_ipv6[i].clear();
    }
}
