use foldhash::fast::FixedState;
use std::{
    fmt::Display,
    hash::{BuildHasher, Hash, Hasher},
}; // BuildHasher trait importieren!

pub struct Deduplicator {
    buffer: Vec<u64>,
    mask: usize,
    hasher_state: FixedState,
}

impl Deduplicator {
    pub fn new(capacity: usize) -> Self {
        // Enforce power of 2 for fast modulo
        let size = capacity.next_power_of_two();

        Self {
            buffer: vec![0; size],
            mask: size - 1,
            // Fixed state per Deduplicator instance.
            // Using a fixed seed is slightly faster than random, sufficient for non-DOS-adversarial traffic.
            hasher_state: FixedState::default(),
        }
    }

    /// Returns true if the element was already present (duplicate).
    /// If not present, it inserts it and returns false.
    ///
    /// Requires mutable access (&mut self) because it's not using Atomics anymore.
    pub fn check_and_insert<T: Hash>(&mut self, key: T) -> bool {
        let hash = self.hasher_state.hash_one(&key);

        // Use hash for both index and tag.
        // Index determines the slot.
        // Tag is the value stored to identify the entry.
        let index = (hash as usize) & self.mask;
        let tag = if hash == 0 { 1 } else { hash };

        let existing = self.buffer[index];

        if existing == tag {
            //eprintln!("duplicate found");
            return true; // Duplicate found
        }

        // Overwrite existing entry (collision or empty slot)
        self.buffer[index] = tag;
        false
    }
}
