use std::cmp::Ordering;

use crate::block::BlockContents;
use crate::options::Options;

use integer_encoding::{FixedIntWriter, VarIntWriter};

/// BlockBuilder contains functionality for building a block consisting of consecutive key-value entries
pub struct BlockBuilder {
    opt: Options,
    buffer: Vec<u8>,
    restarts: Vec<u32>,

    last_key: Vec<u8>,
    restart_counter: usize,
    counter: usize,
}

impl BlockBuilder {
    pub fn new(o: Options) -> BlockBuilder {
        let mut restarts = vec![0];
        restarts.reserve(1023);

        BlockBuilder {
            buffer: Vec::with_capacity(o.block_size),
            opt: o,
            restarts,
            last_key: Vec::new(),
            restart_counter: 0,
            counter: 0,
        }
    }

    pub fn entries(&self) -> usize {
        self.counter
    }

    pub fn last_key(&self) -> &[u8] {
        &self.last_key
    }

    pub fn size_estimate(&self) -> usize {
        self.buffer.len() + 4 * self.restarts.len() + 4
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.restarts.clear();
        self.last_key.clear();
        self.restart_counter = 0;
        self.counter = 0;
    }

    pub fn add(&mut self, key: &[u8], val: &[u8]) {
        assert!(self.restart_counter <= self.opt.block_restart_interval);
        assert!(
            self.buffer.is_empty()
                || self.opt.comparator.compare(self.last_key.as_slice(), key) == Ordering::Less
        );

        let mut shared = 0;

        if self.restart_counter < self.opt.block_restart_interval {
            let smallest = if self.last_key.len() < key.len() {
                self.last_key.len()
            } else {
                key.len()
            };

            while shared < smallest && self.last_key[shared] == key[shared] {
                shared += 1;
            }
        } else {
            self.restarts.push(self.buffer.len() as u32);
            self.last_key.resize(0, 0);
            self.restart_counter = 0;
        }

        let non_shared = key.len() - shared;

        self.buffer
            .write_varint(shared)
            .expect("write to buffer failed");
        self.buffer
            .write_varint(non_shared)
            .expect("write to buffer failed");
        self.buffer
            .write_varint(val.len())
            .expect("write to buffer failed");
        self.buffer.extend_from_slice(&key[shared..]);
        self.buffer.extend_from_slice(val);

        // Update key
        self.last_key.resize(shared, 0);
        self.last_key.extend_from_slice(&key[shared..]);

        self.restart_counter += 1;
        self.counter += 1;
    }

    pub fn finish(mut self) -> BlockContents {
        self.buffer.reserve(self.restarts.len() * 4 + 4);

        // 1. Append RESTARTS
        for r in self.restarts.iter() {
            self.buffer
                .write_fixedint(*r as u32)
                .expect("write to buffer failed");
        }

        // 2. Append N_RESTARTS
        self.buffer
            .write_fixedint(self.restarts.len() as u32)
            .expect("write to buffer failed");

        // done
        self.buffer
    }
}