use crate::cmp::{Comparator, MemtableKeyCmp};
use crate::key_types::{build_memtable_key, parse_internal_key, parse_memtable_key, ValueType};
use crate::key_types::{LookupKey, UserKey};
use crate::skipmap::{SkipMap, SkipMapIter};
use crate::types::{current_key_val, LdbIterator, SequenceNumber};

use std::rc::Rc;

use integer_encoding::FixedInt;

/// Provides Insert/Get/Iterate, based on the SkipMap implementation.
/// MemTable uses MemtableKeys internally, that is, it stores key and value in the [Skipmap] key.
pub struct MemTable {
    map: SkipMap,
}

impl MemTable {
    /// This wraps opt.cmp inside a MemtableKey-specific Comparator.
    pub fn new(cmp: Rc<Box<dyn Comparator>>) -> MemTable {
        MemTable::new_raw(Rc::new(Box::new(MemtableKeyCmp(cmp))))
    }

    /// Doesn't wrap the Comparator in a MemtableKeyCmp.
    fn new_raw(cmp: Rc<Box<dyn Comparator>>) -> MemTable {
        MemTable {
            map: SkipMap::new(cmp),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn approx_mem_usage(&self) -> usize {
        self.map.approx_memory()
    }

    pub fn add<'a>(&mut self, seq: SequenceNumber, t: ValueType, key: UserKey<'a>, value: &[u8]) {
        self.map
            .insert(build_memtable_key(key, value, t, seq), Vec::new())
    }

    /// get returns the value for the given entry and whether the entry is marked as deleted. This
    /// is to distinguish between not-found and found-deleted.
    #[allow(unused_variables)]
    pub fn get(&self, key: &LookupKey) -> (Option<Vec<u8>>, bool) {
        let mut iter = self.map.iter();
        iter.seek(key.memtable_key());

        if let Some((foundkey, _)) = current_key_val(&iter) {
            let (fkeylen, fkeyoff, tag, vallen, valoff) = parse_memtable_key(&foundkey);

            // Compare user key -- if equal, proceed
            // We only care about user key equality here
            if key.user_key() == &foundkey[fkeyoff..fkeyoff + fkeylen] {
                if tag & 0xff == ValueType::TypeValue as u64 {
                    return (Some(foundkey[valoff..valoff + vallen].to_vec()), false);
                } else {
                    return (None, true);
                }
            }
        }
        (None, false)
    }

    pub fn iter(&self) -> MemtableIterator {
        MemtableIterator {
            skipmapiter: self.map.iter(),
        }
    }
}

/// MemtableIterator is an iterator over a MemTable. It is mostly concerned with converting to and
/// from the MemtableKey format used in the inner map; all key-taking or -returning methods deal
/// with InternalKeys.
///
/// This iterator does not skip deleted entries.
pub struct MemtableIterator {
    skipmapiter: SkipMapIter,
}

impl LdbIterator for MemtableIterator {
    fn advance(&mut self) -> bool {
        if !self.skipmapiter.advance() {
            return false;
        }
        self.skipmapiter.valid()
    }
    fn reset(&mut self) {
        self.skipmapiter.reset();
    }
    fn prev(&mut self) -> bool {
        // Make sure this is actually needed (skipping deleted values?).
        let (mut key, mut val) = (vec![], vec![]);
        loop {
            if !self.skipmapiter.prev() {
                return false;
            }
            if self.skipmapiter.current(&mut key, &mut val) {
                let (_, _, tag, _, _) = parse_memtable_key(&key);

                if tag & 0xff == ValueType::TypeValue as u64 {
                    return true;
                } else {
                    continue;
                }
            } else {
                return false;
            }
        }
    }
    fn valid(&self) -> bool {
        self.skipmapiter.valid()
    }
    /// current places the current key (in InternalKey format) and value into the supplied vectors.
    fn current(&self, key: &mut Vec<u8>, val: &mut Vec<u8>) -> bool {
        if !self.valid() {
            return false;
        }

        if self.skipmapiter.current(key, val) {
            let (keylen, keyoff, _, vallen, valoff) = parse_memtable_key(&key);
            val.clear();
            val.extend_from_slice(&key[valoff..valoff + vallen]);
            // zero-allocation truncation.
            shift_left(key, keyoff);
            // Truncate key to key+tag.
            key.truncate(keylen + u64::required_space());
            true
        } else {
            panic!("should not happen");
        }
    }
    /// seek takes an InternalKey.
    fn seek(&mut self, to: &[u8]) {
        // Assemble the correct memtable key from the supplied InternalKey.
        let (_, seq, ukey) = parse_internal_key(to);
        self.skipmapiter
            .seek(LookupKey::new(ukey, seq).memtable_key());
    }
}

/// shift_left moves s[mid..] to s[0..s.len()-mid]. The new size is s.len()-mid.
fn shift_left(s: &mut Vec<u8>, mid: usize) {
    for i in mid..s.len() {
        s.swap(i, i - mid);
    }
    let newlen = s.len() - mid;
    s.truncate(newlen);
}
