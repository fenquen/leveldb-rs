use crate::key_types::{self, LookupKey};
use crate::types;

use std::cmp::Ordering;
use std::rc::Rc;

type WrappedCmp = Rc<Box<dyn Comparator>>;

pub trait Comparator {
    /// Compare to byte strings, bytewise.
    fn compare(&self, a: &[u8], b: &[u8]) -> Ordering;

    /// Return the shortest byte string that compares "Greater" to the first argument and "Less" to the second one.
    fn find_shortest_sep(&self, from: &[u8], to: &[u8]) -> Vec<u8>;

    /// Return the shortest byte string that compares "Greater" to the argument.
    fn find_short_succ(&self, key: &[u8]) -> Vec<u8>;

    /// A unique identifier for a Comparator. A Comparator wrapper (like InternalKeyCmp) may
    /// return the id of its inner Comparator.
    fn name(&self) -> &'static str;
}

/// The default byte-wise Comparator.
#[derive(Clone)]
pub struct DefaultCmp;

impl Comparator for DefaultCmp {
    fn compare(&self, a: &[u8], b: &[u8]) -> Ordering {
        a.cmp(b)
    }

    fn find_shortest_sep(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        if a == b {
            return a.to_vec();
        }

        let min = if a.len() < b.len() { a.len() } else { b.len() };
        let mut diff_at = 0;

        while diff_at < min && a[diff_at] == b[diff_at] {
            diff_at += 1;
        }

        // First, try to find a short separator. If that fails, try a backup mechanism below.
        while diff_at < min {
            let diff = a[diff_at];
            if diff < 0xff && diff + 1 < b[diff_at] {
                let mut sep = Vec::from(&a[0..diff_at + 1]);
                sep[diff_at] += 1;
                assert!(self.compare(&sep, b) == Ordering::Less);
                return sep;
            }

            diff_at += 1;
        }

        let mut sep = Vec::with_capacity(a.len() + 1);
        sep.extend_from_slice(a);
        // Try increasing a and check if it's still smaller than b. First find the last byte
        // smaller than 0xff, and then increment that byte. Only if the separator is lesser than b,
        // return it.
        let mut i = a.len() - 1;
        while i > 0 && sep[i] == 0xff {
            i -= 1;
        }
        if sep[i] < 0xff {
            sep[i] += 1;
            if self.compare(&sep, b) == Ordering::Less {
                return sep;
            } else {
                sep[i] -= 1;
            }
        }

        // Backup case: either `a` is full of 0xff, or all different places are less than 2
        // characters apart.
        // The result is not necessarily short, but a good separator: e.g., "abc" vs "abd" ->
        // "abc\0", which is greater than abc and lesser than abd.
        // Append a 0 byte; by making it longer than a, it will compare greater to it.
        sep.extend_from_slice(&[0]);
        sep
    }

    fn find_short_succ(&self, a: &[u8]) -> Vec<u8> {
        let mut result = a.to_vec();
        for i in 0..a.len() {
            if a[i] != 0xff {
                result[i] += 1;
                result.resize(i + 1, 0);
                return result;
            }
        }
        // Rare path
        result.push(255);
        result
    }

    fn name(&self) -> &'static str {
        "leveldb.BytewiseComparator"
    }
}

/// Same as memtable_key_cmp, but for InternalKeys.
#[derive(Clone)]
pub struct InternalKeyCmp(pub Rc<Box<dyn Comparator>>);

impl Comparator for InternalKeyCmp {
    fn compare(&self, a: &[u8], b: &[u8]) -> Ordering {
        key_types::cmp_internal_key(self.0.as_ref().as_ref(), a, b)
    }

    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn find_shortest_sep(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        if a == b {
            return a.to_vec();
        }

        let (_, seqa, keya) = key_types::parse_internal_key(a);
        let (_, _, keyb) = key_types::parse_internal_key(b);

        let sep: Vec<u8> = self.0.find_shortest_sep(keya, keyb);

        if sep.len() < keya.len() && self.0.compare(keya, &sep) == Ordering::Less {
            return LookupKey::new(&sep, types::MAX_SEQUENCE_NUMBER)
                .internal_key()
                .to_vec();
        }
        LookupKey::new(&sep, seqa).internal_key().to_vec()
    }

    fn find_short_succ(&self, a: &[u8]) -> Vec<u8> {
        let (_, seq, key) = key_types::parse_internal_key(a);
        let succ: Vec<u8> = self.0.find_short_succ(key);
        LookupKey::new(&succ, seq).internal_key().to_vec()
    }
}

impl InternalKeyCmp {
    /// cmp_inner compares a and b using the underlying Comparator (the "user Comparator").
    pub fn cmp_inner(&self, a: &[u8], b: &[u8]) -> Ordering {
        self.0.compare(a, b)
    }
}

/// An internal Comparator wrapping a user-supplied Comparator. This Comparator is used to compare
/// memtable keys, which contain length prefixes and a sequence number.
/// The ordering is determined by asking the wrapped Comparator; ties are broken by *reverse*
/// ordering the sequence numbers. (This means that when having an entry abx/4 and seRching for
/// abx/5, then abx/4 is counted as "greater-or-equal", making snapshot functionality work at all)
#[derive(Clone)]
pub struct MemtableKeyCmp(pub Rc<Box<dyn Comparator>>);

impl Comparator for MemtableKeyCmp {
    fn compare(&self, a: &[u8], b: &[u8]) -> Ordering {
        key_types::cmp_memtable_key(self.0.as_ref().as_ref(), a, b)
    }

    // The following two impls should not be used (by principle) although they should be correct.
    // They will crash the program.
    fn find_shortest_sep(&self, _: &[u8], _: &[u8]) -> Vec<u8> {
        panic!("find* functions are invalid on MemtableKeyCmp");
    }

    fn find_short_succ(&self, _: &[u8]) -> Vec<u8> {
        panic!("find* functions are invalid on MemtableKeyCmp");
    }

    fn name(&self) -> &'static str {
        self.0.name()
    }
}
