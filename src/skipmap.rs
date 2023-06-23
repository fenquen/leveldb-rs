use crate::cmp::{Comparator, MemtableKeyCmp};
use crate::rand::rngs::StdRng;
use crate::rand::{RngCore, SeedableRng};
use crate::types::LdbIterator;

use std::cell::RefCell;
use std::cmp::Ordering;
use std::mem::{replace, size_of};
use std::rc::Rc;

const MAX_HEIGHT: usize = 12;
const BRANCHING_FACTOR: u32 = 4;

/// A node in a skipmap contains links to the next node and others that are further away (skips);
/// `skips[0]` is the immediate element after, that is, the element contained in `next`.
struct Node {
    skips: Vec<Option<*mut Node>>,
    next: Option<Box<Node>>,
    key: Vec<u8>,
    value: Vec<u8>,
}

/// Implements the backing store for a `MemTable`. The important methods are `insert()` and
/// `contains()`; in order to get full key and value for an entry, use a `SkipMapIter` instance,
/// `seek()` to the key to look up (this is as fast as any lookup in a skip map), and then call
/// `current()`.
struct InnerSkipMap {
    head: Box<Node>,
    rand: StdRng,
    len: usize,
    // approximation of memory used.
    approx_mem: usize,
    cmp: Rc<Box<dyn Comparator>>,
}

impl Drop for InnerSkipMap {
    // Avoid possible stack overflow caused by dropping many nodes.
    fn drop(&mut self) {
        let mut next_node = self.head.next.take();
        while let Some(mut boxed_node) = next_node {
            next_node = boxed_node.next.take();
        }
    }
}

pub struct SkipMap {
    map: Rc<RefCell<InnerSkipMap>>,
}

impl SkipMap {
    /// Returns a SkipMap that wraps the Comparator inside a MemtableKeyCmp.
    pub fn new_memtable_map(cmp: Rc<Box<dyn Comparator>>) -> SkipMap {
        SkipMap::new(Rc::new(Box::new(MemtableKeyCmp(cmp))))
    }

    /// Returns a SkipMap that uses the specified Comparator.
    pub fn new(cmp: Rc<Box<dyn Comparator>>) -> SkipMap {
        let mut s = Vec::new();
        s.resize(MAX_HEIGHT, None);

        SkipMap {
            map: Rc::new(RefCell::new(InnerSkipMap {
                head: Box::new(Node {
                    skips: s,
                    next: None,
                    key: Vec::new(),
                    value: Vec::new(),
                }),
                rand: StdRng::seed_from_u64(0xdeadbeef),
                len: 0,
                approx_mem: size_of::<Self>() + MAX_HEIGHT * size_of::<Option<*mut Node>>(),
                cmp,
            })),
        }
    }

    pub fn len(&self) -> usize {
        self.map.borrow().len
    }
    pub fn approx_memory(&self) -> usize {
        self.map.borrow().approx_mem
    }
    pub fn contains(&self, key: &[u8]) -> bool {
        self.map.borrow().contains(key)
    }

    /// inserts a key into the table. key may not be empty.
    pub fn insert(&mut self, key: Vec<u8>, val: Vec<u8>) {
        assert!(!key.is_empty());
        self.map.borrow_mut().insert(key, val);
    }

    pub fn iter(&self) -> SkipMapIter {
        SkipMapIter {
            map: self.map.clone(),
            current: self.map.borrow().head.as_ref() as *const Node,
        }
    }
}

impl InnerSkipMap {
    fn random_height(&mut self) -> usize {
        let mut height = 1;

        while height < MAX_HEIGHT && self.rand.next_u32() % BRANCHING_FACTOR == 0 {
            height += 1;
        }

        height
    }

    fn contains(&self, key: &[u8]) -> bool {
        if let Some(n) = self.get_greater_or_equal(key) {
            n.key.starts_with(&key)
        } else {
            false
        }
    }

    /// Returns the node with key or the next greater one
    /// Returns None if the given key lies past the greatest key in the table.
    fn get_greater_or_equal<'a>(&'a self, key: &[u8]) -> Option<&'a Node> {
        // Start at the highest skip link of the head node, and work down from there
        let mut current = self.head.as_ref() as *const Node;
        let mut level = self.head.skips.len() - 1;

        loop {
            unsafe {
                if let Some(next) = (*current).skips[level] {
                    let ord = self.cmp.compare((*next).key.as_slice(), key);

                    match ord {
                        Ordering::Less => {
                            current = next;
                            continue;
                        }
                        Ordering::Equal => return Some(&(*next)),
                        Ordering::Greater => {
                            if level == 0 {
                                return Some(&(*next));
                            }
                        }
                    }
                }
            }
            if level == 0 {
                break;
            }
            level -= 1;
        }

        unsafe {
            if current.is_null() || current == self.head.as_ref() {
                None
            } else if self.cmp.compare(&(*current).key, key) == Ordering::Less {
                None
            } else {
                Some(&(*current))
            }
        }
    }

    /// Finds the node immediately before the node with key.
    /// Returns None if no smaller key was found.
    fn get_next_smaller<'a>(&'a self, key: &[u8]) -> Option<&'a Node> {
        // Start at the highest skip link of the head node, and work down from there
        let mut current = self.head.as_ref() as *const Node;
        let mut level = self.head.skips.len() - 1;

        loop {
            unsafe {
                if let Some(next) = (*current).skips[level] {
                    let ord = self.cmp.compare((*next).key.as_slice(), key);

                    match ord {
                        Ordering::Less => {
                            current = next;
                            continue;
                        }
                        _ => (),
                    }
                }
            }
            if level == 0 {
                break;
            }
            level -= 1;
        }

        unsafe {
            if current.is_null() || current == self.head.as_ref() {
                // If we're past the end for some reason or at the head
                None
            } else if self.cmp.compare(&(*current).key, key) != Ordering::Less {
                None
            } else {
                Some(&(*current))
            }
        }
    }

    fn insert(&mut self, key: Vec<u8>, val: Vec<u8>) {
        assert!(!key.is_empty());

        // Keeping track of skip entries that will need to be updated
        let mut prevs: [Option<*mut Node>; MAX_HEIGHT] = [None; MAX_HEIGHT];
        let new_height = self.random_height();
        let prevs = &mut prevs[0..new_height];

        let mut level = MAX_HEIGHT - 1;
        let mut current = self.head.as_mut() as *mut Node;
        // Set previous node for all levels to current node.
        for i in 0..prevs.len() {
            prevs[i] = Some(current);
        }

        // Find the node after which we want to insert the new node; this is the node with the key
        // immediately smaller than the key to be inserted.
        loop {
            unsafe {
                if let Some(next) = (*current).skips[level] {
                    // If the wanted position is after the current node
                    let ord = self.cmp.compare(&(*next).key, &key);

                    assert!(ord != Ordering::Equal, "No duplicates allowed");

                    if ord == Ordering::Less {
                        current = next;
                        continue;
                    }
                }
            }

            if level < new_height {
                prevs[level] = Some(current);
            }

            if level == 0 {
                break;
            } else {
                level -= 1;
            }
        }

        // Construct new node
        let mut new_skips = Vec::new();
        new_skips.resize(new_height, None);
        let mut new = Box::new(Node {
            skips: new_skips,
            next: None,
            key,
            value: val,
        });
        let newp = new.as_mut() as *mut Node;

        for i in 0..new_height {
            if let Some(prev) = prevs[i] {
                unsafe {
                    new.skips[i] = (*prev).skips[i];
                    (*prev).skips[i] = Some(newp);
                }
            }
        }

        let added_mem = size_of::<Node>()
            + size_of::<Option<*mut Node>>() * new.skips.len()
            + new.key.len()
            + new.value.len();
        self.approx_mem += added_mem;
        self.len += 1;

        // Insert new node by first replacing the previous element's next field with None and
        // assigning its value to new.next...
        new.next = unsafe { replace(&mut (*current).next, None) };
        // ...and then setting the previous element's next field to the new node
        unsafe { replace(&mut (*current).next, Some(new)) };
    }
    /// Runs through the skipmap and prints everything including addresses
    fn dbg_print(&self) {
        let mut current = self.head.as_ref() as *const Node;
        loop {
            unsafe {
                eprintln!(
                    "{:?} {:?}/{:?} - {:?}",
                    current,
                    (*current).key,
                    (*current).value,
                    (*current).skips
                );
                if let Some(next) = (*current).skips[0].clone() {
                    current = next;
                } else {
                    break;
                }
            }
        }
    }
}

pub struct SkipMapIter {
    map: Rc<RefCell<InnerSkipMap>>,
    current: *const Node,
}

impl LdbIterator for SkipMapIter {
    fn advance(&mut self) -> bool {
        // we first go to the next element, then return that -- in order to skip the head node
        let r = unsafe {
            (*self.current)
                .next
                .as_ref()
                .map(|next| {
                    self.current = next.as_ref() as *const Node;
                    true
                })
                .unwrap_or(false)
        };
        if !r {
            self.reset();
        }
        r
    }
    fn current(&self, key: &mut Vec<u8>, val: &mut Vec<u8>) -> bool {
        if self.valid() {
            key.clear();
            val.clear();
            unsafe {
                key.extend_from_slice(&(*self.current).key);
                val.extend_from_slice(&(*self.current).value);
            }
            true
        } else {
            false
        }
    }
    fn seek(&mut self, key: &[u8]) {
        if let Some(node) = self.map.borrow().get_greater_or_equal(key) {
            self.current = node as *const Node;
            return;
        }
        self.reset();
    }
    fn reset(&mut self) {
        self.current = self.map.borrow().head.as_ref();
    }
    fn valid(&self) -> bool {
        self.current != self.map.borrow().head.as_ref()
    }
    fn prev(&mut self) -> bool {
        // Going after the original implementation here; we just seek to the node before current().
        if self.valid() {
            if let Some(prev) = self
                .map
                .borrow()
                .get_next_smaller(unsafe { &(*self.current).key })
            {
                self.current = prev as *const Node;
                if !prev.key.is_empty() {
                    return true;
                }
            }
        }
        self.reset();
        false
    }
}