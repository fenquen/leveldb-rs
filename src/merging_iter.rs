use crate::cmp::Comparator;
use crate::types::{current_key_val, Direction, LdbIterator};

use std::cmp::Ordering;
use std::rc::Rc;

// Warning: This module is kinda messy. The original implementation is
// not that much better though :-)
//
// Issues: 1) prev() may not work correctly at the beginning of a merging
// iterator.

#[derive(PartialEq)]
enum SL {
    Smallest,
    Largest,
}

pub struct MergingIter {
    iters: Vec<Box<dyn LdbIterator>>,
    current: Option<usize>,
    direction: Direction,
    cmp: Rc<Box<dyn Comparator>>,
}

impl MergingIter {
    /// Construct a new merging iterator.
    pub fn new(cmp: Rc<Box<dyn Comparator>>, iters: Vec<Box<dyn LdbIterator>>) -> MergingIter {
        MergingIter {
            iters,
            current: None,
            direction: Direction::Forward,
            cmp,
        }
    }

    fn init(&mut self) {
        for i in 0..self.iters.len() {
            self.iters[i].reset();
            self.iters[i].advance();
            if !self.iters[i].valid() {
                self.iters[i].reset()
            }
        }
        self.find_smallest();
    }

    /// Adjusts the direction of the iterator depending on whether the last
    /// call was next() or prev(). This basically sets all iterators to one
    /// entry after (Forward) or one entry before (Reverse) the current() entry.
    fn update_direction(&mut self, d: Direction) {
        if self.direction == d {
            return;
        }

        let mut keybuf = vec![];
        let mut valbuf = vec![];

        if let Some((key, _)) = current_key_val(self) {
            if let Some(current) = self.current {
                match d {
                    Direction::Forward if self.direction == Direction::Reverse => {
                        self.direction = Direction::Forward;
                        for i in 0..self.iters.len() {
                            if i != current {
                                self.iters[i].seek(&key);
                                // This doesn't work if two iterators are returning the exact same
                                // keys. However, in reality, two entries will always have differing
                                // sequence numbers.
                                if self.iters[i].current(&mut keybuf, &mut valbuf)
                                    && self.cmp.compare(&keybuf, &key) == Ordering::Equal
                                {
                                    self.iters[i].advance();
                                }
                            }
                        }
                    }
                    Direction::Reverse if self.direction == Direction::Forward => {
                        self.direction = Direction::Reverse;
                        for i in 0..self.iters.len() {
                            if i != current {
                                self.iters[i].seek(&key);
                                if self.iters[i].valid() {
                                    self.iters[i].prev();
                                } else {
                                    // seek to last.
                                    while self.iters[i].advance() {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn find_smallest(&mut self) {
        self.find(SL::Smallest)
    }
    fn find_largest(&mut self) {
        self.find(SL::Largest)
    }

    fn find(&mut self, direction: SL) {
        if self.iters.len() == 0 {
            // Iterator stays invalid.
            return;
        }

        let ord;

        if direction == SL::Smallest {
            ord = Ordering::Less;
        } else {
            ord = Ordering::Greater;
        }

        let mut next_ix = 0;
        let (mut current, mut smallest, mut valscratch) = (vec![], vec![], vec![]);

        for i in 1..self.iters.len() {
            if self.iters[i].current(&mut current, &mut valscratch) {
                if self.iters[next_ix].current(&mut smallest, &mut valscratch) {
                    if self.cmp.compare(&current, &smallest) == ord {
                        next_ix = i;
                    }
                } else {
                    next_ix = i;
                }
            }
        }

        self.current = Some(next_ix);
    }
}

impl LdbIterator for MergingIter {
    fn advance(&mut self) -> bool {
        if let Some(current) = self.current {
            self.update_direction(Direction::Forward);
            if !self.iters[current].advance() {
                // Take this iterator out of rotation; this will return false
                // for every call to current() and thus it will be ignored
                // from here on.
                self.iters[current].reset();
            }
            self.find_smallest();
        } else {
            self.init();
        }
        self.valid()
    }
    fn valid(&self) -> bool {
        if let Some(ix) = self.current {
            self.iters[ix].valid()
        } else {
            false
        }
    }
    fn seek(&mut self, key: &[u8]) {
        for i in 0..self.iters.len() {
            self.iters[i].seek(key);
        }
        self.find_smallest();
    }
    fn reset(&mut self) {
        for i in 0..self.iters.len() {
            self.iters[i].reset();
        }
        self.current = None;
    }
    fn current(&self, key: &mut Vec<u8>, val: &mut Vec<u8>) -> bool {
        if let Some(ix) = self.current {
            self.iters[ix].current(key, val)
        } else {
            false
        }
    }
    fn prev(&mut self) -> bool {
        if let Some(current) = self.current {
            if self.iters[current].valid() {
                self.update_direction(Direction::Reverse);
                self.iters[current].prev();
                self.find_largest();
                self.valid()
            } else {
                false
            }
        } else {
            false
        }
    }
}