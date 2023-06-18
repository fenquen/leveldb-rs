use crate::block::{Block, BlockIter};
use crate::blockhandle::BlockHandle;
use crate::cache;
use crate::cmp::InternalKeyCmp;
use crate::env::RandomAccess;
use crate::error::{self, err, Result};
use crate::filter;
use crate::filter_block::FilterBlockReader;
use crate::key_types::InternalKey;
use crate::options::Options;
use crate::table_block;
use crate::table_builder::{self, Footer};
use crate::types::{current_key_val, LdbIterator};

use std::cmp::Ordering;
use std::rc::Rc;

use integer_encoding::FixedIntWriter;

/// Reads the table footer.
fn read_footer(f: &dyn RandomAccess, size: usize) -> Result<Footer> {
    let mut buf = vec![0; table_builder::FULL_FOOTER_LENGTH];
    f.read_at(size - table_builder::FULL_FOOTER_LENGTH, &mut buf)?;
    match Footer::decode(&buf) {
        Some(ok) => Ok(ok),
        None => err(
            error::StatusCode::Corruption,
            &format!("Couldn't decode damaged footer {:?}", &buf),
        ),
    }
}

#[derive(Clone)]
pub struct Table {
    file: Rc<Box<dyn RandomAccess>>,
    file_size: usize,
    cache_id: cache::CacheID,

    opt: Options,

    footer: Footer,
    indexblock: Block,
    filters: Option<FilterBlockReader>,
}

impl Table {
    /// Creates a new table reader operating on unformatted keys (i.e., UserKey).
    fn new_raw(opt: Options, file: Rc<Box<dyn RandomAccess>>, size: usize) -> Result<Table> {
        let footer = read_footer(file.as_ref().as_ref(), size)?;
        let indexblock =
            table_block::read_table_block(opt.clone(), file.as_ref().as_ref(), &footer.index)?;
        let metaindexblock =
            table_block::read_table_block(opt.clone(), file.as_ref().as_ref(), &footer.meta_index)?;

        let filter_block_reader =
            Table::read_filter_block(&metaindexblock, file.as_ref().as_ref(), &opt)?;
        let cache_id = opt.block_cache.borrow_mut().new_cache_id();

        Ok(Table {
            file,
            file_size: size,
            cache_id,
            opt,
            footer,
            filters: filter_block_reader,
            indexblock,
        })
    }

    fn read_filter_block(
        metaix: &Block,
        file: &dyn RandomAccess,
        options: &Options,
    ) -> Result<Option<FilterBlockReader>> {
        // Open filter block for reading
        let filter_name = format!("filter.{}", options.filter_policy.name())
            .as_bytes()
            .to_vec();

        let mut metaindexiter = metaix.iter();
        metaindexiter.seek(&filter_name);

        if let Some((_key, val)) = current_key_val(&metaindexiter) {
            let fbl = BlockHandle::decode(&val);
            let filter_block_location = match fbl {
                None => {
                    return err(
                        error::StatusCode::Corruption,
                        &format!("Couldn't decode corrupt blockhandle {:?}", &val),
                    )
                }
                Some(ok) => ok.0,
            };
            if filter_block_location.size() > 0 {
                return Ok(Some(table_block::read_filter_block(
                    file,
                    &filter_block_location,
                    options.filter_policy.clone(),
                )?));
            }
        }
        Ok(None)
    }

    /// Creates a new table reader operating on internal keys (i.e., InternalKey). This means that
    /// a different comparator (internal_key_cmp) and a different filter policy
    /// (InternalFilterPolicy) are used.
    pub fn new(mut opt: Options, file: Rc<Box<dyn RandomAccess>>, size: usize) -> Result<Table> {
        opt.cmp = Rc::new(Box::new(InternalKeyCmp(opt.cmp.clone())));
        opt.filter_policy = Rc::new(Box::new(filter::InternalFilterPolicy::new(
            opt.filter_policy,
        )));
        Table::new_raw(opt, file, size)
    }

    /// block_cache_handle creates a CacheKey for a block with a given offset to be used in the
    /// block cache.
    fn block_cache_handle(&self, block_off: usize) -> cache::CacheKey {
        let mut dst = [0; 2 * 8];
        (&mut dst[..8])
            .write_fixedint(self.cache_id)
            .expect("error writing to vec");
        (&mut dst[8..])
            .write_fixedint(block_off as u64)
            .expect("error writing to vec");
        dst
    }

    /// Read a block from the current table at `location`, and cache it in the options' block
    /// cache.
    fn read_block(&self, location: &BlockHandle) -> Result<Block> {
        let cachekey = self.block_cache_handle(location.offset());
        if let Some(block) = self.opt.block_cache.borrow_mut().get(&cachekey) {
            return Ok(block.clone());
        }

        // Two times as_ref(): First time to get a ref from Rc<>, then one from Box<>.
        let b =
            table_block::read_table_block(self.opt.clone(), self.file.as_ref().as_ref(), location)?;

        // insert a cheap copy (Rc).
        self.opt
            .block_cache
            .borrow_mut()
            .insert(&cachekey, b.clone());

        Ok(b)
    }

    /// Returns the offset of the block that contains `key`.
    pub fn approx_offset_of(&self, key: &[u8]) -> usize {
        let mut iter = self.indexblock.iter();

        iter.seek(key);

        if let Some((_, val)) = current_key_val(&iter) {
            let location = BlockHandle::decode(&val).unwrap().0;
            return location.offset();
        }

        self.footer.meta_index.offset()
    }

    /// Iterators read from the file; thus only one iterator can be borrowed (mutably) per scope
    pub fn iter(&self) -> TableIterator {
        TableIterator {
            current_block: None,
            current_block_off: 0,
            index_block: self.indexblock.iter(),
            table: self.clone(),
        }
    }

    /// Retrieve next-biggest entry for key from table. This function uses the attached filters, so
    /// is better suited if you frequently look for non-existing values (as it will detect the
    /// non-existence of an entry in a block without having to load the block).
    ///
    /// The caller must check if the returned key, which is the raw key (not e.g. the user portion
    /// of an InternalKey) is acceptable (e.g. correct value type or sequence number), as it may
    /// not be an exact match for key.
    ///
    /// This is done this way because some key types, like internal keys, will not result in an
    /// exact match; it depends on other comparators than the one that the table reader knows
    /// whether a match is acceptable.
    pub fn get<'a>(&self, key: InternalKey<'a>) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut index_iter = self.indexblock.iter();
        index_iter.seek(key);

        let handle;
        if let Some((last_in_block, h)) = current_key_val(&index_iter) {
            if self.opt.cmp.cmp(key, &last_in_block) == Ordering::Less {
                handle = BlockHandle::decode(&h).unwrap().0;
            } else {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        // found correct block.

        // Check bloom (or whatever) filter
        if let Some(ref filters) = self.filters {
            if !filters.key_may_match(handle.offset(), key) {
                return Ok(None);
            }
        }

        // Read block (potentially from cache)
        let tb = self.read_block(&handle)?;
        let mut iter = tb.iter();

        // Go to entry and check if it's the wanted entry.
        iter.seek(key);
        if let Some((k, v)) = current_key_val(&iter) {
            if self.opt.cmp.cmp(&k, key) >= Ordering::Equal {
                return Ok(Some((k, v)));
            }
        }
        Ok(None)
    }
}

/// This iterator is a "TwoLevelIterator"; it uses an index block in order to get an offset hint
/// into the data blocks.
pub struct TableIterator {
    // A TableIterator is independent of its table (on the syntax level -- it doesn't know its
    // Table's lifetime). This is mainly required by the dynamic iterators used everywhere, where a
    // lifetime makes things like returning an iterator from a function neigh-impossible.
    //
    // Instead, reference-counted pointers and locks inside the Table ensure that all
    // TableIterators still share a table.
    table: Table,
    current_block: Option<BlockIter>,
    current_block_off: usize,
    index_block: BlockIter,
}

impl TableIterator {
    // Skips to the entry referenced by the next entry in the index block.
    // This is called once a block has run out of entries.
    // Err means corruption or I/O error; Ok(true) means a new block was loaded; Ok(false) means
    // tht there's no more entries.
    fn skip_to_next_entry(&mut self) -> Result<bool> {
        if let Some((_key, val)) = self.index_block.next() {
            self.load_block(&val).map(|_| true)
        } else {
            Ok(false)
        }
    }

    // Load the block at `handle` into `self.current_block`
    fn load_block(&mut self, handle: &[u8]) -> Result<()> {
        let (new_block_handle, _) = match BlockHandle::decode(handle) {
            None => {
                return err(
                    error::StatusCode::Corruption,
                    "Couldn't decode corrupt block handle",
                )
            }
            Some(ok) => ok,
        };
        let block = self.table.read_block(&new_block_handle)?;

        self.current_block = Some(block.iter());
        self.current_block_off = new_block_handle.offset();

        Ok(())
    }
}

impl LdbIterator for TableIterator {
    fn advance(&mut self) -> bool {
        // Uninitialized case.
        if self.current_block.is_none() {
            match self.skip_to_next_entry() {
                Ok(true) => return self.advance(),
                Ok(false) => {
                    self.reset();
                    return false;
                }
                // try next block from index, this might be corruption
                Err(_) => return self.advance(),
            }
        }

        // Initialized case -- does the current block have more entries?
        if let Some(ref mut cb) = self.current_block {
            if cb.advance() {
                return true;
            }
        }

        // If the current block is exhausted, try loading the next block.
        self.current_block = None;
        match self.skip_to_next_entry() {
            Ok(true) => self.advance(),
            Ok(false) => {
                self.reset();
                false
            }
            // try next block, this might be corruption
            Err(_) => self.advance(),
        }
    }

    // A call to valid() after seeking is necessary to ensure that the seek worked (e.g., no error
    // while reading from disk)
    fn seek(&mut self, to: &[u8]) {
        // first seek in index block, rewind by one entry (so we get the next smaller index entry),
        // then set current_block and seek there
        self.index_block.seek(to);

        // It's possible that this is a seek past-last; reset in that case.
        if let Some((past_block, handle)) = current_key_val(&self.index_block) {
            if self.table.opt.cmp.cmp(to, &past_block) <= Ordering::Equal {
                // ok, found right block: continue
                if let Ok(()) = self.load_block(&handle) {
                    // current_block is always set if load_block() returned Ok.
                    self.current_block.as_mut().unwrap().seek(to);
                    return;
                }
            }
        }
        // Reached in case of failure.
        self.reset();
    }

    fn prev(&mut self) -> bool {
        // happy path: current block contains previous entry
        if let Some(ref mut cb) = self.current_block {
            if cb.prev() {
                return true;
            }
        }

        // Go back one block and look for the last entry in the previous block
        if self.index_block.prev() {
            if let Some((_, handle)) = current_key_val(&self.index_block) {
                if self.load_block(&handle).is_ok() {
                    self.current_block.as_mut().unwrap().seek_to_last();
                    self.current_block.as_ref().unwrap().valid()
                } else {
                    self.reset();
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    fn reset(&mut self) {
        self.index_block.reset();
        self.current_block = None;
    }

    // This iterator is special in that it's valid even before the first call to advance(). It
    // behaves correctly, though.
    fn valid(&self) -> bool {
        self.current_block.is_some() && (self.current_block.as_ref().unwrap().valid())
    }

    fn current(&self, key: &mut Vec<u8>, val: &mut Vec<u8>) -> bool {
        if let Some(ref cb) = self.current_block {
            cb.current(key, val)
        } else {
            false
        }
    }
}