//! db_impl contains the implementation of the database interface and high-level compaction and
//! maintenance logic.

#![allow(unused_attributes)]

use crate::db_iter::DBIterator;

use crate::cmp::{Cmp, InternalKeyCmp};
use crate::env::{Env, FileLock};
use crate::error::{err, Result, StatusCode};
use crate::filter::{BoxedFilterPolicy, InternalFilterPolicy};
use crate::infolog::Logger;
use crate::key_types::{parse_internal_key, InternalKey, LookupKey, ValueType};
use crate::log::{LogReader, LogWriter};
use crate::memtable::MemTable;
use crate::merging_iter::MergingIter;
use crate::options::Options;
use crate::snapshot::{Snapshot, SnapshotList};
use crate::table_builder::TableBuilder;
use crate::table_cache::{table_file_name, TableCache};
use crate::types::{
    parse_file_name, share, FileMetaData, FileNum, FileType, LdbIterator, SequenceNumber, Shared,
    MAX_SEQUENCE_NUMBER, NUM_LEVELS,
};
use crate::version::Version;
use crate::version_edit::VersionEdit;
use crate::version_set::{
    manifest_file_name, readCurrentFile, set_current_file, Compaction, VersionSet,
};
use crate::write_batch::WriteBatch;

use std::cmp::Ordering;
use std::io::{self, BufWriter, Write};
use std::mem;
use std::ops::Drop;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

/// DB contains the actual database implementation.
/// As opposed to the original, this implementation is not concurrent (yet).
pub struct DB {
    /// 数据目录的路径(不管是是绝对还是相对) 也可以说成是db的name
    name: PathBuf,
    /// 数据目录的绝对路径
    path: PathBuf,

    lock: Option<FileLock>,

    internal_cmp: Rc<Box<dyn Cmp>>,
    fpol: InternalFilterPolicy<BoxedFilterPolicy>,
    options: Options,

    memTable: MemTable,
    immutableMemTable: Option<MemTable>,

    log: Option<LogWriter<BufWriter<Box<dyn Write>>>>,
    log_num: Option<FileNum>,
    tableCache: Shared<TableCache>,
    versionSet: Shared<VersionSet>,
    snaps: SnapshotList,

    compactionStatsArr: [CompactionStats; NUM_LEVELS],
}

unsafe impl Send for DB {}

impl DB {
    // RECOVERY AND INITIALIZATION //

    /// new initializes a new DB object, but doesn't touch disk.
    fn new<P: AsRef<Path>>(dbName: P, mut options: Options) -> DB {
        let name = dbName.as_ref();

        if options.log.is_none() {
            let log = open_info_log(options.env.as_ref().as_ref(), name);
            options.log = Some(share(log));
        }

        let path = name.canonicalize().unwrap_or(name.to_owned());

        let tableCache = share(TableCache::new(&name, options.clone(), options.max_open_files - 10));
        let versionSet = VersionSet::new(&name, options.clone(), tableCache.clone());

        DB {
            name: name.to_owned(),
            path,
            lock: None,
            internal_cmp: Rc::new(Box::new(InternalKeyCmp(options.cmp.clone()))),
            fpol: InternalFilterPolicy::new(options.filter_policy.clone()),

            memTable: MemTable::new(options.cmp.clone()),
            immutableMemTable: None,

            options,

            log: None,
            log_num: None,
            tableCache,
            versionSet: share(versionSet),
            snaps: SnapshotList::new(),

            compactionStatsArr: Default::default(),
        }
    }

    fn current(&self) -> Shared<Version> {
        self.versionSet.borrow().current()
    }

    /// Opens or creates a new or existing database. `name` is the name of the directory containing the database.
    ///
    /// Whether a new database is created and what happens if a database exists at the given path
    /// depends on the options set (`create_if_missing`, `error_if_exists`).
    pub fn open<P: AsRef<Path>>(name: P, options: Options) -> Result<DB> {
        let name = name.as_ref();
        let mut db = DB::new(name, options);
        let mut versionEdit = VersionEdit::new();
        let saveManifest = db.recover(&mut versionEdit)?;

        // Create log file if an old one is not being reused.
        if db.log.is_none() {
            let lognum = db.versionSet.borrow_mut().new_file_number();
            let logfile = db.options.env.open_writable_file(Path::new(&getLogFilePath(&db.name, lognum)))?;
            versionEdit.set_log_num(lognum);
            db.log = Some(LogWriter::new(BufWriter::new(logfile)));
            db.log_num = Some(lognum);
        }

        if saveManifest {
            versionEdit.set_log_num(db.log_num.unwrap_or(0));
            db.versionSet.borrow_mut().log_and_apply(versionEdit)?;
        }

        db.delete_obsolete_files()?;
        db.maybe_do_compaction()?;
        Ok(db)
    }

    /// initialize_db initializes a new database.
    fn initialize_db(&mut self) -> Result<()> {
        let mut ve = VersionEdit::new();
        ve.set_comparator_name(self.options.cmp.id());
        ve.set_log_num(0);
        ve.set_next_file(2);
        ve.set_last_seq(0);

        {
            let manifest = manifest_file_name(&self.path, 1);
            let manifest_file = self.options.env.open_writable_file(Path::new(&manifest))?;
            let mut lw = LogWriter::new(manifest_file);
            lw.add_record(&ve.encode())?;
            lw.flush()?;
        }
        set_current_file(&self.options.env, &self.path, 1)
    }

    /// recover recovers from the existing state on disk. If the wrapped result is `true`, then
    /// log_and_apply() should be called after recovery has finished.
    fn recover(&mut self, versionEdit: &mut VersionEdit) -> Result<bool> {
        if self.options.errorIfExists && self.options.env.exists(&self.path.as_ref()).unwrap_or(false) {
            return err(StatusCode::AlreadyExists, "database already exists");
        }

        let _ = self.options.env.mkdir(Path::new(&self.path));

        self.acquire_lock()?;

        if let Err(e) = readCurrentFile(&self.options.env, &self.path) {
            if e.code == StatusCode::NotFound && self.options.createIfMissing {
                self.initialize_db()?;
            } else {
                return err(StatusCode::InvalidArgument, "database does not exist and create_if_missing is false");
            }
        }

        // If save_manifest is true, we should log_and_apply() later in order to write the new manifest.
        let mut save_manifest = self.versionSet.borrow_mut().recover()?;

        // Recover from all log files not in the descriptor.
        let mut max_seq = 0;
        let filenames = self.options.env.children(&self.path)?;
        let mut expected = self.versionSet.borrow().live_files();
        let mut log_files = vec![];

        for file in &filenames {
            match parse_file_name(&file) {
                Ok((num, typ)) => {
                    expected.remove(&num);
                    if typ == FileType::Log
                        && (num >= self.versionSet.borrow().log_num
                        || num == self.versionSet.borrow().prev_log_num)
                    {
                        log_files.push(num);
                    }
                }
                Err(e) => return Err(e.annotate(format!("While parsing {:?}", file))),
            }
        }

        if !expected.is_empty() {
            log!(self.options.log, "Missing at least these files: {:?}", expected);
            return err(StatusCode::Corruption, "missing live files (see log)");
        }

        log_files.sort();

        for i in 0..log_files.len() {
            let (save_manifest_, max_seq_) =
                self.recover_log_file(log_files[i], i == log_files.len() - 1, versionEdit)?;
            if save_manifest_ {
                save_manifest = true;
            }
            if max_seq_ > max_seq {
                max_seq = max_seq_;
            }
            self.versionSet.borrow_mut().mark_file_number_used(log_files[i]);
        }

        if self.versionSet.borrow().last_seq < max_seq {
            self.versionSet.borrow_mut().last_seq = max_seq;
        }

        Ok(save_manifest)
    }

    /// recover_log_file reads a single log file into a memtable, writing new L0 tables if
    /// necessary. If is_last is true, it checks whether the log file can be reused, and sets up
    /// the database's logging handles appropriately if that's the case.
    fn recover_log_file(
        &mut self,
        log_num: FileNum,
        is_last: bool,
        ve: &mut VersionEdit,
    ) -> Result<(bool, SequenceNumber)> {
        let filename = getLogFilePath(&self.path, log_num);
        let logfile = self.options.env.open_sequential_file(Path::new(&filename))?;
        // Use the user-supplied comparator; it will be wrapped inside a MemtableKeyCmp.
        let cmp: Rc<Box<dyn Cmp>> = self.options.cmp.clone();

        let mut logreader = LogReader::new(
            logfile, // checksum=
            true,
        );
        log!(self.options.log, "Recovering log file {:?}", filename);
        let mut scratch = vec![];
        let mut mem = MemTable::new(cmp.clone());
        let mut batch = WriteBatch::new();

        let mut compactions = 0;
        let mut max_seq = 0;
        let mut save_manifest = false;

        while let Ok(len) = logreader.read(&mut scratch) {
            if len == 0 {
                break;
            }
            if len < 12 {
                log!(
                    self.options.log,
                    "corruption in log file {:06}: record shorter than 12B",
                    log_num
                );
                continue;
            }

            batch.set_contents(&scratch);
            batch.insert_into_memtable(batch.sequence(), &mut mem);

            let last_seq = batch.sequence() + batch.count() as u64 - 1;
            if last_seq > max_seq {
                max_seq = last_seq
            }
            if mem.approx_mem_usage() > self.options.write_buffer_size {
                compactions += 1;
                self.write_l0_table(&mem, ve, None)?;
                save_manifest = true;
                mem = MemTable::new(cmp.clone());
            }
            batch.clear();
        }

        // Check if we can reuse the last log file.
        if self.options.reuse_logs && is_last && compactions == 0 {
            assert!(self.log.is_none());
            log!(self.options.log, "reusing log file {:?}", filename);
            let oldsize = self.options.env.size_of(Path::new(&filename))?;
            let oldfile = self.options.env.open_appendable_file(Path::new(&filename))?;
            let lw = LogWriter::new_with_off(BufWriter::new(oldfile), oldsize);
            self.log = Some(lw);
            self.log_num = Some(log_num);
            self.memTable = mem;
        } else if mem.len() > 0 {
            // Log is not reused, so write out the accumulated memtable.
            save_manifest = true;
            self.write_l0_table(&mem, ve, None)?;
        }

        Ok((save_manifest, max_seq))
    }

    /// delete_obsolete_files removes files that are no longer needed from the file system.
    fn delete_obsolete_files(&mut self) -> Result<()> {
        let files = self.versionSet.borrow().live_files();
        let filenames = self.options.env.children(Path::new(&self.path))?;
        for name in filenames {
            if let Ok((num, typ)) = parse_file_name(&name) {
                match typ {
                    FileType::Log => {
                        if num >= self.versionSet.borrow().log_num {
                            continue;
                        }
                    }
                    FileType::Descriptor => {
                        if num >= self.versionSet.borrow().manifest_num {
                            continue;
                        }
                    }
                    FileType::Table => {
                        if files.contains(&num) {
                            continue;
                        }
                    }
                    // NOTE: In this non-concurrent implementation, we likely never find temp
                    // files.
                    FileType::Temp => {
                        if files.contains(&num) {
                            continue;
                        }
                    }
                    FileType::Current | FileType::DBLock | FileType::InfoLog => continue,
                }

                // If we're here, delete this file.
                if typ == FileType::Table {
                    let _ = self.tableCache.borrow_mut().evict(num);
                }
                log!(self.options.log, "Deleting file type={:?} num={}", typ, num);
                if let Err(e) = self.options.env.delete(&self.path.join(&name)) {
                    log!(self.options.log, "Deleting file num={} failed: {}", num, e);
                }
            }
        }
        Ok(())
    }

    fn acquire_lock(&mut self) -> Result<()> {
        match self.options.env.lock(Path::new(&getLockFilePath(&self.path))) {
            Ok(lockfile) => {
                self.lock = Some(lockfile);
                Ok(())
            }
            Err(ref e)if e.code == StatusCode::LockError =>
                err(StatusCode::LockError, "database lock is held by another instance"),
            Err(e) => Err(e),
        }
    }

    /// release_lock releases the lock file, if it's currently held.
    fn release_lock(&mut self) -> Result<()> {
        if let Some(l) = self.lock.take() {
            self.options.env.unlock(l)
        } else {
            Ok(())
        }
    }

    /// Flush data to disk and release lock.
    pub fn close(&mut self) -> Result<()> {
        self.flush()?;
        self.release_lock()?;
        Ok(())
    }
}

impl DB {
    // WRITE //

    /// Adds a single entry. It's a short, non-synchronous, form of `write()`; in order to make
    /// sure that the written entry is on disk, call `flush()` afterwards.
    pub fn put(&mut self, k: &[u8], v: &[u8]) -> Result<()> {
        let mut wb = WriteBatch::new();
        wb.put(k, v);
        self.write(wb, false)
    }

    /// Deletes a single entry. Like with `put()`, you can call `flush()` to guarantee that
    /// the operation made it to disk.
    pub fn delete(&mut self, k: &[u8]) -> Result<()> {
        let mut wb = WriteBatch::new();
        wb.delete(k);
        self.write(wb, false)
    }

    /// Writes an entire WriteBatch. `sync` determines whether the write should be flushed to
    /// disk.
    pub fn write(&mut self, batch: WriteBatch, sync: bool) -> Result<()> {
        assert!(self.log.is_some());

        self.make_room_for_write(false)?;

        let entries = batch.count() as u64;
        let log = self.log.as_mut().unwrap();
        let next = self.versionSet.borrow().last_seq + 1;

        batch.insert_into_memtable(next, &mut self.memTable);
        log.add_record(&batch.encode(next))?;
        if sync {
            log.flush()?;
        }
        self.versionSet.borrow_mut().last_seq += entries;
        Ok(())
    }

    /// flush makes sure that all pending changes (e.g. from put()) are stored on disk.
    pub fn flush(&mut self) -> Result<()> {
        assert!(self.log.is_some());
        self.log.as_mut().unwrap().flush()
    }
}

impl DB {
    // READ //

    fn get_internal(&mut self, seq: SequenceNumber, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Using this lookup key will skip all entries with higher sequence numbers, because they
        // will compare "Lesser" using the InternalKeyCmp
        let lkey = LookupKey::new(key, seq);

        match self.memTable.get(&lkey) {
            (Some(v), _) => return Ok(Some(v)),
            // deleted entry
            (None, true) => return Ok(None),
            // not found entry
            (None, false) => {}
        }

        if let Some(imm) = self.immutableMemTable.as_ref() {
            match imm.get(&lkey) {
                (Some(v), _) => return Ok(Some(v)),
                // deleted entry
                (None, true) => return Ok(None),
                // not found entry
                (None, false) => {}
            }
        }

        let mut do_compaction = false;
        let mut result = None;

        // Limiting the borrow scope of self.current.
        {
            let current = self.current();
            let mut current = current.borrow_mut();
            if let Ok(Some((v, st))) = current.get(lkey.internal_key()) {
                if current.update_stats(st) {
                    do_compaction = true;
                }
                result = Some(v)
            }
        }

        if do_compaction {
            if let Err(e) = self.maybe_do_compaction() {
                log!(self.options.log, "error while doing compaction in get: {}", e);
            }
        }
        Ok(result)
    }

    /// get_at reads the value for a given key at or before snapshot. It returns Ok(None) if the
    /// entry wasn't found, and Err(_) if an error occurred.
    pub fn get_at(&mut self, snapshot: &Snapshot, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_internal(snapshot.sequence(), key)
    }

    /// get is a simplified version of get_at(), translating errors to None.
    pub fn get(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let seq = self.versionSet.borrow().last_seq;
        if let Ok(v) = self.get_internal(seq, key) {
            v
        } else {
            None
        }
    }
}

impl DB {
    // ITERATOR //

    /// new_iter returns a DBIterator over the current state of the database. The iterator will not
    /// return elements added to the database after its creation.
    pub fn new_iter(&mut self) -> Result<DBIterator> {
        let snapshot = self.get_snapshot();
        self.new_iter_at(snapshot)
    }

    /// new_iter_at returns a DBIterator at the supplied snapshot.
    pub fn new_iter_at(&mut self, ss: Snapshot) -> Result<DBIterator> {
        Ok(DBIterator::new(
            self.options.cmp.clone(),
            self.versionSet.clone(),
            self.merge_iterators()?,
            ss,
        ))
    }

    /// merge_iterators produces a MergingIter merging the entries in the memtable, the immutable
    /// memtable, and table files from all levels.
    fn merge_iterators(&mut self) -> Result<MergingIter> {
        let mut iters: Vec<Box<dyn LdbIterator>> = vec![];
        if self.memTable.len() > 0 {
            iters.push(Box::new(self.memTable.iter()));
        }
        if let Some(ref imm) = self.immutableMemTable {
            if imm.len() > 0 {
                iters.push(Box::new(imm.iter()));
            }
        }

        // Add iterators for table files.
        let current = self.current();
        let current = current.borrow();
        iters.extend(current.new_iters()?);

        Ok(MergingIter::new(self.internal_cmp.clone(), iters))
    }
}

impl DB {
    // SNAPSHOTS //

    /// Returns a snapshot at the current state. It can be used to retrieve entries from the
    /// database as they were at an earlier point in time.
    pub fn get_snapshot(&mut self) -> Snapshot {
        self.snaps.new_snapshot(self.versionSet.borrow().last_seq)
    }
}

impl DB {
    // STATISTICS //
    fn add_stats(&mut self, level: usize, cs: CompactionStats) {
        assert!(level < NUM_LEVELS);
        self.compactionStatsArr[level].add(cs);
    }

    /// Trigger a compaction based on where this key is located in the different levels.
    fn record_read_sample<'a>(&mut self, k: InternalKey<'a>) {
        let current = self.current();
        if current.borrow_mut().record_read_sample(k) {
            if let Err(e) = self.maybe_do_compaction() {
                log!(self.options.log, "record_read_sample: compaction failed: {}", e);
            }
        }
    }
}

impl DB {
    // COMPACTIONS //

    /// make_room_for_write checks if the memtable has become too large, and triggers a compaction
    /// if it's the case.
    fn make_room_for_write(&mut self, force: bool) -> Result<()> {
        if !force && self.memTable.approx_mem_usage() < self.options.write_buffer_size {
            Ok(())
        } else if self.memTable.len() == 0 {
            Ok(())
        } else {
            // Create new memtable.
            let logn = self.versionSet.borrow_mut().new_file_number();
            let logf = self
                .options
                .env
                .open_writable_file(Path::new(&getLogFilePath(&self.path, logn)));
            if logf.is_err() {
                self.versionSet.borrow_mut().reuse_file_number(logn);
                Err(logf.err().unwrap())
            } else {
                self.log = Some(LogWriter::new(BufWriter::new(logf.unwrap())));
                self.log_num = Some(logn);

                let mut imm = MemTable::new(self.options.cmp.clone());
                mem::swap(&mut imm, &mut self.memTable);
                self.immutableMemTable = Some(imm);
                self.maybe_do_compaction()
            }
        }
    }

    /// maybe_do_compaction starts a blocking compaction if it makes sense.
    fn maybe_do_compaction(&mut self) -> Result<()> {
        if self.immutableMemTable.is_some() {
            self.compact_memtable()
        } else if self.versionSet.borrow().needs_compaction() {
            let c = self.versionSet.borrow_mut().pick_compaction();
            if let Some(c) = c {
                self.start_compaction(c)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    /// compact_range triggers an immediate compaction on the specified key range. Repeatedly
    /// calling this without actually adding new keys is not useful.
    ///
    /// Compactions in general will cause the database to find entries more quickly, and take up
    /// less space on disk.
    pub fn compact_range(&mut self, from: &[u8], to: &[u8]) -> Result<()> {
        let mut max_level = 1;
        {
            let v = self.versionSet.borrow().current();
            let v = v.borrow();
            for l in 1..NUM_LEVELS - 1 {
                if v.overlap_in_level(l, from, to) {
                    max_level = l;
                }
            }
        }

        // Compact memtable.
        self.make_room_for_write(true)?;

        let mut ifrom = LookupKey::new(from, MAX_SEQUENCE_NUMBER)
            .internal_key()
            .to_vec();
        let iend = LookupKey::new_full(to, 0, ValueType::TypeDeletion);

        for l in 0..max_level + 1 {
            loop {
                let c_ = self
                    .versionSet
                    .borrow_mut()
                    .compact_range(l, &ifrom, iend.internal_key());
                if let Some(c) = c_ {
                    // Update ifrom to the largest key of the last file in this compaction.
                    let ix = c.num_inputs(0) - 1;
                    ifrom = c.input(0, ix).largest.clone();
                    self.start_compaction(c)?;
                } else {
                    break;
                }
            }
        }
        Ok(())
    }

    /// start_compaction dispatches the different kinds of compactions depending on the current
    /// state of the database.
    fn start_compaction(&mut self, mut compaction: Compaction) -> Result<()> {
        if compaction.is_trivial_move() {
            assert_eq!(1, compaction.num_inputs(0));
            let f = compaction.input(0, 0);
            let num = f.num;
            let size = f.size;
            let level = compaction.level();

            compaction.edit().delete_file(level, num);
            compaction.edit().add_file(level + 1, f);

            let r = self.versionSet.borrow_mut().log_and_apply(compaction.into_edit());
            if let Err(e) = r {
                log!(self.options.log, "trivial move failed: {}", e);
                Err(e)
            } else {
                log!(
                    self.options.log,
                    "Moved num={} bytes={} from L{} to L{}",
                    num,
                    size,
                    level,
                    level + 1
                );
                log!(
                    self.options.log,
                    "Summary: {}",
                    self.versionSet.borrow().current_summary()
                );
                Ok(())
            }
        } else {
            let smallest = if self.snaps.empty() {
                self.versionSet.borrow().last_seq
            } else {
                self.snaps.oldest()
            };
            let mut state = CompactionState::new(compaction, smallest);
            if let Err(e) = self.do_compaction_work(&mut state) {
                state.cleanup(&self.options.env, &self.path);
                log!(self.options.log, "Compaction work failed: {}", e);
            }
            self.install_compaction_results(state)?;
            log!(
                self.options.log,
                "Compaction finished: {}",
                self.versionSet.borrow().current_summary()
            );

            self.delete_obsolete_files()
        }
    }

    fn compact_memtable(&mut self) -> Result<()> {
        assert!(self.immutableMemTable.is_some());

        let mut ve = VersionEdit::new();
        let base = self.current();

        let imm = self.immutableMemTable.take().unwrap();
        if let Err(e) = self.write_l0_table(&imm, &mut ve, Some(&base.borrow())) {
            self.immutableMemTable = Some(imm);
            return Err(e);
        }
        ve.set_log_num(self.log_num.unwrap_or(0));
        self.versionSet.borrow_mut().log_and_apply(ve)?;
        if let Err(e) = self.delete_obsolete_files() {
            log!(self.options.log, "Error deleting obsolete files: {}", e);
        }
        Ok(())
    }

    /// write_l0_table writes the given memtable to a table file.
    fn write_l0_table(
        &mut self,
        memt: &MemTable,
        ve: &mut VersionEdit,
        base: Option<&Version>,
    ) -> Result<()> {
        let start_ts = self.options.env.micros();
        let num = self.versionSet.borrow_mut().new_file_number();
        log!(self.options.log, "Start write of L0 table {:06}", num);
        let fmd = build_table(&self.path, &self.options, memt.iter(), num)?;
        log!(self.options.log, "L0 table {:06} has {} bytes", num, fmd.size);

        // Wrote empty table.
        if fmd.size == 0 {
            self.versionSet.borrow_mut().reuse_file_number(num);
            return Ok(());
        }

        let cache_result = self.tableCache.borrow_mut().get_table(num);
        if let Err(e) = cache_result {
            log!(
                self.options.log,
                "L0 table {:06} not returned by cache: {}",
                num,
                e
            );
            let _ = self
                .options
                .env
                .delete(Path::new(&table_file_name(&self.path, num)));
            return Err(e);
        }

        let mut stats = CompactionStats::default();
        stats.micros = self.options.env.micros() - start_ts;
        stats.written = fmd.size;

        let mut level = 0;
        if let Some(b) = base {
            level = b.pick_memtable_output_level(
                parse_internal_key(&fmd.smallest).2,
                parse_internal_key(&fmd.largest).2,
            );
        }

        self.add_stats(level, stats);
        ve.add_file(level, fmd);

        Ok(())
    }

    fn do_compaction_work(&mut self, cs: &mut CompactionState) -> Result<()> {
        {
            let current = self.versionSet.borrow().current();
            assert!(current.borrow().num_level_files(cs.compaction.level()) > 0);
            assert!(cs.builder.is_none());
        }
        let start_ts = self.options.env.micros();
        log!(
            self.options.log,
            "Compacting {} files at L{} and {} files at L{}",
            cs.compaction.num_inputs(0),
            cs.compaction.level(),
            cs.compaction.num_inputs(1),
            cs.compaction.level() + 1
        );

        let mut input = self.versionSet.borrow().make_input_iterator(&cs.compaction);
        input.seek_to_first();

        let (mut key, mut val) = (vec![], vec![]);
        let mut last_seq_for_key = MAX_SEQUENCE_NUMBER;

        let mut have_ukey = false;
        let mut current_ukey = vec![];

        while input.valid() {
            // TODO: Do we need to do a memtable compaction here? Probably not, in the sequential
            // case.
            assert!(input.current(&mut key, &mut val));
            if cs.compaction.should_stop_before(&key) && cs.builder.is_some() {
                self.finish_compaction_output(cs, key.clone())?;
            }
            let (ktyp, seq, ukey) = parse_internal_key(&key);
            if seq == 0 {
                // Parsing failed.
                log!(self.options.log, "Encountered seq=0 in key: {:?}", &key);
                last_seq_for_key = MAX_SEQUENCE_NUMBER;
                have_ukey = false;
                current_ukey.clear();
                input.advance();
                continue;
            }

            if !have_ukey || self.options.cmp.cmp(ukey, &current_ukey) != Ordering::Equal {
                // First occurrence of this key.
                current_ukey.clear();
                current_ukey.extend_from_slice(ukey);
                have_ukey = true;
                last_seq_for_key = MAX_SEQUENCE_NUMBER;
            }

            // We can omit the key under the following conditions:
            if last_seq_for_key <= cs.smallest_seq {
                last_seq_for_key = seq;
                input.advance();
                continue;
            }
            // Entry is deletion; no older version is observable by any snapshot; and all entries
            // in compacted levels with smaller sequence numbers will
            if ktyp == ValueType::TypeDeletion
                && seq <= cs.smallest_seq
                && cs.compaction.is_base_level_for(ukey)
            {
                last_seq_for_key = seq;
                input.advance();
                continue;
            }

            last_seq_for_key = seq;

            if cs.builder.is_none() {
                let fnum = self.versionSet.borrow_mut().new_file_number();
                let mut fmd = FileMetaData::default();
                fmd.num = fnum;

                let fname = table_file_name(&self.path, fnum);
                let f = self.options.env.open_writable_file(Path::new(&fname))?;
                let f = Box::new(BufWriter::new(f));
                cs.builder = Some(TableBuilder::new(self.options.clone(), f));
                cs.outputs.push(fmd);
            }
            if cs.builder.as_ref().unwrap().entries() == 0 {
                cs.current_output().smallest = key.clone();
            }
            cs.builder.as_mut().unwrap().add(&key, &val)?;
            // NOTE: Adjust max file size based on level.
            if cs.builder.as_ref().unwrap().size_estimate() > self.options.max_file_size {
                self.finish_compaction_output(cs, key.clone())?;
            }

            input.advance();
        }

        if cs.builder.is_some() {
            self.finish_compaction_output(cs, key)?;
        }

        let mut stats = CompactionStats::default();
        stats.micros = self.options.env.micros() - start_ts;
        for parent in 0..2 {
            for inp in 0..cs.compaction.num_inputs(parent) {
                stats.read += cs.compaction.input(parent, inp).size;
            }
        }
        for output in &cs.outputs {
            stats.written += output.size;
        }
        self.compactionStatsArr[cs.compaction.level()].add(stats);
        Ok(())
    }

    fn finish_compaction_output(
        &mut self,
        cs: &mut CompactionState,
        largest: Vec<u8>,
    ) -> Result<()> {
        assert!(cs.builder.is_some());
        let output_num = cs.current_output().num;
        assert!(output_num > 0);

        // The original checks if the input iterator has an OK status. For this, we'd need to
        // extend the LdbIterator interface though -- let's see if we can without for now.
        // (it's not good for corruptions, in any case)
        let b = cs.builder.take().unwrap();
        let entries = b.entries();
        let bytes = b.finish()?;
        cs.total_bytes += bytes;

        cs.current_output().largest = largest;
        cs.current_output().size = bytes;

        if entries > 0 {
            // Verify that table can be used. (Separating get_table() because borrowing in an if
            // let expression is dangerous).
            let r = self.tableCache.borrow_mut().get_table(output_num);
            if let Err(e) = r {
                log!(self.options.log, "New table can't be read: {}", e);
                return Err(e);
            }
            log!(
                self.options.log,
                "New table num={}: keys={} size={}",
                output_num,
                entries,
                bytes
            );
        }
        Ok(())
    }

    fn install_compaction_results(&mut self, mut cs: CompactionState) -> Result<()> {
        log!(
            self.options.log,
            "Compacted {} L{} files + {} L{} files => {}B",
            cs.compaction.num_inputs(0),
            cs.compaction.level(),
            cs.compaction.num_inputs(1),
            cs.compaction.level() + 1,
            cs.total_bytes
        );
        cs.compaction.add_input_deletions();
        let level = cs.compaction.level();
        for output in &cs.outputs {
            cs.compaction.edit().add_file(level + 1, output.clone());
        }
        self.versionSet
            .borrow_mut()
            .log_and_apply(cs.compaction.into_edit())
    }
}

impl Drop for DB {
    fn drop(&mut self) {
        let _ = self.release_lock();
    }
}

struct CompactionState {
    compaction: Compaction,
    smallest_seq: SequenceNumber,
    outputs: Vec<FileMetaData>,
    builder: Option<TableBuilder<Box<dyn Write>>>,
    total_bytes: usize,
}

impl CompactionState {
    fn new(c: Compaction, smallest: SequenceNumber) -> CompactionState {
        CompactionState {
            compaction: c,
            smallest_seq: smallest,
            outputs: vec![],
            builder: None,
            total_bytes: 0,
        }
    }

    fn current_output(&mut self) -> &mut FileMetaData {
        let len = self.outputs.len();
        &mut self.outputs[len - 1]
    }

    /// cleanup cleans up after an aborted compaction.
    fn cleanup<P: AsRef<Path>>(&mut self, env: &Box<dyn Env>, name: P) {
        for o in self.outputs.drain(..) {
            let name = table_file_name(name.as_ref(), o.num);
            let _ = env.delete(&name);
        }
    }
}

#[derive(Debug, Default)]
struct CompactionStats {
    micros: u64,
    read: usize,
    written: usize,
}

impl CompactionStats {
    fn add(&mut self, cs: CompactionStats) {
        self.micros += cs.micros;
        self.read += cs.read;
        self.written += cs.written;
    }
}

pub fn build_table<I: LdbIterator, P: AsRef<Path>>(
    dbname: P,
    opt: &Options,
    mut from: I,
    num: FileNum,
) -> Result<FileMetaData> {
    from.reset();
    let filename = table_file_name(dbname.as_ref(), num);

    let (mut kbuf, mut vbuf) = (vec![], vec![]);
    let mut firstkey = None;
    // lastkey is what remains in kbuf.

    // Clean up file if write fails at any point.
    //
    // TODO: Replace with catch {} when available.
    let r = (|| -> Result<()> {
        let f = opt.env.open_writable_file(Path::new(&filename))?;
        let f = BufWriter::new(f);
        let mut builder = TableBuilder::new(opt.clone(), f);
        while from.advance() {
            assert!(from.current(&mut kbuf, &mut vbuf));
            if firstkey.is_none() {
                firstkey = Some(kbuf.clone());
            }
            builder.add(&kbuf, &vbuf)?;
        }
        builder.finish()?;
        Ok(())
    })();

    if let Err(e) = r {
        let _ = opt.env.delete(Path::new(&filename));
        return Err(e);
    }

    let mut md = FileMetaData::default();
    match firstkey {
        None => {
            let _ = opt.env.delete(Path::new(&filename));
        }
        Some(key) => {
            md.num = num;
            md.size = opt.env.size_of(Path::new(&filename))?;
            md.smallest = key;
            md.largest = kbuf;
        }
    }
    Ok(md)
}

fn getLogFilePath(databasePath: &Path, num: FileNum) -> PathBuf {
    databasePath.join(format!("{:06}.log", num))
}

fn getLockFilePath(databasePath: &Path) -> PathBuf {
    databasePath.join("LOCK")
}

/// open_info_log opens an info log file in the given database. It transparently returns a
/// /dev/null logger in case the open fails.
fn open_info_log<E: Env + ?Sized, P: AsRef<Path>>(env: &E, db: P) -> Logger {
    let db = db.as_ref();
    let logfilename = db.join("LOG");
    let oldlogfilename = db.join("LOG.old");
    let _ = env.mkdir(Path::new(db));
    if let Ok(e) = env.exists(Path::new(&logfilename)) {
        if e {
            let _ = env.rename(Path::new(&logfilename), Path::new(&oldlogfilename));
        }
    }
    if let Ok(w) = env.open_writable_file(Path::new(&logfilename)) {
        Logger(w)
    } else {
        Logger(Box::new(io::sink()))
    }
}