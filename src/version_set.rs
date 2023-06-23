use crate::cmp::{Comparator, InternalKeyCmp};
use crate::env::Env;
use crate::error::{err, Result, Status, StatusCode};
use crate::key_types::{parse_internal_key, InternalKey, UserKey};
use crate::log::{LogReader, LogWriter};
use crate::merging_iter::MergingIter;
use crate::options::Options;
use crate::table_cache::TableCache;
use crate::types::{
    parse_file_name, share, FileMetaData, FileNum, FileType, LdbIterator, Shared, NUM_LEVELS,
};
use crate::version::{new_version_iter, total_size, FileMetaHandle, Version};
use crate::version_edit::VersionEdit;

use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub struct Compaction {
    level: usize,
    max_file_size: usize,
    input_version: Option<Shared<Version>>,
    level_ixs: [usize; NUM_LEVELS],
    cmp: Rc<Box<dyn Comparator>>,
    icmp: InternalKeyCmp,

    manual: bool,

    // "parent" inputs from level and level+1.
    inputs: [Vec<FileMetaHandle>; 2],
    grandparent_ix: usize,
    // remaining inputs from level+2..NUM_LEVELS
    grandparents: Option<Vec<FileMetaHandle>>,
    overlapped_bytes: usize,
    seen_key: bool,
    edit: VersionEdit,
}

impl Compaction {
    // Note: opt.cmp should be the user-supplied or default Comparator (not an InternalKeyCmp).
    pub fn new(opt: &Options, level: usize, input: Option<Shared<Version>>) -> Compaction {
        Compaction {
            level,
            max_file_size: opt.max_file_size,
            input_version: input,
            level_ixs: Default::default(),
            cmp: opt.comparator.clone(),
            icmp: InternalKeyCmp(opt.comparator.clone()),
            manual: false,

            inputs: Default::default(),
            grandparent_ix: 0,
            grandparents: Default::default(),
            overlapped_bytes: 0,
            seen_key: false,
            edit: VersionEdit::new(),
        }
    }

    fn add_input(&mut self, parent: usize, f: FileMetaHandle) {
        assert!(parent <= 1);
        self.inputs[parent].push(f)
    }

    pub fn level(&self) -> usize {
        self.level
    }

    pub fn input(&self, parent: usize, ix: usize) -> FileMetaData {
        assert!(parent < 2);
        assert!(ix < self.inputs[parent].len());
        self.inputs[parent][ix].borrow().clone()
    }

    pub fn num_inputs(&self, parent: usize) -> usize {
        assert!(parent < 2);
        self.inputs[parent].len()
    }

    pub fn edit(&mut self) -> &mut VersionEdit {
        &mut self.edit
    }

    pub fn into_edit(self) -> VersionEdit {
        self.edit
    }

    /// add_input_deletions marks the current input files as deleted in the inner VersionEdit.
    pub fn add_input_deletions(&mut self) {
        for parent in 0..2 {
            for f in &self.inputs[parent] {
                self.edit.delete_file(self.level + parent, f.borrow().num);
            }
        }
    }

    /// is_base_level_for checks whether the given key may exist in levels higher than this
    /// compaction's level plus 2. I.e., whether the levels for this compaction are the last ones
    /// to contain the key.
    pub fn is_base_level_for<'a>(&mut self, k: UserKey<'a>) -> bool {
        assert!(self.input_version.is_some());
        let inp_version = self.input_version.as_ref().unwrap();
        for level in self.level + 2..NUM_LEVELS {
            let files = &inp_version.borrow().fileMetaHandleVecArr[level];
            while self.level_ixs[level] < files.len() {
                let f = files[self.level_ixs[level]].borrow();
                if self.cmp.compare(k, parse_internal_key(&f.largest).2) <= Ordering::Equal {
                    if self.cmp.compare(k, parse_internal_key(&f.smallest).2) >= Ordering::Equal {
                        // key is in this file's range, so this is not the base level.
                        return false;
                    }
                    break;
                }
                // level_ixs contains cross-call state to speed up following lookups.
                self.level_ixs[level] += 1;
            }
        }
        true
    }

    pub fn is_trivial_move(&self) -> bool {
        if self.manual {
            return false;
        }

        let inputs_size;
        if let Some(gp) = self.grandparents.as_ref() {
            inputs_size = total_size(gp.iter());
        } else {
            inputs_size = 0;
        }
        self.num_inputs(0) == 1 && self.num_inputs(1) == 0 && inputs_size < 10 * self.max_file_size
    }

    pub fn should_stop_before<'a>(&mut self, k: InternalKey<'a>) -> bool {
        if self.grandparents.is_none() {
            self.seen_key = true;
            return false;
        }
        let grandparents = self.grandparents.as_ref().unwrap();
        while self.grandparent_ix < grandparents.len()
            && self
            .icmp
            .compare(k, &grandparents[self.grandparent_ix].borrow().largest)
            == Ordering::Greater
        {
            if self.seen_key {
                self.overlapped_bytes += grandparents[self.grandparent_ix].borrow().size;
            }
            self.grandparent_ix += 1;
        }
        self.seen_key = true;

        if self.overlapped_bytes > 10 * self.max_file_size {
            self.overlapped_bytes = 0;
            true
        } else {
            false
        }
    }
}

/// VersionSet managed the various versions that are live within a database. A single version
/// contains references to the files on disk as they were at a certain point.
pub struct VersionSet {
    dbname: PathBuf,
    options: Options,
    cmp: InternalKeyCmp,
    tableCache: Shared<TableCache>,

    pub next_file_num: u64,
    pub manifest_num: u64,
    pub last_seq: u64,
    pub logNumber: u64,
    pub prev_log_num: u64,

    currentVersion: Option<Shared<Version>>,
    compaction_ptrs: [Vec<u8>; NUM_LEVELS],

    descriptor_log: Option<LogWriter<Box<dyn Write>>>,
}

impl VersionSet {
    // note: opt.cmp should not contain an InternalKeyCmp at this point, but instead the default or user-supplied one.
    pub fn new<P: AsRef<Path>>(dbName: P,
                               options: Options,
                               tableCache: Shared<TableCache>) -> VersionSet {
        VersionSet {
            dbname: dbName.as_ref().to_owned(),
            cmp: InternalKeyCmp(options.comparator.clone()),
            options: options.clone(),
            tableCache: tableCache.clone(),

            next_file_num: 2,
            manifest_num: 0,
            last_seq: 0,
            logNumber: 0,
            prev_log_num: 0,

            currentVersion: Some(share(Version::new(tableCache, options.comparator.clone()))),
            compaction_ptrs: Default::default(),
            descriptor_log: None,
        }
    }

    pub fn current_summary(&self) -> String {
        self.currentVersion.as_ref().unwrap().borrow().level_summary()
    }

    /// live_files returns the files that are currently active.
    pub fn live_files(&self) -> HashSet<FileNum> {
        let mut files = HashSet::new();
        if let Some(ref version) = self.currentVersion {
            for level in 0..NUM_LEVELS {
                for file in &version.borrow().fileMetaHandleVecArr[level] {
                    files.insert(file.borrow().num);
                }
            }
        }
        files
    }

    /// current returns a reference to the current version. It panics if there is no current version.
    pub fn current(&self) -> Shared<Version> {
        assert!(self.currentVersion.is_some());
        self.currentVersion.as_ref().unwrap().clone()
    }

    pub fn add_version(&mut self, v: Version) {
        self.currentVersion = Some(share(v));
    }

    pub fn new_file_number(&mut self) -> FileNum {
        self.next_file_num += 1;
        self.next_file_num - 1
    }

    pub fn reuse_file_number(&mut self, n: FileNum) {
        if n == self.next_file_num - 1 {
            self.next_file_num = n;
        }
    }

    pub fn markFileNumberUsed(&mut self, n: FileNum) {
        if self.next_file_num <= n {
            self.next_file_num = n + 1;
        }
    }

    /// needs_compaction returns true if a compaction makes sense at this point.
    pub fn needs_compaction(&self) -> bool {
        assert!(self.currentVersion.is_some());
        let v = self.currentVersion.as_ref().unwrap();
        let v = v.borrow();
        v.compaction_score.unwrap_or(0.0) >= 1.0 || v.file_to_compact.is_some()
    }

    fn approximate_offset<'a>(&self, v: &Shared<Version>, key: InternalKey<'a>) -> usize {
        let mut offset = 0;
        for level in 0..NUM_LEVELS {
            for f in &v.borrow().fileMetaHandleVecArr[level] {
                if self.options.comparator.compare(&f.borrow().largest, key) <= Ordering::Equal {
                    offset += f.borrow().size;
                } else if self.options.comparator.compare(&f.borrow().smallest, key) == Ordering::Greater {
                    // In higher levels, files are sorted; we don't need to search further.
                    if level > 0 {
                        break;
                    }
                } else if let Ok(tbl) = self.tableCache.borrow_mut().get_table(f.borrow().num) {
                    offset += tbl.approx_offset_of(key);
                }
            }
        }
        offset
    }

    pub fn pick_compaction(&mut self) -> Option<Compaction> {
        assert!(self.currentVersion.is_some());
        let current = self.current();
        let current = current.borrow();

        let mut c = Compaction::new(&self.options, 0, self.currentVersion.clone());
        let level;

        // Size compaction?
        if current.compaction_score.unwrap_or(0.0) >= 1.0 {
            level = current.compaction_level.unwrap();
            assert!(level < NUM_LEVELS - 1);

            for f in &current.fileMetaHandleVecArr[level] {
                if self.compaction_ptrs[level].is_empty()
                    || self
                    .cmp
                    .compare(&f.borrow().largest, &self.compaction_ptrs[level])
                    == Ordering::Greater
                {
                    c.add_input(0, f.clone());
                    break;
                }
            }

            if c.num_inputs(0) == 0 {
                // Add first file in level. This will also reset the compaction pointers.
                c.add_input(0, current.fileMetaHandleVecArr[level][0].clone());
            }
        } else if let Some(ref ftc) = current.file_to_compact {
            // Seek compaction?
            level = current.file_to_compact_lvl;
            c.add_input(0, ftc.clone());
        } else {
            return None;
        }

        c.level = level;
        c.input_version = self.currentVersion.clone();

        if level == 0 {
            let (smallest, largest) = get_range(&self.cmp, c.inputs[0].iter());
            // This call intentionally overwrites the file previously put into c.inputs[0].
            c.inputs[0] = current.overlapping_inputs(0, &smallest, &largest);
            assert!(!c.inputs[0].is_empty());
        }

        self.setup_other_inputs(&mut c);
        Some(c)
    }

    pub fn compact_range(&mut self,
                         level: usize,
                         from: InternalKey,
                         to: InternalKey, ) -> Option<Compaction> {
        assert!(self.currentVersion.is_some());
        let mut inputs = self
            .currentVersion
            .as_ref()
            .unwrap()
            .borrow()
            .overlapping_inputs(level, from, to);
        if inputs.is_empty() {
            return None;
        }

        if level > 0 {
            let mut total = 0;
            for i in 0..inputs.len() {
                total += inputs[i].borrow().size;
                if total > self.options.max_file_size {
                    inputs.truncate(i + 1);
                    break;
                }
            }
        }

        let mut c = Compaction::new(&self.options, level, self.currentVersion.clone());
        c.inputs[0] = inputs;
        c.manual = true;
        self.setup_other_inputs(&mut c);
        Some(c)
    }

    fn setup_other_inputs(&mut self, compaction: &mut Compaction) {
        assert!(self.currentVersion.is_some());
        let current = self.currentVersion.as_ref().unwrap();
        let current = current.borrow();

        let level = compaction.level;
        let (mut smallest, mut largest) = get_range(&self.cmp, compaction.inputs[0].iter());

        // Set up level+1 inputs.
        compaction.inputs[1] = current.overlapping_inputs(level + 1, &smallest, &largest);

        let (mut allstart, mut alllimit) = get_range(
            &self.cmp,
            compaction.inputs[0]
                .iter()
                .chain(compaction.inputs[1].iter()),
        );

        // Check if we can add more inputs in the current level without having to compact more
        // inputs from level+1.
        if !compaction.inputs[1].is_empty() {
            let expanded0 = current.overlapping_inputs(level, &allstart, &alllimit);
            let inputs1_size = total_size(compaction.inputs[1].iter());
            let expanded0_size = total_size(expanded0.iter());
            // ...if we picked up more files in the current level, and the total size is acceptable
            if expanded0.len() > compaction.num_inputs(0)
                && (inputs1_size + expanded0_size) < 25 * self.options.max_file_size
            {
                let (new_start, new_limit) = get_range(&self.cmp, expanded0.iter());
                let expanded1 = current.overlapping_inputs(level + 1, &new_start, &new_limit);
                if expanded1.len() == compaction.num_inputs(1) {
                    log!(
                        self.options.log,
                        "Expanding inputs@{} {}+{} ({}+{} bytes) to {}+{} ({}+{} bytes)",
                        level,
                        compaction.inputs[0].len(),
                        compaction.inputs[1].len(),
                        total_size(compaction.inputs[0].iter()),
                        total_size(compaction.inputs[1].iter()),
                        expanded0.len(),
                        expanded1.len(),
                        total_size(expanded0.iter()),
                        total_size(expanded1.iter())
                    );

                    smallest = new_start;
                    largest = new_limit;
                    compaction.inputs[0] = expanded0;
                    compaction.inputs[1] = expanded1;
                    let (newallstart, newalllimit) = get_range(
                        &self.cmp,
                        compaction.inputs[0]
                            .iter()
                            .chain(compaction.inputs[1].iter()),
                    );
                    allstart = newallstart;
                    alllimit = newalllimit;
                }
            }
        }

        // Set the list of grandparent (l+2) inputs to the files overlapped by the current overall
        // range.
        if level + 2 < NUM_LEVELS {
            let grandparents = self.currentVersion.as_ref().unwrap().borrow().overlapping_inputs(
                level + 2,
                &allstart,
                &alllimit,
            );
            compaction.grandparents = Some(grandparents);
        }

        log!(
            self.options.log,
            "Compacting @{} {:?} .. {:?}",
            level,
            smallest,
            largest
        );

        compaction.edit().set_compact_pointer(level, &largest);
        self.compaction_ptrs[level] = largest;
    }

    /// write_snapshot writes the current version, with all files, to the manifest.
    fn write_snapshot(&mut self) -> Result<usize> {
        assert!(self.descriptor_log.is_some());

        let mut edit = VersionEdit::new();
        edit.comparatorName = Some(self.options.comparator.name().to_string());

        // Save compaction pointers.
        for level in 0..NUM_LEVELS {
            if !self.compaction_ptrs[level].is_empty() {
                edit.set_compact_pointer(level, &self.compaction_ptrs[level]);
            }
        }

        let current = self.currentVersion.as_ref().unwrap().borrow();
        // Save files.
        for level in 0..NUM_LEVELS {
            let fs = &current.fileMetaHandleVecArr[level];
            for f in fs {
                edit.add_file(level, f.borrow().clone());
            }
        }
        self.descriptor_log
            .as_mut()
            .unwrap()
            .addRecord(&edit.encode())
    }

    /// log_and_apply merges the given edit with the current state and generates a new version. It
    /// writes the VersionEdit to the manifest.
    pub fn log_and_apply(&mut self, mut edit: VersionEdit) -> Result<()> {
        assert!(self.currentVersion.is_some());

        if edit.logNumber.is_none() {
            edit.logNumber = Some(self.logNumber);
        } else {
            assert!(edit.logNumber.unwrap() >= self.logNumber);
            assert!(edit.logNumber.unwrap() < self.next_file_num);
        }

        if edit.prevLogNumber.is_none() {
            edit.prevLogNumber = Some(self.prev_log_num);
        }

        edit.nextFileNumber = Some(self.next_file_num);
        edit.lastSequenceNumber = Some(self.last_seq);

        let mut v = Version::new(self.tableCache.clone(), self.options.comparator.clone());
        {
            let mut builder = Builder::new();
            builder.apply(&edit, &mut self.compaction_ptrs);
            builder.save_to(&self.cmp, self.currentVersion.as_ref().unwrap(), &mut v);
        }
        self.finalize(&mut v);

        if self.descriptor_log.is_none() {
            let descname = getManifestFilePath(&self.dbname, self.manifest_num);
            edit.nextFileNumber = Some(self.next_file_num);
            self.descriptor_log = Some(LogWriter::new(
                self.options.env.open_writable_file(Path::new(&descname))?,
            ));
            self.write_snapshot()?;
        }

        let encoded = edit.encode();
        if let Some(ref mut lw) = self.descriptor_log {
            lw.addRecord(&encoded)?;
            lw.flush()?;
        }
        setCurrentFile(&self.options.env, &self.dbname, self.manifest_num)?;

        self.add_version(v);
        // log_number was set above.
        self.logNumber = edit.logNumber.unwrap();

        // TODO: Roll back written files if something went wrong.
        Ok(())
    }

    fn finalize(&self, v: &mut Version) {
        let mut best_lvl = None;
        let mut best_score = None;

        for l in 0..NUM_LEVELS - 1 {
            let score: f64;
            if l == 0 {
                score = v.fileMetaHandleVecArr[l].len() as f64 / 4.0;
            } else {
                let mut max_bytes = 10.0 * f64::from(1 << 20);
                for _ in 0..l - 1 {
                    max_bytes *= 10.0;
                }
                score = total_size(v.fileMetaHandleVecArr[l].iter()) as f64 / max_bytes;
            }
            if let Some(ref mut b) = best_score {
                if *b < score {
                    *b = score;
                    best_lvl = Some(l);
                }
            } else {
                best_score = Some(score);
                best_lvl = Some(l);
            }
        }
        v.compaction_score = best_score;
        v.compaction_level = best_lvl;
    }

    /// recovers the state of a LevelDB instance from the files on disk.
    /// returns true, the a manifest needs to be written eventually (using log_and_apply()).
    pub fn recover(&mut self) -> Result<bool> {
        assert!(self.currentVersion.is_some());

        let mut currentFileContent = readCurrentFile(&self.options.env, &self.dbname)?;
        let len = currentFileContent.len();
        currentFileContent.truncate(len - 1);
        let manifestFileName = Path::new(&currentFileContent);

        let manifestFilePath = self.dbname.join(manifestFileName);

        let mut builder = Builder::new();

        {
            let mut manifestFile = self.options.env.open_sequential_file(Path::new(&manifestFilePath))?;

            let mut logReader = LogReader::new(&mut manifestFile, true);

            let mut logNumber = None;
            let mut prevLogNumber = None;
            let mut nextFileNumber = None;
            let mut lastSequenceNumber = None;

            let mut buffer = Vec::new();
            while let Ok(size) = logReader.read(&mut buffer) {
                if size == 0 {
                    break;
                }

                let versionEdit = VersionEdit::decodeFrom(&buffer)?;
                builder.apply(&versionEdit, &mut self.compaction_ptrs);

                if let Some(ln) = versionEdit.logNumber {
                    logNumber = Some(ln);
                }
                if let Some(nfn) = versionEdit.nextFileNumber {
                    nextFileNumber = Some(nfn);
                }
                if let Some(ls) = versionEdit.lastSequenceNumber {
                    lastSequenceNumber = Some(ls);
                }
                if let Some(pln) = versionEdit.prevLogNumber {
                    prevLogNumber = Some(pln);
                }
            }

            if let Some(ln) = logNumber {
                self.logNumber = ln;
                self.markFileNumberUsed(ln);
            } else {
                return err(StatusCode::Corruption, "no meta-lognumber entry in descriptor");
            }

            if let Some(nfn) = nextFileNumber {
                self.next_file_num = nfn + 1;
            } else {
                return err(StatusCode::Corruption, "no meta-next-file entry in descriptor");
            }

            if let Some(ls) = lastSequenceNumber {
                self.last_seq = ls;
            } else {
                return err(StatusCode::Corruption, "no last-sequence entry in descriptor");
            }

            if let Some(pln) = prevLogNumber {
                self.prev_log_num = pln;
                self.markFileNumberUsed(prevLogNumber.unwrap());
            } else {
                self.prev_log_num = 0;
            }
        }

        let mut v = Version::new(self.tableCache.clone(), self.options.comparator.clone());
        builder.save_to(&self.cmp, self.currentVersion.as_ref().unwrap(), &mut v);
        self.finalize(&mut v);
        self.add_version(v);
        self.manifest_num = self.next_file_num - 1;

        log!(self.options.log,
            "recovered manifest with next_file={} manifest_num={} log_num={} prev_log_num={} last_seq={}",
            self.next_file_num,
            self.manifest_num,
            self.logNumber,
            self.prev_log_num,
            self.last_seq);

        // A new manifest needs to be written only if we don't reuse the existing one.
        Ok(!self.reuse_manifest(&manifestFilePath, &manifestFileName))
    }

    /// reuse_manifest checks whether the current manifest can be reused.
    fn reuse_manifest(&mut self,
                      current_manifest_path: &Path,
                      current_manifest_base: &Path, ) -> bool {
        // Note: The original has only one option, reuse_logs; reuse_logs has to be set in order to reuse manifests.
        // However, there's not much that stops us from reusing manifests without reusing logs or
        // vice versa. One issue exists though: If no write operations are done, empty log files
        // will accumulate every time a DB is opened, until at least one write happens (otherwise,
        // the logs won't be compacted and deleted).
        if !self.options.reuse_manifest {
            return false;
        }

        // The original doesn't reuse manifests; we do.
        if let Ok((num, typ)) = parse_file_name(current_manifest_base) {
            if typ != FileType::Descriptor {
                return false;
            }
            if let Ok(size) = self.options.env.size_of(Path::new(current_manifest_path)) {
                if size >= self.options.max_file_size {
                    return false;
                }

                assert!(self.descriptor_log.is_none());
                let s = self
                    .options
                    .env
                    .open_appendable_file(Path::new(current_manifest_path));
                if let Ok(f) = s {
                    log!(self.options.log, "reusing manifest {:?}", current_manifest_path);
                    self.descriptor_log = Some(LogWriter::new_with_off(f, size));
                    self.manifest_num = num;
                    return true;
                } else {
                    log!(self.options.log, "reuse_manifest: {}", s.err().unwrap());
                }
            }
        }
        false
    }

    /// make_input_iterator returns an iterator over the inputs of a compaction.
    pub fn make_input_iterator(&self, c: &Compaction) -> Box<dyn LdbIterator> {
        let cap = if c.level == 0 { c.num_inputs(0) + 1 } else { 2 };
        let mut iters: Vec<Box<dyn LdbIterator>> = Vec::with_capacity(cap);
        for i in 0..2 {
            if c.num_inputs(i) == 0 {
                continue;
            }
            if c.level + i == 0 {
                // Add individual iterators for L0 tables.
                for fi in 0..c.num_inputs(i) {
                    let f = &c.inputs[i][fi];
                    let s = self.tableCache.borrow_mut().get_table(f.borrow().num);
                    if let Ok(tbl) = s {
                        iters.push(Box::new(tbl.iter()));
                    } else {
                        log!(
                            self.options.log,
                            "error opening table {}: {}",
                            f.borrow().num,
                            s.err().unwrap()
                        );
                    }
                }
            } else {
                // Create concatenating iterator higher levels.
                iters.push(Box::new(new_version_iter(
                    c.inputs[i].clone(),
                    self.tableCache.clone(),
                    self.options.comparator.clone(),
                )));
            }
        }
        assert!(iters.len() <= cap);
        let cmp: Rc<Box<dyn Comparator>> = Rc::new(Box::new(self.cmp.clone()));
        Box::new(MergingIter::new(cmp, iters))
    }
}

struct Builder {
    // (added, deleted) files per level.
    deleted: [Vec<FileNum>; NUM_LEVELS],
    added: [Vec<FileMetaHandle>; NUM_LEVELS],
}

impl Builder {
    fn new() -> Builder {
        Builder {
            deleted: Default::default(),
            added: Default::default(),
        }
    }

    /// apply applies the edits recorded in edit to the builder state. compaction pointers are
    /// copied to the supplied compaction_ptrs array.
    fn apply(&mut self, edit: &VersionEdit, compaction_ptrs: &mut [Vec<u8>; NUM_LEVELS]) {
        for c in edit.compactionPointerVec.iter() {
            compaction_ptrs[c.level] = c.key.clone();
        }
        for &(level, num) in edit.deleted.iter() {
            self.deleted[level].push(num);
        }
        for &(level, ref f) in edit.new_files.iter() {
            let mut f = f.clone();
            f.allowed_seeks = f.size / 16384;
            if f.allowed_seeks < 100 {
                f.allowed_seeks = 100;
            }
            // Remove this file from the list of deleted files.
            self.deleted[level] = self.deleted[level]
                .iter()
                .filter_map(|d| if *d != f.num { Some(*d) } else { None })
                .collect();
            self.added[level].push(share(f));
        }
    }

    /// maybe_add_file adds a file f at level to version v, if it's not already marked as deleted
    /// in this edit. It also asserts that the ordering of files is preserved.
    fn maybe_add_file(&mut self,
                      cmp: &InternalKeyCmp,
                      v: &mut Version,
                      level: usize,
                      f: FileMetaHandle, ) {
        // Only add file if it's not already deleted.
        if self.deleted[level].iter().any(|d| *d == f.borrow().num) {
            return;
        }

        {
            let files = &v.fileMetaHandleVecArr[level];
            if level > 0 && !files.is_empty() {
                // File must be after last file in level.
                assert_eq!(
                    cmp.compare(
                        &files[files.len() - 1].borrow().largest,
                        &f.borrow().smallest,
                    ),
                    Ordering::Less
                );
            }
        }

        v.fileMetaHandleVecArr[level].push(f);
    }

    /// saves the edits applied to the builder to v, adding all non-deleted files from Version base to v.
    fn save_to(&mut self, cmp: &InternalKeyCmp, base: &Shared<Version>, v: &mut Version) {
        for level in 0..NUM_LEVELS {
            sort_files_by_smallest(cmp, &mut self.added[level]);
            // The base version should already have sorted files.
            sort_files_by_smallest(cmp, &mut base.borrow_mut().fileMetaHandleVecArr[level]);

            let added = self.added[level].clone();
            let basefiles = base.borrow().fileMetaHandleVecArr[level].clone();
            v.fileMetaHandleVecArr[level].reserve(basefiles.len() + self.added[level].len());

            let iadded = added.into_iter();
            let ibasefiles = basefiles.into_iter();
            let merged = merge_iters(iadded, ibasefiles, |a, b| {
                cmp.compare(&a.borrow().smallest, &b.borrow().smallest)
            });
            for m in merged {
                self.maybe_add_file(cmp, v, level, m);
            }

            // Make sure that there is no overlap in higher levels.
            if level == 0 {
                continue;
            }
            for i in 1..v.fileMetaHandleVecArr[level].len() {
                let (prev_end, this_begin) = (
                    &v.fileMetaHandleVecArr[level][i - 1].borrow().largest,
                    &v.fileMetaHandleVecArr[level][i].borrow().smallest,
                );
                assert!(cmp.compare(prev_end, this_begin) < Ordering::Equal);
            }
        }
    }
}

fn getManifestFileName(file_num: FileNum) -> PathBuf {
    Path::new(&format!("MANIFEST-{:06}", file_num)).to_owned()
}

pub fn getManifestFilePath<P: AsRef<Path>>(databasePath: P, file_num: FileNum) -> PathBuf {
    databasePath.as_ref().join(getManifestFileName(file_num))
}

fn getTempFilePath<P: AsRef<Path>>(databasePath: P, fileNum: FileNum) -> PathBuf {
    databasePath.as_ref().join(format!("{:06}.dbtmp", fileNum))
}

fn getCurrentFilePath<P: AsRef<Path>>(dbName: P) -> PathBuf {
    dbName.as_ref().join("CURRENT").to_owned()
}

/// CURRENT 文件的内容应该是MANIFEST文件的名字
pub fn readCurrentFile(env: &Box<dyn Env>, dbname: &Path) -> Result<String> {
    let mut currentFileContent = String::new();
    let mut f = env.open_sequential_file(Path::new(&getCurrentFilePath(dbname)))?;

    f.read_to_string(&mut currentFileContent)?;

    if currentFileContent.is_empty() || !currentFileContent.ends_with('\n') {
        return err(StatusCode::Corruption, "current file is empty or has no newline");
    }

    Ok(currentFileContent)
}

pub fn setCurrentFile<P: AsRef<Path>>(env: &Box<dyn Env>,
                                      databasePath: P,
                                      manifestFileNum: FileNum) -> Result<()> {
    let databasePath = databasePath.as_ref();
    let tempFilePath = getTempFilePath(databasePath, manifestFileNum);

    {
        let mut tempFile = env.open_writable_file(Path::new(&tempFilePath))?;
        tempFile.write_all(getManifestFileName(manifestFileNum).display().to_string().as_bytes())?;
        tempFile.write_all(b"\n")?;
    }

    // 把temp文件重命名为CURRENT
    if let Err(e) = env.rename(Path::new(&tempFilePath), Path::new(&getCurrentFilePath(databasePath))) {
        let _ = env.delete(Path::new(&tempFilePath));
        return Err(Status::from(e));
    }

    Ok(())
}

/// sort_files_by_smallest sorts the list of files by the smallest keys of the files.
fn sort_files_by_smallest<C: Comparator>(cmp: &C, files: &mut Vec<FileMetaHandle>) {
    files.sort_by(|a, b| cmp.compare(&a.borrow().smallest, &b.borrow().smallest))
}

/// merge_iters merges and collects the items from two sorted iterators.
fn merge_iters<
    Item,
    C: Fn(&Item, &Item) -> Ordering,
    I: Iterator<Item=Item>,
    J: Iterator<Item=Item>,
>(
    mut iter_a: I,
    mut iter_b: J,
    cmp: C,
) -> Vec<Item> {
    let mut a = iter_a.next();
    let mut b = iter_b.next();
    let mut out = vec![];
    while a.is_some() && b.is_some() {
        let ord = cmp(a.as_ref().unwrap(), b.as_ref().unwrap());
        if ord == Ordering::Less {
            out.push(a.unwrap());
            a = iter_a.next();
        } else {
            out.push(b.unwrap());
            b = iter_b.next();
        }
    }

    // Push cached elements.
    if let Some(a_) = a {
        out.push(a_);
    }
    if let Some(b_) = b {
        out.push(b_);
    }

    // Push remaining elements from either iterator.
    for a in iter_a {
        out.push(a);
    }
    for b in iter_b {
        out.push(b);
    }
    out
}

/// get_range returns the indices of the files within files that have the smallest lower bound
/// respectively the largest upper bound.
fn get_range<'a, C: Comparator, I: Iterator<Item=&'a FileMetaHandle>>(
    c: &C,
    files: I,
) -> (Vec<u8>, Vec<u8>) {
    let mut smallest = None;
    let mut largest = None;
    for f in files {
        if smallest.is_none() {
            smallest = Some(f.borrow().smallest.clone());
        }
        if largest.is_none() {
            largest = Some(f.borrow().largest.clone());
        }
        let f = f.borrow();
        if c.compare(&f.smallest, smallest.as_ref().unwrap()) == Ordering::Less {
            smallest = Some(f.smallest.clone());
        }
        if c.compare(&f.largest, largest.as_ref().unwrap()) == Ordering::Greater {
            largest = Some(f.largest.clone());
        }
    }
    (smallest.unwrap(), largest.unwrap())
}