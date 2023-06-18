//! table_cache implements a cache providing access to the immutable SSTables on disk. It's a
//! read-through cache, meaning that non-present tables are read from disk and cached before being
//! returned.

use crate::cache::{self, Cache};
use crate::error::{err, Result, StatusCode};
use crate::key_types::InternalKey;
use crate::options::Options;
use crate::table_reader::Table;
use crate::types::FileNum;

use integer_encoding::FixedIntWriter;

use std::convert::AsRef;
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub fn table_file_name<P: AsRef<Path>>(name: P, num: FileNum) -> PathBuf {
    assert!(num > 0);
    name.as_ref().join(format!("{:06}.ldb", num))
}

fn filenum_to_key(num: FileNum) -> cache::CacheKey {
    let mut buf = [0; 16];
    (&mut buf[..]).write_fixedint(num).unwrap();
    buf
}

pub struct TableCache {
    dbName: PathBuf,
    cache: Cache<Table>,
    options: Options,
}

impl TableCache {
    /// Create a new TableCache for the database named `db`, caching up to `entries` tables.
    ///
    /// opt.cmp should be the user-supplied comparator.
    pub fn new<P: AsRef<Path>>(dbName: P,
                               options: Options,
                               cacheCapacity: usize) -> TableCache {
        TableCache {
            dbName: dbName.as_ref().to_owned(),
            cache: Cache::new(cacheCapacity),
            options,
        }
    }

    pub fn get(
        &mut self,
        file_num: FileNum,
        key: InternalKey,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let tbl = self.get_table(file_num)?;
        tbl.get(key)
    }

    /// Return a table from cache, or open the backing file, then cache and return it.
    pub fn get_table(&mut self, file_num: FileNum) -> Result<Table> {
        let key = filenum_to_key(file_num);
        if let Some(t) = self.cache.get(&key) {
            return Ok(t.clone());
        }
        self.open_table(file_num)
    }

    /// Open a table on the file system and read it.
    fn open_table(&mut self, file_num: FileNum) -> Result<Table> {
        let name = table_file_name(&self.dbName, file_num);
        let path = Path::new(&name);
        let file_size = self.options.env.size_of(&path)?;
        if file_size == 0 {
            return err(StatusCode::InvalidData, "file is empty");
        }
        let file = Rc::new(self.options.env.open_random_access_file(&path)?);
        // No SSTable file name compatibility.
        let table = Table::new(self.options.clone(), file, file_size)?;
        self.cache.insert(&filenum_to_key(file_num), table.clone());
        Ok(table)
    }

    pub fn evict(&mut self, file_num: FileNum) -> Result<()> {
        if self.cache.remove(&filenum_to_key(file_num)).is_some() {
            Ok(())
        } else {
            err(StatusCode::NotFound, "table not present in cache")
        }
    }
}