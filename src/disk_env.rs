use crate::env::{path_to_str, Env, FileLock, Logger, RandomAccess};
use crate::env_common::{micros, sleep_for};
use crate::error::{err, Result, Status, StatusCode};
use fs2::FileExt;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

type FileDescriptor = i32;

#[derive(Clone)]
pub struct PosixDiskEnv {
    locks: Arc<Mutex<HashMap<String, File>>>,
}

impl PosixDiskEnv {
    pub fn new() -> PosixDiskEnv {
        PosixDiskEnv {
            locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

///  annotates an io::Error with information about the operation and the file.
fn err2Status(methodName: &'static str, path: &Path, error: io::Error) -> Status {
    let mut status = Status::from(error);
    status.err = format!("{}: {}: {}", methodName, status.err, path_to_str(path));
    status
}

// Note: We're using Ok(f()?) in several locations below in order to benefit from the automatic
// error conversion using std::convert::From.
impl Env for PosixDiskEnv {
    fn open_sequential_file(&self, path: &Path) -> Result<Box<dyn Read>> {
        Ok(Box::new(
            fs::OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|e| err2Status("open (seq)", path, e))?,
        ))
    }

    fn open_random_access_file(&self, path: &Path) -> Result<Box<dyn RandomAccess>> {
        Ok(fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map(|f| { Box::new(f) as Box<dyn RandomAccess> })
            .map_err(|e| err2Status("open (random access)", path, e))?)
    }

    fn open_writable_file(&self, path: &Path) -> Result<Box<dyn Write>> {
        Ok(Box::new(
            fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(false)
                .open(path)
                .map_err(|e| err2Status("open (write)", path, e))?,
        ))
    }

    fn open_appendable_file(&self, path: &Path) -> Result<Box<dyn Write>> {
        Ok(Box::new(
            fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(path)
                .map_err(|e| err2Status("open (append)", path, e))?,
        ))
    }

    fn exists(&self, path: &Path) -> Result<bool> {
        Ok(path.exists())
    }

    fn children(&self, p: &Path) -> Result<Vec<PathBuf>> {
        let dir_reader = fs::read_dir(p).map_err(|e| err2Status("children", p, e))?;
        let filenames = dir_reader
            .map(|r| match r {
                Ok(_) => {
                    let direntry = r.unwrap();
                    Path::new(&direntry.file_name()).to_owned()
                }
                Err(_) => Path::new("").to_owned(),
            })
            .filter(|s| !s.as_os_str().is_empty());
        Ok(Vec::from_iter(filenames))
    }

    fn size_of(&self, p: &Path) -> Result<usize> {
        let meta = fs::metadata(p).map_err(|e| err2Status("size_of", p, e))?;
        Ok(meta.len() as usize)
    }

    fn delete(&self, p: &Path) -> Result<()> {
        Ok(fs::remove_file(p).map_err(|e| err2Status("delete", p, e))?)
    }

    fn mkdir(&self, p: &Path) -> Result<()> {
        Ok(fs::create_dir_all(p).map_err(|e| err2Status("mkdir", p, e))?)
    }

    fn rmdir(&self, p: &Path) -> Result<()> {
        Ok(fs::remove_dir_all(p).map_err(|e| err2Status("rmdir", p, e))?)
    }

    fn rename(&self, old: &Path, new: &Path) -> Result<()> {
        Ok(fs::rename(old, new).map_err(|e| err2Status("rename", old, e))?)
    }

    fn lock(&self, path: &Path) -> Result<FileLock> {
        let mut locks = self.locks.lock().unwrap();

        if locks.contains_key(&path.to_str().unwrap().to_string()) {
            return Err(Status::new(StatusCode::AlreadyExists, "Lock is held"));
        }

        let f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(path)
            .map_err(|e| err2Status("lock", path, e))?;

        match f.try_lock_exclusive() {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(Status::new(StatusCode::LockError, "lock on database is already held by different process"));
            }
            Err(_) => {
                return Err(Status::new(StatusCode::Errno(errno::errno()), &format!("unknown lock error on file {:?} (file {})", f, path.display())));
            }
            _ => (),
        };

        locks.insert(path.to_str().unwrap().to_string(), f);

        Ok(FileLock{path: path: path.to_str().unwrap().to_string()})
    }
    fn unlock(&self, l: FileLock) -> Result<()> {
        let mut locks = self.locks.lock().unwrap();
        if !locks.contains_key(&l.path) {
            err(
                StatusCode::LockError,
                &format!("unlocking a file that is not locked: {}", l.path),
            )
        } else {
            let f = locks.remove(&l.path).unwrap();
            if f.unlock().is_err() {
                return err(StatusCode::LockError, &format!("unlock failed: {}", l.path));
            }
            Ok(())
        }
    }

    fn new_logger(&self, p: &Path) -> Result<Logger> {
        self.open_appendable_file(p)
            .map(|dst| Logger::new(Box::new(dst)))
    }

    fn micros(&self) -> u64 {
        micros()
    }

    fn sleep_for(&self, micros: u32) {
        sleep_for(micros);
    }
}