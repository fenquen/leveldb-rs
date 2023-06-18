use crate::error::{err, Result, StatusCode};
use crate::key_types::InternalKey;
use crate::types::{FileMetaData, FileNum, SequenceNumber};

use integer_encoding::{VarIntReader, VarIntWriter};

use std::collections::HashSet;
use std::io::{Read, Write};

#[derive(PartialEq, Debug, Clone)]
pub struct CompactionPointer {
    pub level: usize,
    // This key is in InternalKey format.
    pub key: Vec<u8>,
}

enum EditTag {
    Comparator = 1,
    LogNumber = 2,
    NextFileNumber = 3,
    LastSequence = 4,
    CompactPointer = 5,
    DeletedFile = 6,
    NewFile = 7,
    PrevLogNumber = 9, // sic!
}

fn tag2enum(t: u32) -> Option<EditTag> {
    match t {
        1 => Some(EditTag::Comparator),
        2 => Some(EditTag::LogNumber),
        3 => Some(EditTag::NextFileNumber),
        4 => Some(EditTag::LastSequence),
        5 => Some(EditTag::CompactPointer),
        6 => Some(EditTag::DeletedFile),
        7 => Some(EditTag::NewFile),
        9 => Some(EditTag::PrevLogNumber),
        _ => None,
    }
}

fn readLengthPrefixed<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    if let Ok(keyLength) = reader.read_varint() {
        let mut buffer = Vec::new();
        buffer.resize(keyLength, 0);

        if let Ok(count) = reader.read(&mut buffer) {
            if count != keyLength {
                return err(StatusCode::IOError, "Couldn't read full key");
            }
            Ok(buffer)
        } else {
            err(StatusCode::IOError, "Couldn't read key")
        }
    } else {
        err(StatusCode::IOError, "Couldn't read key length")
    }
}

/// manages changes to the set of managed SSTables and logfiles.
pub struct VersionEdit {
    comparator: Option<String>,
    pub logNumber: Option<FileNum>,
    pub prevLogNumber: Option<FileNum>,
    pub next_file_number: Option<FileNum>,
    pub last_seq: Option<SequenceNumber>,

    pub compactionPointerVec: Vec<CompactionPointer>,
    pub deleted: HashSet<(usize, FileNum)>,
    pub new_files: Vec<(usize, FileMetaData)>,
}

impl VersionEdit {
    pub fn new() -> VersionEdit {
        VersionEdit {
            comparator: None,
            logNumber: None,
            prevLogNumber: None,
            next_file_number: None,
            last_seq: None,
            compactionPointerVec: Vec::with_capacity(8),
            deleted: HashSet::with_capacity(8),
            new_files: Vec::with_capacity(8),
        }
    }

    pub fn clear(&mut self) {
        *self = VersionEdit::new();
    }

    pub fn add_file(&mut self, level: usize, file: FileMetaData) {
        self.new_files.push((level, file))
    }

    pub fn delete_file(&mut self, level: usize, file_num: FileNum) {
        self.deleted.insert((level, file_num));
    }

    pub fn set_comparator_name(&mut self, name: &str) {
        self.comparator = Some(name.to_string())
    }

    pub fn set_log_num(&mut self, num: u64) {
        self.logNumber = Some(num)
    }

    pub fn set_prev_log_num(&mut self, num: u64) {
        self.prevLogNumber = Some(num);
    }

    pub fn set_last_seq(&mut self, num: u64) {
        self.last_seq = Some(num)
    }

    pub fn set_next_file(&mut self, num: FileNum) {
        self.next_file_number = Some(num)
    }

    pub fn set_compact_pointer(&mut self, level: usize, key: InternalKey) {
        self.compactionPointerVec.push(CompactionPointer {
            level,
            key: Vec::from(key),
        })
    }

    /// Encode this VersionEdit into a buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        if let Some(ref cmp) = self.comparator {
            // swallow errors, because it's a pure in-memory write
            buf.write_varint(EditTag::Comparator as u32).unwrap();
            // data is prefixed by a varint32 describing the length of the following chunk
            buf.write_varint(cmp.len()).unwrap();
            buf.write_all(cmp.as_bytes()).unwrap();
        }

        if let Some(lognum) = self.logNumber {
            buf.write_varint(EditTag::LogNumber as u32).unwrap();
            buf.write_varint(lognum).unwrap();
        }

        if let Some(prevlognum) = self.prevLogNumber {
            buf.write_varint(EditTag::PrevLogNumber as u32).unwrap();
            buf.write_varint(prevlognum).unwrap();
        }

        if let Some(nfn) = self.next_file_number {
            buf.write_varint(EditTag::NextFileNumber as u32).unwrap();
            buf.write_varint(nfn).unwrap();
        }

        if let Some(ls) = self.last_seq {
            buf.write_varint(EditTag::LastSequence as u32).unwrap();
            buf.write_varint(ls).unwrap();
        }

        for cptr in self.compactionPointerVec.iter() {
            buf.write_varint(EditTag::CompactPointer as u32).unwrap();
            buf.write_varint(cptr.level).unwrap();
            buf.write_varint(cptr.key.len()).unwrap();
            buf.write_all(cptr.key.as_ref()).unwrap();
        }

        for df in self.deleted.iter() {
            buf.write_varint(EditTag::DeletedFile as u32).unwrap();
            buf.write_varint(df.0).unwrap();
            buf.write_varint(df.1).unwrap();
        }

        for nf in self.new_files.iter() {
            buf.write_varint(EditTag::NewFile as u32).unwrap();
            buf.write_varint(nf.0).unwrap();
            buf.write_varint(nf.1.num).unwrap();
            buf.write_varint(nf.1.size).unwrap();

            buf.write_varint(nf.1.smallest.len()).unwrap();
            buf.write_all(nf.1.smallest.as_ref()).unwrap();
            buf.write_varint(nf.1.largest.len()).unwrap();
            buf.write_all(nf.1.largest.as_ref()).unwrap();
        }

        buf
    }

    pub fn decodeFrom(src: &[u8]) -> Result<VersionEdit> {
        let mut reader = src;
        let mut versionEdit = VersionEdit::new();

        while let Ok(tag) = reader.read_varint::<u32>() {
            if let Some(tag) = tag2enum(tag) {
                match tag {
                    EditTag::Comparator => {
                        let buffer = readLengthPrefixed(&mut reader)?;
                        if let Ok(c) = String::from_utf8(buffer) {
                            versionEdit.comparator = Some(c);
                        } else {
                            return err(StatusCode::Corruption, "Bad comparator encoding");
                        }
                    }
                    EditTag::LogNumber => {
                        if let Ok(logNum) = reader.read_varint() {
                            versionEdit.logNumber = Some(logNum);
                        } else {
                            return err(StatusCode::IOError, "Couldn't read log number");
                        }
                    }
                    EditTag::PrevLogNumber => {
                        if let Ok(prevLogNumber) = reader.read_varint() {
                            versionEdit.prevLogNumber = Some(prevLogNumber);
                        } else {
                            return err(StatusCode::IOError, "Couldn't read prev log number");
                        }
                    }
                    EditTag::NextFileNumber => {
                        if let Ok(nextFileNumber) = reader.read_varint() {
                            versionEdit.next_file_number = Some(nextFileNumber);
                        } else {
                            return err(StatusCode::IOError, "Couldn't read next_file_number");
                        }
                    }
                    EditTag::LastSequence => {
                        if let Ok(ls) = reader.read_varint() {
                            versionEdit.last_seq = Some(ls);
                        } else {
                            return err(StatusCode::IOError, "Couldn't read last_sequence");
                        }
                    }
                    EditTag::CompactPointer => {
                        // Monads by indentation...
                        if let Ok(lvl) = reader.read_varint() {
                            let key = readLengthPrefixed(&mut reader)?;

                            versionEdit.compactionPointerVec.push(CompactionPointer { level: lvl, key });
                        } else {
                            return err(StatusCode::IOError, "Couldn't read level");
                        }
                    }
                    EditTag::DeletedFile => {
                        if let Ok(lvl) = reader.read_varint() {
                            if let Ok(num) = reader.read_varint() {
                                versionEdit.deleted.insert((lvl, num));
                            } else {
                                return err(StatusCode::IOError, "Couldn't read file num");
                            }
                        } else {
                            return err(StatusCode::IOError, "Couldn't read level");
                        }
                    }
                    EditTag::NewFile => {
                        if let Ok(lvl) = reader.read_varint() {
                            if let Ok(num) = reader.read_varint() {
                                if let Ok(size) = reader.read_varint() {
                                    let smallest = readLengthPrefixed(&mut reader)?;
                                    let largest = readLengthPrefixed(&mut reader)?;
                                    versionEdit.new_files.push((
                                        lvl,
                                        FileMetaData {
                                            num,
                                            size,
                                            smallest,
                                            largest,
                                            allowed_seeks: 0,
                                        },
                                    ))
                                } else {
                                    return err(StatusCode::IOError, "Couldn't read file size");
                                }
                            } else {
                                return err(StatusCode::IOError, "Couldn't read file num");
                            }
                        } else {
                            return err(StatusCode::IOError, "Couldn't read file level");
                        }
                    }
                }
            } else {
                return err(StatusCode::Corruption, &format!("Invalid tag number {}", tag));
            }
        }

        Ok(versionEdit)
    }
}