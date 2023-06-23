//! A log consists of a number of blocks.
//! A block consists of a number of records and an optional trailer (filler).
//! A record is a bytestring: [checksum: uint32, length: uint16, type: uint8, data: [u8]]
//! checksum is the crc32 sum of type and data; type is one of RecordType::{Full/First/Middle/Last}

use crate::error::{err, Result, StatusCode};

use std::io::{Read, Write};

use crc::crc32;
use crc::Hasher32;
use integer_encoding::FixedInt;
use integer_encoding::FixedIntWriter;

const BLOCK_SIZE: usize = 32 * 1024;

/// checkSum(4) + length(2) + type(1)
const HEADER_SIZE: usize = 4 + 2 + 1;

#[derive(Clone, Copy)]
pub enum RecordType {
    Full = 1,
    First = 2,
    Middle = 3,
    Last = 4,
}

pub struct LogWriter<W: Write> {
    writer: W,
    digest: crc32::Digest,
    current_block_offset: usize,
    block_size: usize,
}

impl<W: Write> LogWriter<W> {
    pub fn new(writer: W) -> LogWriter<W> {
        let digest = crc32::Digest::new(crc32::CASTAGNOLI);
        LogWriter {
            writer: writer,
            current_block_offset: 0,
            block_size: BLOCK_SIZE,
            digest,
        }
    }

    /// new_with_off opens a writer starting at some offset of an existing log file. The file must
    /// have the default block size.
    pub fn new_with_off(writer: W, off: usize) -> LogWriter<W> {
        let mut w = LogWriter::new(writer);
        w.current_block_offset = off % BLOCK_SIZE;
        w
    }

    pub fn addRecord(&mut self, record: &[u8]) -> Result<usize> {
        let mut record = &record[..];
        let mut firstRound = true;
        let mut result = Ok(0);

        while result.is_ok() && !record.is_empty() {
            assert!(self.block_size > HEADER_SIZE);

            let space_left = self.block_size - self.current_block_offset;

            // fill up block; go to next block.
            if space_left < HEADER_SIZE {
                self.writer.write_all(&vec![0, 0, 0, 0, 0, 0][0..space_left])?;
                self.current_block_offset = 0;
            }

            let availableLenForData = self.block_size - self.current_block_offset - HEADER_SIZE;

            let data_frag_len = if record.len() < availableLenForData {
                record.len()
            } else {
                availableLenForData
            };

            let recordType =
                if firstRound && data_frag_len == record.len() {
                    RecordType::Full
                } else if firstRound {
                    RecordType::First
                } else if data_frag_len == record.len() {
                    RecordType::Last
                } else {
                    RecordType::Middle
                };

            result = self.emit_record(recordType, record, data_frag_len);
            record = &record[data_frag_len..];
            firstRound = false;
        }

        result
    }

    fn emit_record(&mut self, t: RecordType, data: &[u8], len: usize) -> Result<usize> {
        assert!(len < 256 * 256);

        self.digest.reset();
        self.digest.write(&[t as u8]);
        self.digest.write(&data[0..len]);

        let chksum = mask_crc(self.digest.sum32());

        let mut s = 0;
        s += self.writer.write(&chksum.encode_fixed_vec())?;
        s += self.writer.write_fixedint(len as u16)?;
        s += self.writer.write(&[t as u8])?;
        s += self.writer.write(&data[0..len])?;

        self.current_block_offset += s;
        Ok(s)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

pub struct LogReader<R: Read> {
    // TODO: Wrap src in a buffer to enhance read performance.
    src: R,
    digest: crc32::Digest,
    blockOffset: usize,
    blockSize: usize,
    headScratch: [u8; HEADER_SIZE],
    checksums: bool,
}

impl<R: Read> LogReader<R> {
    pub fn new(src: R, checksum: bool) -> LogReader<R> {
        LogReader {
            src,
            blockOffset: 0,
            blockSize: BLOCK_SIZE,
            checksums: checksum,
            headScratch: [0; HEADER_SIZE],
            digest: crc32::Digest::new(crc32::CASTAGNOLI),
        }
    }

    pub fn read(&mut self, dest: &mut Vec<u8>) -> Result<usize> {
        dest.clear();

        loop {
            // skip to next block
            if self.blockSize - self.blockOffset < HEADER_SIZE {
                self.src.read_exact(&mut self.headScratch[0..self.blockSize - self.blockOffset])?;
                self.blockOffset = 0;
            }

            let mut readCount = self.src.read(&mut self.headScratch)?;

            // EOF is signalled by Ok(0)
            if readCount == 0 {
                return Ok(0);
            }

            self.blockOffset += readCount;

            let mut checksum = u32::decode_fixed(&self.headScratch[0..4]);
            let mut length = u16::decode_fixed(&self.headScratch[4..6]);
            let mut type_ = self.headScratch[6];

            // dest当前的位置
            let mut destOffset: usize = 0;

            dest.resize(destOffset + length as usize, 0);

            readCount = self.src.read(&mut dest[destOffset..destOffset + length as usize])?;
            self.blockOffset += readCount;

            // 校验
            if self.checksums && !self.check_integrity(type_, &dest[destOffset..destOffset + readCount], checksum) {
                return err(StatusCode::Corruption, "Invalid Checksum");
            }

            destOffset += length as usize;

            if type_ == RecordType::Full as u8 {
                return Ok(destOffset);
            }

            if type_ == RecordType::First as u8 {
                continue;
            }

            if type_ == RecordType::Middle as u8 {
                continue;
            }

            if type_ == RecordType::Last as u8 {
                return Ok(destOffset);
            }
        }
    }

    fn check_integrity(&mut self, typ: u8, data: &[u8], expected: u32) -> bool {
        self.digest.reset();
        self.digest.write(&[typ]);
        self.digest.write(data);
        unmask_crc(expected) == self.digest.sum32()
    }
}

const MASK_DELTA: u32 = 0xa282ead8;

pub fn mask_crc(c: u32) -> u32 {
    (c.wrapping_shr(15) | c.wrapping_shl(17)).wrapping_add(MASK_DELTA)
}

pub fn unmask_crc(mc: u32) -> u32 {
    let rot = mc.wrapping_sub(MASK_DELTA);
    rot.wrapping_shr(17) | rot.wrapping_shl(15)
}
