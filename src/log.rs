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
const HEADER_SIZE: usize = 4 + 2 + 1;

#[derive(Clone, Copy)]
pub enum RecordType {
    Full = 1,
    First = 2,
    Middle = 3,
    Last = 4,
}

pub struct LogWriter<W: Write> {
    dst: W,
    digest: crc32::Digest,
    current_block_offset: usize,
    block_size: usize,
}

impl<W: Write> LogWriter<W> {
    pub fn new(writer: W) -> LogWriter<W> {
        let digest = crc32::Digest::new(crc32::CASTAGNOLI);
        LogWriter {
            dst: writer,
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

    pub fn add_record(&mut self, r: &[u8]) -> Result<usize> {
        let mut record = &r[..];
        let mut first_frag = true;
        let mut result = Ok(0);
        while result.is_ok() && !record.is_empty() {
            assert!(self.block_size > HEADER_SIZE);

            let space_left = self.block_size - self.current_block_offset;

            // Fill up block; go to next block.
            if space_left < HEADER_SIZE {
                self.dst.write_all(&vec![0, 0, 0, 0, 0, 0][0..space_left])?;
                self.current_block_offset = 0;
            }

            let avail_for_data = self.block_size - self.current_block_offset - HEADER_SIZE;

            let data_frag_len = if record.len() < avail_for_data {
                record.len()
            } else {
                avail_for_data
            };

            let recordtype;

            if first_frag && data_frag_len == record.len() {
                recordtype = RecordType::Full;
            } else if first_frag {
                recordtype = RecordType::First;
            } else if data_frag_len == record.len() {
                recordtype = RecordType::Last;
            } else {
                recordtype = RecordType::Middle;
            }

            result = self.emit_record(recordtype, record, data_frag_len);
            record = &record[data_frag_len..];
            first_frag = false;
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
        s += self.dst.write(&chksum.encode_fixed_vec())?;
        s += self.dst.write_fixedint(len as u16)?;
        s += self.dst.write(&[t as u8])?;
        s += self.dst.write(&data[0..len])?;

        self.current_block_offset += s;
        Ok(s)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.dst.flush()?;
        Ok(())
    }
}

pub struct LogReader<R: Read> {
    // TODO: Wrap src in a buffer to enhance read performance.
    src: R,
    digest: crc32::Digest,
    blk_off: usize,
    blocksize: usize,
    head_scratch: [u8; HEADER_SIZE],
    checksums: bool,
}

impl<R: Read> LogReader<R> {
    pub fn new(src: R, checksum: bool) -> LogReader<R> {
        LogReader {
            src,
            blk_off: 0,
            blocksize: BLOCK_SIZE,
            checksums: checksum,
            head_scratch: [0; 7],
            digest: crc32::Digest::new(crc32::CASTAGNOLI),
        }
    }

    /// EOF is signalled by Ok(0)
    pub fn read(&mut self, dest: &mut Vec<u8>) -> Result<usize> {
        dest.clear();

        loop {
            if self.blocksize - self.blk_off < HEADER_SIZE {
                // skip to next block
                self.src.read_exact(&mut self.head_scratch[0..self.blocksize - self.blk_off])?;
                self.blk_off = 0;
            }

            let mut bytes_read = self.src.read(&mut self.head_scratch)?;

            // EOF
            if bytes_read == 0 {
                return Ok(0);
            }

            self.blk_off += bytes_read;

            let mut checksum = u32::decode_fixed(&self.head_scratch[0..4]);
            let mut length = u16::decode_fixed(&self.head_scratch[4..6]);
            let mut typ = self.head_scratch[6];

            let mut dst_offset: usize = 0;

            dest.resize(dst_offset + length as usize, 0);
            bytes_read = self.src.read(&mut dest[dst_offset..dst_offset + length as usize])?;
            self.blk_off += bytes_read;

            if self.checksums && !self.check_integrity(typ, &dest[dst_offset..dst_offset + bytes_read], checksum) {
                return err(StatusCode::Corruption, "Invalid Checksum");
            }

            dst_offset += length as usize;

            if typ == RecordType::Full as u8 {
                return Ok(dst_offset);
            }

            if typ == RecordType::First as u8 {
                continue;
            }

            if typ == RecordType::Middle as u8 {
                continue;
            }

            if typ == RecordType::Last as u8 {
                return Ok(dst_offset);
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
