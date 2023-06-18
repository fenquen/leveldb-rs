use integer_encoding::VarInt;

/// Contains an offset and a length (or size); can be efficiently encoded in to varints. This is
/// used typically as file-internal pointer in table (SSTable) files. For example, the index block
/// in an SSTable is a block of (key = largest key in block) -> (value = encoded blockhandle of block)
#[derive(Debug, Clone)]
pub struct BlockHandle {
    offset: usize,
    size: usize,
}

impl BlockHandle {
    /// Decodes a block handle from `from` and returns a block handle
    /// together with how many bytes were read from the slice.
    pub fn decode(from: &[u8]) -> Option<(BlockHandle, usize)> {
        let (off, offsize) = usize::decode_var(from)?;
        let (sz, szsize) = usize::decode_var(&from[offsize..])?;

        Some((
            BlockHandle {
                offset: off,
                size: sz,
            },
            offsize + szsize,
        ))
    }

    pub fn new(offset: usize, size: usize) -> BlockHandle {
        BlockHandle { offset, size }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns how many bytes were written, or 0 if the write failed because `dst` is too small.
    pub fn encode_to(&self, dst: &mut [u8]) -> usize {
        assert!(dst.len() >= self.offset.required_space() + self.size.required_space());

        let off = self.offset.encode_var(dst);
        off + self.size.encode_var(&mut dst[off..])
    }
}
