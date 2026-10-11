use std::ops::Deref;

const PREFIX_BUFFER_COMPACT_THRESHOLD: usize = 1024;

#[derive(Clone, Debug, Default)]
pub struct PrefixBuffer {
    buf: Vec<u8>,
    head: usize,
}

impl PrefixBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a decoder input buffer while keeping its allocation available to
    /// the caller. When no bytes are buffered, swapping is safe because the
    /// prefix has no pending head or residual bytes; this transfers the input
    /// allocation without copying and returns the old allocation for reuse.
    /// A residual prefix must remain in this buffer, so that path copies the
    /// input and clears only its length.
    pub fn append_owned(&mut self, input: &mut Vec<u8>) {
        if input.is_empty() {
            return;
        }

        if self.head == self.buf.len() {
            self.clear();
            std::mem::swap(&mut self.buf, input);
            return;
        }

        self.maybe_compact_for_append(input.len());
        self.buf.extend_from_slice(input);
        input.clear();
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.maybe_compact_for_append(data.len());
        self.buf.extend_from_slice(data);
    }

    pub fn consume(&mut self, n: usize) {
        assert!(n <= self.len(), "consume beyond prefix buffer length");
        if n == 0 {
            return;
        }

        self.head += n;
        if self.head == self.buf.len() {
            self.clear();
        }
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.head = 0;
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.head..]
    }

    fn maybe_compact_for_append(&mut self, additional: usize) {
        if self.head == 0 {
            return;
        }

        let tail_capacity = self.buf.capacity().saturating_sub(self.buf.len());
        if tail_capacity < additional
            || (self.head >= PREFIX_BUFFER_COMPACT_THRESHOLD && self.head * 2 >= self.buf.len())
        {
            self.compact();
        }
    }

    fn compact(&mut self) {
        if self.head == 0 {
            return;
        }

        let remaining = self.len();
        self.buf.copy_within(self.head.., 0);
        self.buf.truncate(remaining);
        self.head = 0;
    }
}

impl From<Vec<u8>> for PrefixBuffer {
    fn from(buf: Vec<u8>) -> Self {
        Self { buf, head: 0 }
    }
}

impl Deref for PrefixBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[self.head..]
    }
}

#[cfg(test)]
mod tests {
    use super::PrefixBuffer;

    #[test]
    fn prefix_buffer_preserves_remaining_bytes_after_consume() {
        let mut buf = PrefixBuffer::new();
        buf.extend_from_slice(b"abcdef");
        buf.consume(2);
        assert_eq!(&*buf, b"cdef");

        buf.extend_from_slice(b"gh");
        assert_eq!(&*buf, b"cdefgh");
    }

    #[test]
    fn prefix_buffer_clears_when_fully_consumed() {
        let mut buf = PrefixBuffer::new();
        buf.extend_from_slice(b"hello");
        buf.consume(5);
        assert!(buf.is_empty());

        buf.extend_from_slice(b"world");
        assert_eq!(&*buf, b"world");
    }

    #[test]
    fn prefix_buffer_append_owned_reuses_empty_and_residual_allocations() {
        let mut buf = PrefixBuffer::from(Vec::with_capacity(8));
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(b"abcdef");
        let input_capacity = input.capacity();

        buf.append_owned(&mut input);
        assert_eq!(&*buf, b"abcdef");
        assert!(input.is_empty());
        assert_eq!(input.capacity(), 8);
        assert_eq!(buf.buf.capacity(), input_capacity);

        buf.consume(5);
        let mut next = Vec::with_capacity(32);
        next.extend_from_slice(b"gh");
        let next_capacity = next.capacity();
        buf.append_owned(&mut next);
        assert_eq!(&*buf, b"fgh");
        assert!(next.is_empty());
        assert_eq!(next.capacity(), next_capacity);
    }

    #[test]
    fn prefix_buffer_append_owned_does_not_swap_empty_input() {
        let mut buf = PrefixBuffer::from(Vec::with_capacity(8));
        let buf_capacity = buf.buf.capacity();
        let mut input = Vec::with_capacity(16);

        buf.append_owned(&mut input);

        assert!(buf.is_empty());
        assert_eq!(buf.buf.capacity(), buf_capacity);
        assert_eq!(input.capacity(), 16);
    }
}
