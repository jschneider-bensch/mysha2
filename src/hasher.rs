// As defined in FIPS 180-4.
const INITIAL_VALUES: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub struct Hasher {
    // The internal hash state; will be initialized per FIPS 180-4.
    state: [u32; 8],

    // Information needed to pad the input, thus finalizing the hash.
    // Number of bytes read, so far.
    num_bytes_read: usize,
    // Most recent sub-512-bit message chunk.
    latest_chunk: [u8; 64],
}

impl Hasher {
    /// Initialize a new SHA2-256 Hasher using the FIPS 180-4 specified values.
    pub fn new() -> Self {
        Self {
            state: INITIAL_VALUES.clone(),
            num_bytes_read: 0,
            latest_chunk: [0; 64],
        }
    }

    /// Update the internal state with the message contents.
    pub fn update<T: AsRef<[u8]>>(&mut self, message: &T) {
        unimplemented!()
    }

    /// Apply padding and run the final compression round, then return the
    /// internal state.
    pub fn finalize(&mut self) -> [u8; 32] {
        unimplemented!()
    }

    /// If the message is known in full from the beginning, compute the hash in
    /// one go.
    pub fn hash<T: AsRef<[u8]>>(message: &T) -> [u8; 32] {
        let mut fresh_hasher = Self::new();
        fresh_hasher.update(message);
        fresh_hasher.finalize()
    }
}
