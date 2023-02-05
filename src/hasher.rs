// As defined in FIPS 180-4.
const INITIAL_VALUES: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Hasher {
    // The internal hash state; will be initialized per FIPS 180-4.
    state: [u32; 8],

    // Information needed to pad the input, thus finalizing the hash.
    // Number of bytes read, so far.
    num_bytes_read: usize,
    // Most recent sub-512-bit message block.
    working_block: Vec<u8>,
}

impl Hasher {
    /// Initialize a new SHA2-256 Hasher using the FIPS 180-4 specified values.
    pub fn new() -> Self {
        Self {
            state: INITIAL_VALUES.clone(),
            num_bytes_read: 0,
            working_block: vec![],
        }
    }

    /// Update the internal state with the message contents.
    pub fn update<T: AsRef<[u8]>>(&mut self, message: &T) {
        // Chunk message into 512-bit blocks and run the compression with each.
        let mut msg_iter = message.as_ref().iter();

        while self.working_block.len() < 64 {
            match msg_iter.next() {
                Some(byte) => {
                    self.working_block.append(&mut vec![*byte]);
                    self.num_bytes_read += 1;
                }
                None => {
                    return;
                }
            }
        }

        // now we have filled up the latest message block.
        while self.working_block.len() == 64 {
            self.compress();
            while self.working_block.len() < 64 {
                match msg_iter.next() {
                    Some(byte) => {
                        self.working_block.append(&mut vec![*byte]);
                        self.num_bytes_read += 1;
                    }
                    None => {
                        return;
                    }
                }
            }
        }
    }

    /// Apply padding and run the final compression round, then return the
    /// internal state.
    pub fn finalize(&mut self) -> Vec<u8> {
        use byteorder::{BigEndian, WriteBytesExt};

        self.apply_padding();

        // Do a final compression.
        self.compress();
        let mut out = Vec::new();
        for byte in self.state {
            out.write_u32::<BigEndian>(byte).unwrap();
        }
        out
    }

    /// If the message is known in full from the beginning, compute the hash in
    /// one go.
    pub fn hash<T: AsRef<[u8]>>(message: &T) -> Vec<u8> {
        let mut fresh_hasher = Self::new();
        fresh_hasher.update(message);
        fresh_hasher.finalize()
    }

    fn apply_padding(&mut self) {
        use byteorder::{BigEndian, WriteBytesExt};

        let msg_length = (self.num_bytes_read * 8) as u64;
        assert!(self.working_block.len() <= 63);

        // append 1-bit (+7 0-bits)
        self.working_block.append(&mut vec![1u8 << 7]);

        if self.working_block.len() > 56 {
            // We need 8 bytes in the chunk to write out the length.
            // If appending the 1-bit has resulted in less than 8 bytes
            // remaining in the chunk, we have to padd this chunk with 0-bits,
            // compress and encode the length in the next chunk.

            self.working_block
                .append(&mut vec![0; 64 - self.working_block.len()]);

            self.compress();
        }

        self.working_block
            .append(&mut vec![0; 64 - self.working_block.len() - 8]);

        let mut length_bytes = Vec::new();
        length_bytes.write_u64::<BigEndian>(msg_length).unwrap();

        self.working_block.append(&mut length_bytes);
    }

    fn compress(&mut self) {
        // Combine the current hash state with the full message chunk. Reset
        // message chunk.
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        let w = self.message_schedule();
        // println!(
        //        "init:\t a: {:08x}\t b: {:08x}\t c: {:08x}\t d: {:08x}\t e: {:08x}\t f: {:08x}\t g: {:08x}\t h: {:08x}",
        //         a, b, c, d, e, f, g, h
        //    );

        for j in 0..=63 {
            let ch_res = self.ch(e, f, g);
            let maj_res = self.maj(a, b, c);
            let sigma0_res = self.sigma0(a);
            let sigma1_res = self.sigma1(e);

            let t1 = h
                .wrapping_add(sigma1_res)
                .wrapping_add(ch_res)
                .wrapping_add(K[j])
                .wrapping_add(w[j]);
            let t2 = sigma0_res.wrapping_add(maj_res);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);

            self.working_block.clear();
            // println!(
            //    "j: {}\t a: {:08x}\t b: {:08x}\t c: {:08x}\t d: {:08x}\t e: {:08x}\t f: {:08x}\t g: {:08x}\t h: {:08x}",
            //    j, a, b, c, d, e, f, g, h
            //);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn ch(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn maj(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn sigma0(&self, x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    fn sigma1(&self, x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    fn subsigma_0(&self, x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    fn subsigma_1(&self, x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn message_schedule(&self) -> [u32; 64] {
        use byteorder::{BigEndian, ReadBytesExt};
        let mut w = [0; 64];
        for j in 0..16 {
            // fill first 16 words with the message buffer
            w[j] = self
                .working_block
                .as_slice()
                .get(j * 4..(j + 1) * 4)
                .unwrap()
                .read_u32::<BigEndian>()
                .unwrap();
        }

        for j in 16..64 {
            w[j] = self
                .subsigma_1(w[j - 2])
                .wrapping_add(w[j - 7])
                .wrapping_add(self.subsigma_0(w[j - 15]))
                .wrapping_add(w[j - 16]);
        }
        w
    }
}
