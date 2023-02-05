struct TestVector {
    msg: Vec<u8>,
    md: [u8; 32],
}

impl TestVector {
    fn parse(input_file: &str) -> Vec<Self> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test_nist {
    use super::*;

    #[test]
    fn nist_vectors_short() {
        use mysha2::hasher::Hasher;

        let vector_file = include_str!("data/SHA256ShortMsg.rsp");
        let vectors = TestVector::parse(vector_file);

        for v in vectors {
            assert_eq!(Hasher::hash(&v.msg), v.md);
        }
    }

    #[test]
    fn nist_vectors_long() {
        use mysha2::hasher::Hasher;

        let vector_file = include_str!("data/SHA256LongMsg.rsp");
        let vectors = TestVector::parse(vector_file);

        for v in vectors {
            assert_eq!(Hasher::hash(&v.msg), v.md);
        }
    }
}
