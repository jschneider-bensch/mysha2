use hex::{decode, encode};
use nom::{
    bytes::complete::tag,
    character::complete::{digit1, hex_digit1, line_ending},
    combinator::map_res,
    multi::many1,
    sequence::{delimited, terminated},
    IResult,
};

use std::str::FromStr;

fn len_line(s: &str) -> IResult<&str, usize> {
    delimited(
        tag("Len = "),
        map_res(many1(digit1), |s: Vec<&str>| usize::from_str(&s.concat())),
        line_ending,
    )(s)
}

fn msg_line(s: &str) -> IResult<&str, Vec<u8>> {
    delimited(
        tag("Msg = "),
        map_res(many1(hex_digit1), |s: Vec<&str>| decode(&s.concat())),
        line_ending,
    )(s)
}

fn md_line(s: &str) -> IResult<&str, Vec<u8>> {
    delimited(
        tag("MD = "),
        map_res(many1(hex_digit1), |s: Vec<&str>| decode(&s.concat())),
        line_ending,
    )(s)
}

fn vector_lines(s: &str) -> IResult<&str, TestVector> {
    let (s, len) = len_line(s)?;
    let (s, msg) = msg_line(s)?;
    let (s, md) = md_line(s)?;

    // confusingly the zero-length message is given as '00'
    if len != 0 {
        assert_eq!(msg.len() * 8, len);
    }

    assert_eq!(md.len(), 32);

    let mut vector = TestVector { msg: msg, md: md };
    if len == 0 {
        vector.msg = vec![];
    }
    Ok((s, vector))
}

fn digest_len_line(s: &str) -> IResult<&str, usize> {
    terminated(
        delimited(
            tag("[L = "),
            map_res(many1(digit1), |s: Vec<&str>| usize::from_str(&s.concat())),
            tag("]"),
        ),
        line_ending,
    )(s)
}

fn comment_line(s: &str) -> IResult<&str, &str> {
    use nom::character::complete::not_line_ending;
    delimited(tag("#"), not_line_ending, line_ending)(s)
}

#[derive(Debug, PartialEq)]
struct TestVector {
    msg: Vec<u8>,
    md: Vec<u8>,
}

impl TestVector {
    fn parse(input_file: &str) -> IResult<&str, Vec<Self>> {
        let (s, _) = many1(comment_line)(input_file)?;
        let (s, _) = line_ending(s)?;
        let (s, digest_len) = digest_len_line(s)?;
        let (s, _) = line_ending(s)?;
        let (s, vector_list) = many1(terminated(vector_lines, line_ending))(s)?;

        assert_eq!(32, digest_len);
        assert!(s.is_empty());

        Ok((s, vector_list))
    }
}

#[cfg(test)]
mod test_nist {
    use super::*;

    #[test]
    fn test_num_vectors_line() {
        assert_eq!(digest_len_line("[L = 4]\n").unwrap().1, 4);
        assert_eq!(digest_len_line("[L = 32]\n").unwrap().1, 32);
    }

    #[test]
    fn test_len_line() {
        assert_eq!(len_line("Len = 0\n").unwrap().1, 0);
        assert_eq!(len_line("Len = 8\n").unwrap().1, 8);
        assert_eq!(len_line("Len = 324\n").unwrap().1, 324);
    }

    #[test]
    fn test_msg_line() {
        assert_eq!(msg_line("Msg = d3\n").unwrap().1, vec![0xd3]);
        assert_eq!(msg_line("Msg = 11af\n").unwrap().1, vec![0x11, 0xaf]);
    }

    #[test]
    fn test_md_line() {
        assert_eq!(
            md_line("MD = 3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2\n")
                .unwrap()
                .1,
            decode("3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2").unwrap()
        );
    }

    #[test]
    fn test_parse_vector() {
        let text = "Len = 1304
Msg = 451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae086b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b85c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480858bec
MD = 3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2\n";

        assert_eq!(vector_lines(&text).unwrap().1, TestVector{msg: decode("451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae086b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b85c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480858bec").unwrap(), md: decode("3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2").unwrap()})
    }

    #[test]
    fn nist_vectors_short() {
        use mysha2::hasher::Hasher;

        let vector_file = include_str!("data/SHA256ShortMsg.rsp");
        let vectors = TestVector::parse(vector_file)
            .expect("Malformed Vector file?")
            .1;

        for v in vectors {
            let hash = Hasher::hash(&v.msg);
            assert_eq!(
                hash[..],
                v.md,
                "\nExpected:\t{}\nGot:\t\t{}\n",
                encode(&v.md),
                encode(&hash)
            );
        }
    }

    #[test]
    fn nist_vectors_long() {
        use mysha2::hasher::Hasher;

        let vector_file = include_str!("data/SHA256LongMsg.rsp");
        let vectors = TestVector::parse(vector_file)
            .expect("Malformed Vector file?")
            .1;

        for v in vectors {
            let hash = Hasher::hash(&v.msg);
            assert_eq!(
                hash[..],
                v.md,
                "\nExpected:\t{}\nGot:\t\t{}\n",
                encode(&v.md),
                encode(&hash)
            );
        }
    }
}
