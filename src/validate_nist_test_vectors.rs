use std::fs;

use crate::{sha3_224, sha3_256, sha3_384, sha3_512};

pub fn validate_224_short() {
    validate_vectors("test_vectors/SHA3_224ShortMsg.rsp", &sha3_224);
}
pub fn validate_256_short() {
    validate_vectors("test_vectors/SHA3_256ShortMsg.rsp", &sha3_256);
}
pub fn validate_384_short() {
    validate_vectors("test_vectors/SHA3_384ShortMsg.rsp", &sha3_384);
}
pub fn validate_512_short() {
    validate_vectors("test_vectors/SHA3_512ShortMsg.rsp", &sha3_512);
}

pub fn validate_224_long() {
    validate_vectors("test_vectors/SHA3_224LongMsg.rsp", &sha3_224);
}
pub fn validate_256_long() {
    validate_vectors("test_vectors/SHA3_256LongMsg.rsp", &sha3_256);
}
pub fn validate_384_long() {
    validate_vectors("test_vectors/SHA3_384LongMsg.rsp", &sha3_384);
}
pub fn validate_512_long() {
    validate_vectors("test_vectors/SHA3_512LongMsg.rsp", &sha3_512);
}

fn validate_vectors(file: &str, sha_version: &dyn Fn(&[u8]) -> String) {
    let text = fs::read_to_string(file).unwrap();
    let mut iterator = text.lines().filter(|line| line.contains("="));
    iterator.next(); // This removes the first "=" which is the digest size
    while let (Some(len), Some(msg), Some(md)) = (iterator.next(), iterator.next(), iterator.next())
    {
        let len: usize = len.split('=').nth(1).unwrap().trim().parse().unwrap();
        let msg = msg.split('=').nth(1).unwrap().trim();
        let md = md.split('=').nth(1).unwrap().trim();
        let input = if len == 0 {
            vec![]
        } else {
            hex::decode(msg).unwrap()
        };
        assert_eq!(sha_version(&input), md);
    }
}
