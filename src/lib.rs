use std::{
    fs,
    io::{BufReader, Read},
};

use step_mappings::{State, chi, iota, pi, rho, theta};

pub mod step_mappings;

fn round(state: &mut State, ir: usize) {
    theta(state);
    rho(state);
    pi(state);
    chi(state);
    iota(state, ir);
}

fn keccak_f_1600(state: &mut State) {
    for ir in 0..24 {
        round(state, ir);
    }
}

#[derive(Clone, Copy)]
enum DigestSize {
    SHA3_224 = 28,
    SHA3_256 = 32,
    SHA3_384 = 48,
    SHA3_512 = 64,
}

fn sha3(input: &[u8], d: DigestSize) -> Vec<u8> {
    // Could optimize with fixed length arrays
    // d in bytes
    let c = 2 * (d as usize);
    let rate = 200 - c; //For SHA3 we only use b = 1600
    let n = (input.len() / rate) + 1;
    let mut state: State = [0u64; 25];
    let mut buffer = [0u8; 8];
    for i in 0..(n - 1) {
        let chunk = &input[i * rate..(i + 1) * rate];
        for j in 0..(rate / 8) {
            buffer.copy_from_slice(&chunk[j * 8..(j + 1) * 8]);
            let lane = u64::from_le_bytes(buffer);

            state[j] ^= lane;
        }
        keccak_f_1600(&mut state);
    }
    let final_chunk = &input[(n - 1) * rate..];
    let mut last_block = vec![0; rate];
    let last_length = final_chunk.len();
    last_block[0..last_length].copy_from_slice(final_chunk);

    last_block[last_length] ^= 0x06;
    last_block[rate - 1] ^= 0x80;
    for j in 0..(rate / 8) {
        buffer.copy_from_slice(&last_block[j * 8..(j + 1) * 8]);
        let lane = u64::from_le_bytes(buffer);
        state[j] ^= lane;
    }
    keccak_f_1600(&mut state);
    let mut z: Vec<u8> = Vec::new();
    for squeezed in state[0..(rate / 8)].iter() {
        for byte in squeezed.to_le_bytes().iter() {
            z.push(*byte);
        }
    }
    // What follows is not needed for SHA3: rate is always >= d
    // while z.len() < d {
    //     index += 1;
    //     keccak_f_1600(&mut state);
    //     let squeezed = state[index];
    //     for byte in squeezed.to_le_bytes().iter() {
    //         z.push(*byte);
    //     }
    // }
    z[0..(d as usize)].into()
}

// For ease of use, different SHA3 versions with hex string output
pub fn sha3_224(input: &[u8]) -> String {
    hex::encode(sha3(input, DigestSize::SHA3_224))
}

pub fn sha3_256(input: &[u8]) -> String {
    hex::encode(sha3(input, DigestSize::SHA3_256))
}

pub fn sha3_384(input: &[u8]) -> String {
    hex::encode(sha3(input, DigestSize::SHA3_384))
}

pub fn sha3_512(input: &[u8]) -> String {
    hex::encode(sha3(input, DigestSize::SHA3_512))
}

struct Sha3Hasher<const RATE: usize, const SIZE: usize> {
    state: State,
}
impl<const RATE: usize, const SIZE: usize> Sha3Hasher<RATE, SIZE> {
    pub fn new() -> Self {
        Self { state: [0u64; 25] }
    }
    fn absorb(&mut self, input: &[u8; RATE]) {
        let mut buffer = [0u8; 8];
        for j in 0..(RATE / 8) {
            buffer.copy_from_slice(&input[j * 8..(j + 1) * 8]);
            let lane = u64::from_le_bytes(buffer);

            self.state[j] ^= lane;
        }
        keccak_f_1600(&mut self.state);
    }
    fn squeeze(&mut self, input: &[u8]) -> [u8; SIZE] {
        let mut buffer = [0u8; 8];

        let mut last_block = [0u8; RATE];
        let last_length = input.len();
        last_block[0..last_length].copy_from_slice(input);

        last_block[last_length] ^= 0x06;
        last_block[RATE - 1] ^= 0x80;
        for j in 0..(RATE / 8) {
            buffer.copy_from_slice(&last_block[j * 8..(j + 1) * 8]);
            let lane = u64::from_le_bytes(buffer);
            self.state[j] ^= lane;
        }
        keccak_f_1600(&mut self.state);
        let mut z: Vec<u8> = Vec::new();
        for squeezed in self.state[0..(RATE / 8)].iter() {
            for byte in squeezed.to_le_bytes().iter() {
                z.push(*byte);
            }
        }
        let mut res = [0u8; SIZE];
        res.copy_from_slice(&z[0..SIZE]);
        res
    }
}

pub fn hash_file(file: String) -> String {
    // This is for SHA3_256: RATE = 136, SIZE = 32
    let mut have = 0;
    let data = fs::File::open(file).unwrap();
    let mut buf_reader = BufReader::new(data);
    let mut buffer = [0u8; 136];
    let mut hasher: Sha3Hasher<136, 32> = Sha3Hasher::new();
    loop {
        let n = buf_reader.read(&mut buffer[have..]).unwrap();
        have += n;
        if n == 0 {
            break;
        }
        if have < 136 {
            continue;
        } else {
            have = 0;
            hasher.absorb(&buffer)
        }
    }
    hex::encode(hasher.squeeze(&buffer[0..have]))
}

#[cfg(test)]
mod validate_nist_test_vectors;
#[cfg(test)]
mod tests {

    use crate::{
        hash_file,
        validate_nist_test_vectors::{
            validate_224_long, validate_224_short, validate_256_long, validate_256_short,
            validate_384_long, validate_384_short, validate_512_long, validate_512_short,
        },
    };
    #[test]
    fn test_sha3_224() {
        validate_224_short();
        validate_224_long();
    }
    #[test]
    fn test_sha3_256() {
        validate_256_short();
        validate_256_long();
    }
    #[test]
    fn test_sha3_384() {
        validate_384_short();
        validate_384_long();
    }
    #[test]
    fn test_sha3_512() {
        validate_512_short();
        validate_512_long();
    }
    #[test]
    fn test_file() {
        let file = "Cargo.toml"; // Change to whatever file.
        assert_eq!(
            "4eb5088c0d702a5eac6b5f347c520a8e1365d579bd296425ea4927d180f3f8a4",
            // Change to hash computed from other implementation
            hash_file(file.into())
        );
    }
}
