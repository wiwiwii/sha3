// State is 5x5x64 -> represent as [u64; 25]
pub type State = [u64; 25];

fn compute_parities(state: &State, x: usize) -> u64 {
    let mut res = 0;
    for y in 0..5 {
        res ^= state[x + 5 * y];
    }
    res
}

pub fn theta(state: &mut State) {
    let mut parities = [0u64; 5];
    #[allow(clippy::needless_range_loop)]
    for x in 0..5 {
        parities[x] = compute_parities(state, x);
    }
    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] ^= parities[(x + 4) % 5] ^ parities[(x + 1) % 5].rotate_left(1)
        }
    }
}

const OFFSETS: [u32; 25] = [
    0, 1, 190, 28, 91, 36, 300, 6, 55, 276, 3, 10, 171, 153, 231, 105, 45, 15, 21, 136, 210, 66,
    253, 120, 78,
];

pub fn rho(state: &mut State) {
    for i in 0..25 {
        state[i] = state[i].rotate_left(OFFSETS[i] % 64);
    }
}

pub fn pi(state: &mut State) {
    let mut tmp: State = [0u64; 25]; // Possible optimization: permutation in place
    for x in 0..5 {
        for y in 0..5 {
            tmp[x + 5 * y] = state[((x + 3 * y) % 5) + 5 * x];
        }
    }
    *state = tmp;
}

pub fn chi(state: &mut State) {
    let mut tmp: State = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            tmp[x + 5 * y] = state[x + 5 * y]
                ^ ((state[((x+1) % 5) + 5*y] ^ u64::MAX) // 1^64
                                            & state[((x+2) % 5) + 5*y])
        }
    }
    *state = tmp;
}

fn rc(t: usize) -> u64 {
    if t % 255 == 0 {
        return 1;
    }
    let mut r: u8 = 0b10000000;
    for _ in 1..((t % 255) + 1) {
        let tmp = r % 2;
        r >>= 1;
        r ^= tmp << 7 | tmp << 3 | tmp << 2 | tmp << 1;
    }
    (r >> 7).into()
}

pub fn iota(state: &mut State, ir: usize) {
    let mut round_constant = 0u64; // 0^w with w = 64
    for j in 0..7 {
        // j is in [0,l] with l = log_2(w) = 6
        round_constant |= rc(j + 7 * ir) << ((1 << j) - 1);
    }
    state[0] ^= round_constant
}
