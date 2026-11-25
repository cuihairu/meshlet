//! Minimal QR encoder: byte mode, ECC level L, versions 1-10, 8 masks with the lowest penalty score.
//!
//! Purpose: render an `otpauth://` TOTP URI as a scannable QR code (imported by an authenticator via scan).
//! The matrix encodes only the input bytes themselves — **it carries no secret beyond the key** (the URI is
//! produced by [crate::totp::otpauth_uri], which contains only the base32 key).
//!
//! Verification: the tests decode the bytes back with the independent third-party decoder `rqrr` and assert
//! they match the input (end-to-end round trip, without depending on any QR generation library).

use core::fmt;

/// ECC level L (largest capacity; the error-correction tolerance of L is sufficient for QR scanners).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcLevel {
    L,
}

impl EcLevel {
    /// The ECC level bits in the 2-bit format info: L = `01`.
    fn format_bits(self) -> u32 {
        match self {
            EcLevel::L => 0b01,
        }
    }
}

/// An encoded QR matrix (no quiet zone; the front end adds whitespace as needed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    /// Side length (module count), `size = 17 + 4 * version`.
    pub size: usize,
    /// `dark[y][x]` ∈ {0,1}, with (0,0) as the top-left.
    pub dark: Vec<Vec<u8>>,
}

/// Encoding error: the input exceeds the capacity of versions 1-10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrError;

impl fmt::Display for QrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("data too long for QR versions 1-10")
    }
}

/// The capacity and block structure of one version (ECC L).
struct VersionInfo {
    /// Total number of data codewords.
    data: usize,
    /// Number of ECC codewords per block.
    ecc: usize,
    /// Blocks: `(block count, data codewords per block)`; laid over the `data` codewords in order.
    blocks: &'static [(usize, usize)],
}

/// Block table for ECC L versions 1-10 (ISO/IEC 18004).
const VERSIONS: [VersionInfo; 10] = [
    VersionInfo {
        data: 19,
        ecc: 7,
        blocks: &[(1, 19)],
    },
    VersionInfo {
        data: 34,
        ecc: 10,
        blocks: &[(1, 34)],
    },
    VersionInfo {
        data: 55,
        ecc: 15,
        blocks: &[(1, 55)],
    },
    VersionInfo {
        data: 80,
        ecc: 20,
        blocks: &[(1, 80)],
    },
    VersionInfo {
        data: 108,
        ecc: 26,
        blocks: &[(1, 108)],
    },
    VersionInfo {
        data: 136,
        ecc: 18,
        blocks: &[(2, 68)],
    },
    VersionInfo {
        data: 156,
        ecc: 20,
        blocks: &[(2, 78)],
    },
    VersionInfo {
        data: 194,
        ecc: 24,
        blocks: &[(2, 97)],
    },
    VersionInfo {
        data: 232,
        ecc: 30,
        blocks: &[(2, 116)],
    },
    VersionInfo {
        data: 274,
        ecc: 18,
        blocks: &[(2, 68), (2, 69)],
    },
];

/// Alignment-pattern center coordinates per version (ISO/IEC 18004), index `version - 1`.
/// Version 1 has no alignment pattern. The leading/trailing (6, …) and (…, 6) entries must skip corner overlaps when drawn.
const ALIGN_POS: [&[usize]; 10] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
];

/// Handwritten GF(256) (primitive polynomial x^8+x^4+x^3+x^2+1 = 0x11D).
struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for (i, e) in exp[..255].iter_mut().enumerate() {
            *e = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        // exp is double-length to avoid index out-of-bounds (still safe after mod 255 in the multiplication).
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
    }
}

/// Generate the RS check-polynomial coefficients (degree = number of ecc codewords).
fn rs_generator_poly(gf: &Gf, degree: usize) -> Vec<u8> {
    let mut poly = vec![1u8];
    for i in 0..degree {
        // Multiply by (x - α^i); subtraction in GF(256) is XOR.
        let factor = gf.exp[i];
        let mut next = vec![0u8; poly.len() + 1];
        for (j, &p) in poly.iter().enumerate() {
            next[j] ^= p;
            next[j + 1] ^= gf.mul(p, factor);
        }
        poly = next;
    }
    poly
}

/// Compute the ECC codewords (the remainder).
fn rs_ecc(gf: &Gf, data: &[u8], degree: usize) -> Vec<u8> {
    let gen = rs_generator_poly(gf, degree);
    let mut rem = vec![0u8; degree];
    for &byte in data {
        let factor = byte ^ rem[0];
        rem.remove(0);
        rem.push(0);
        for (i, &g) in gen.iter().skip(1).enumerate() {
            rem[i] ^= gf.mul(g, factor);
        }
    }
    rem
}

/// Bit buffer (MSB first).
struct Bits {
    bytes: Vec<u8>,
    len: usize,
}

impl Bits {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            len: 0,
        }
    }

    fn push(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            let bit = (value >> i) & 1;
            if self.len.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if bit == 1 {
                let idx = self.len / 8;
                self.bytes[idx] |= 1 << (7 - (self.len % 8));
            }
            self.len += 1;
        }
    }
}

/// Byte-mode codeword generation + ECC + interleaving.
fn build_codewords(data: &[u8], version: usize) -> Vec<u8> {
    let info = &VERSIONS[version - 1];
    let mut bits = Bits::new();
    // byte mode: 0100 + the character count (8 bits for v1-9, 16 bits for v10+).
    bits.push(0b0100, 4);
    let count_bits = if version <= 9 { 8 } else { 16 };
    bits.push(data.len() as u32, count_bits);
    for &b in data {
        bits.push(b as u32, 8);
    }
    // Terminator (at most 4 zero bits) → pad up to the byte boundary → fill with 0xEC/0x11.
    bits.push(0, (4 - bits.len % 4) % 4);
    if !bits.len.is_multiple_of(8) {
        bits.push(0, 8 - bits.len % 8);
    }
    let mut codewords = bits.bytes.clone();
    let mut pad_toggle = false;
    while codewords.len() < info.data {
        codewords.push(if pad_toggle { 0x11 } else { 0xEC });
        pad_toggle = !pad_toggle;
    }

    // Split into blocks → per-block ECC → interleave.
    let gf = Gf::new();
    let mut data_blocks: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0;
    for &(count, per) in info.blocks {
        for _ in 0..count {
            data_blocks.push(codewords[offset..offset + per].to_vec());
            offset += per;
        }
    }
    let ecc_blocks: Vec<Vec<u8>> = data_blocks
        .iter()
        .map(|b| rs_ecc(&gf, b, info.ecc))
        .collect();

    let mut out = Vec::new();
    let max_data = data_blocks.iter().map(Vec::len).max().unwrap_or(0);
    for i in 0..max_data {
        for b in &data_blocks {
            if i < b.len() {
                out.push(b[i]);
            }
        }
    }
    for i in 0..info.ecc {
        for b in &ecc_blocks {
            out.push(b[i]);
        }
    }
    out
}

/// BCH(15,5): generator polynomial 0x537.
fn bch_format(data: u32) -> u32 {
    let mut rem = data << 10;
    for shift in (0..=10).rev() {
        if rem & (1 << (shift + 10)) != 0 {
            rem ^= 0x537 << shift;
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

/// BCH(18,6): generator polynomial 0x1F25.
fn bch_version(version: usize) -> u32 {
    let data = version as u32;
    let mut rem = data << 12;
    for shift in (0..=12).rev() {
        if rem & (1 << (shift + 12)) != 0 {
            rem ^= 0x1f25 << shift;
        }
    }
    (data << 12) | rem
}

/// Draw the function patterns and mark the function regions (including format-info/version-info/dark-module placeholders).
fn draw_function_patterns(dark: &mut [Vec<u8>], function: &mut [Vec<bool>], version: usize) {
    let size = dark.len();

    // 7×7 finder patterns at the three corners + a separator ring (a 9×9 area centered on each pattern, white at
    // dist=2, white separator ring at dist=4, dark elsewhere; out-of-bounds cells are skipped).
    let draw_finder = |dark: &mut [Vec<u8>], function: &mut [Vec<bool>], cy: usize, cx: usize| {
        for dy in -4i64..=4 {
            for dx in -4i64..=4 {
                let y = cy as i64 + dy;
                let x = cx as i64 + dx;
                if !(0..size as i64).contains(&y) || !(0..size as i64).contains(&x) {
                    continue;
                }
                let (y, x) = (y as usize, x as usize);
                let dist = dy.unsigned_abs().max(dx.unsigned_abs()) as usize;
                function[y][x] = true;
                dark[y][x] = if dist != 2 && dist != 4 { 1 } else { 0 };
            }
        }
    };
    draw_finder(dark, function, 3, 3);
    draw_finder(dark, function, 3, size - 4);
    draw_finder(dark, function, size - 4, 3);

    // Timing patterns (row/column 6).
    for i in 8..size - 8 {
        let v = if i % 2 == 0 { 1 } else { 0 };
        dark[6][i] = v;
        dark[i][6] = v;
        function[6][i] = true;
        function[i][6] = true;
    }

    // Alignment patterns (5×5, skipping the corners that overlap finder patterns).
    let pos = ALIGN_POS[version - 1];
    for &cy in pos {
        for &cx in pos {
            let corner = (cy == 6 && cx == 6)
                || (cy == 6 && cx == *pos.last().unwrap_or(&0))
                || (cx == 6 && cy == *pos.last().unwrap_or(&0));
            if corner {
                continue;
            }
            for dy in 0..5usize {
                for dx in 0..5usize {
                    let y = cy - 2 + dy;
                    let x = cx - 2 + dx;
                    if y >= size || x >= size {
                        continue;
                    }
                    function[y][x] = true;
                    let border = dy == 0 || dy == 4 || dx == 0 || dx == 4;
                    let center = dy == 2 && dx == 2;
                    dark[y][x] = if border || center { 1 } else { 0 };
                }
            }
        }
    }

    // Version info (v≥7, two 3×6 blocks).
    if version >= 7 {
        let info = bch_version(version);
        for i in 0..18usize {
            let bit = ((info >> i) & 1) as u8;
            let x1 = size - 11 + i % 3;
            let y1 = i / 3;
            dark[y1][x1] = bit;
            function[y1][x1] = true;
            let y2 = size - 11 + i % 3;
            let x2 = i / 3;
            dark[y2][x2] = bit;
            function[y2][x2] = true;
        }
    }

    // Dark module.
    let dark_y = 4 * version + 9;
    dark[dark_y][8] = 1;
    function[dark_y][8] = true;

    // Reserve placeholders for both format-info copies (15 modules each); the actual values are written later based on the chosen mask.
    let fmt_cells = format_cells(size);
    for (y, x) in fmt_cells {
        function[y][x] = true;
    }
}

/// Both format-info copies, 30 modules total ((row,col)), bit 0 being the LSB and both copies in the same order:
/// - The first winds around the top-left corner: bit 0..=5 at (0..=5, 8), 6→(7,8), 7→(8,8), 8→(8,7),
///   9..=14 at (8, 5..=0);
/// - The second winds around the bottom-right: bit 0..=7 at (8, size-1..=size-8), 8..=14 at (size-7..=size-1, 8).
fn format_cells(size: usize) -> Vec<(usize, usize)> {
    let mut cells = Vec::with_capacity(30);
    let first: [(usize, usize); 15] = [
        (0, 8),
        (1, 8),
        (2, 8),
        (3, 8),
        (4, 8),
        (5, 8),
        (7, 8),
        (8, 8),
        (8, 7),
        (8, 5),
        (8, 4),
        (8, 3),
        (8, 2),
        (8, 1),
        (8, 0),
    ];
    for &(y, x) in &first {
        cells.push((y, x));
    }
    for i in 0..8usize {
        cells.push((8, size - 1 - i));
    }
    for i in 8..15usize {
        cells.push((size - 15 + i, 8));
    }
    cells
}

/// Write the format info (both copies identical, bit 0 as the LSB).
fn write_format(dark: &mut [Vec<u8>], size: usize, ecc: EcLevel, mask: usize) {
    let value = bch_format((ecc.format_bits() << 3) | mask as u32);
    let cells = format_cells(size);
    for (i, &(y, x)) in cells.iter().enumerate() {
        dark[y][x] = ((value >> i) & 1) as u8;
    }
}

/// Mask conditions (0-7).
fn mask_bit(mask: usize, y: usize, x: usize) -> bool {
    match mask {
        0 => (y + x).is_multiple_of(2),
        1 => y.is_multiple_of(2),
        2 => x.is_multiple_of(3),
        3 => (y + x).is_multiple_of(3),
        4 => (y / 2 + x / 3).is_multiple_of(2),
        5 => (y * x) % 2 + (y * x) % 3 == 0,
        6 => ((y * x) % 2 + (y * x) % 3).is_multiple_of(2),
        7 => ((y + x) % 2 + (y * x) % 3).is_multiple_of(2),
        _ => unreachable!(),
    }
}

/// Place the data codewords in a zigzag over the non-function regions (from the bottom-right, two columns per group, skipping column 6).
fn place_data(dark: &mut [Vec<u8>], function: &[Vec<bool>], codewords: &[u8]) {
    let size = dark.len();
    let mut bit = 0usize;
    let total_bits = codewords.len() * 8;
    let get_bit = |i: usize| -> u8 {
        if i >= total_bits {
            return 0;
        }
        (codewords[i / 8] >> (7 - i % 8)) & 1
    };
    let mut upward = true;
    let mut col = size as isize - 1;
    while col > 0 {
        if col == 6 {
            col -= 1;
        }
        let c_right = col as usize;
        let c_left = (col - 1) as usize;
        for step in 0..size {
            let row = if upward { size - 1 - step } else { step };
            for &c in &[c_right, c_left] {
                if !function[row][c] {
                    dark[row][c] = get_bit(bit);
                    bit += 1;
                }
            }
        }
        upward = !upward;
        col -= 2;
    }
}

/// Penalty score (the four ISO/IEC 18004 rules); lower is better.
fn penalty(dark: &[Vec<u8>]) -> u32 {
    let size = dark.len();
    let mut score = 0u32;

    // Rule 1: runs of the same color of length ≥5.
    let run_penalty = |line: &[u8]| -> u32 {
        let mut p = 0u32;
        let mut run = 1usize;
        for w in line.windows(2) {
            if w[0] == w[1] {
                run += 1;
            } else {
                if run >= 5 {
                    p += 3 + (run - 5) as u32;
                }
                run = 1;
            }
        }
        if run >= 5 {
            p += 3 + (run - 5) as u32;
        }
        p
    };
    for row in dark {
        score += run_penalty(row);
    }
    for x in 0..size {
        let col: Vec<u8> = dark.iter().map(|r| r[x]).collect();
        score += run_penalty(&col);
    }

    // Rule 2: 2×2 blocks of the same color.
    for y in 0..size - 1 {
        for x in 0..size - 1 {
            let v = dark[y][x];
            if dark[y][x + 1] == v && dark[y + 1][x] == v && dark[y + 1][x + 1] == v {
                score += 3;
            }
        }
    }

    // Rule 3: 1011101 + four 0s (four 0s on each side).
    let pattern: [u8; 11] = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    let rev: [u8; 11] = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    let check = |line: &[u8]| -> u32 {
        let mut p = 0u32;
        for start in 0..=line.len() - 11 {
            let seg = &line[start..start + 11];
            if seg == pattern || seg == rev {
                p += 40;
            }
        }
        p
    };
    for row in dark {
        score += check(row);
    }
    for x in 0..size {
        let col: Vec<u8> = dark.iter().map(|r| r[x]).collect();
        score += check(&col);
    }

    // Rule 4: how far the dark ratio deviates from 50% (nayuki's formulation: k = ceil((20d − 10T)/T), penalty 10|k|).
    let dark_count = dark.iter().flatten().filter(|&&v| v == 1).count() as i64;
    let total = (size * size) as i64;
    let numer = dark_count * 20 - total * 10;
    let k = if numer % total == 0 {
        numer / total
    } else {
        numer / total + 1
    };
    score += k.unsigned_abs() as u32 * 10;

    score
}

/// Pick the smallest version (ECC L, byte-mode capacity).
fn choose_version(len: usize) -> Result<usize, QrError> {
    for (idx, info) in VERSIONS.iter().enumerate() {
        let version = idx + 1;
        let count_bits = if version <= 9 { 8 } else { 16 };
        // 4-bit mode indicator + count bits + 8*len bits ≤ data*8 bits.
        if 4 + count_bits + 8 * len <= info.data * 8 {
            return Ok(version);
        }
    }
    Err(QrError)
}

/// Encode a byte string into a QR matrix (byte mode, ECC L, versions 1-10 with automatic version selection).
pub fn encode(data: &[u8], ecc: EcLevel) -> Result<QrMatrix, QrError> {
    let version = choose_version(data.len())?;
    let size = 17 + 4 * version;
    let mut dark = vec![vec![0u8; size]; size];
    let mut function = vec![vec![false; size]; size];
    draw_function_patterns(&mut dark, &mut function, version);

    let codewords = build_codewords(data, version);
    place_data(&mut dark, &function, &codewords);

    // Render the matrix once per each of the 8 masks and keep the one with the lowest penalty.
    let mut best: Option<(u32, Vec<Vec<u8>>)> = None;
    for mask in 0..8usize {
        let mut trial = dark.clone();
        for y in 0..size {
            for x in 0..size {
                if !function[y][x] && mask_bit(mask, y, x) {
                    trial[y][x] ^= 1;
                }
            }
        }
        write_format(&mut trial, size, ecc, mask);
        let score = penalty(&trial);
        if best.as_ref().is_none_or(|(s, _)| score < *s) {
            best = Some((score, trial));
        }
    }
    let (_, final_dark) = best.expect("mask loop always yields a candidate");
    Ok(QrMatrix {
        size,
        dark: final_dark,
    })
}

/// Encode a UTF-8 string.
pub fn encode_str(s: &str, ecc: EcLevel) -> Result<QrMatrix, QrError> {
    encode(s.as_bytes(), ecc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::{generate_secret, otpauth_uri, OTPAUTH_ISSUER};

    /// rqrr round-trip: feed the matrix to an independent decoder and assert that the decoded string matches the input.
    fn rqrr_roundtrip(s: &str) {
        let m = encode_str(s, EcLevel::L).unwrap();
        let simple = rqrr::SimpleGrid::from_func(m.size, |x, y| m.dark[y][x] == 1);
        let grid = rqrr::Grid::new(simple);
        let (_, text) = grid.decode().expect("rqrr decode");
        assert_eq!(text, s, "rqrr roundtrip decode mismatch");
    }

    #[test]
    fn rqrr_roundtrip_short_ascii() {
        rqrr_roundtrip("HELLO");
    }

    #[test]
    fn rqrr_roundtrip_long_ascii() {
        // More than 17 bytes, forcing a higher version; covers the 8-bit count path.
        rqrr_roundtrip("meshlet-qr-roundtrip-test-string-longer-than-v1");
    }

    #[test]
    fn rqrr_roundtrip_realistic_otpauth_uri() {
        let secret = generate_secret();
        let uri = otpauth_uri(OTPAUTH_ISSUER, "admin@meshlet.local", &secret);
        rqrr_roundtrip(&uri);
    }

    #[test]
    fn rqrr_roundtrip_16bit_count_version() {
        // Long input → exercises the 16-bit count (v10) path.
        let secret = generate_secret();
        let account = format!("{}@example.com", "user".repeat(20));
        let uri = otpauth_uri(OTPAUTH_ISSUER, &account, &secret);
        assert!(uri.len() > 100);
        rqrr_roundtrip(&uri);
    }

    #[test]
    fn encode_rejects_oversized_input() {
        let big = vec![b'x'; 300];
        assert_eq!(encode(&big, EcLevel::L), Err(QrError));
    }

    #[test]
    fn matrix_has_quiet_finder_and_dark_module() {
        let m = encode_str("A", EcLevel::L).unwrap();
        // The top-left cell of the top-left finder pattern is dark.
        assert_eq!(m.dark[0][0], 1);
        // The first cell of the timing pattern (row 6, column 8; even positions are dark).
        assert_eq!(m.dark[6][8], 1);
        // The dark module exists.
        let version = (m.size - 17) / 4;
        assert_eq!(m.dark[4 * version + 9][8], 1);
    }
}
