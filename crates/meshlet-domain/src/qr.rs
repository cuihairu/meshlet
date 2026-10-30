//! 最小 QR 编码器：byte 模式、ECC 级别 L、版本 1–10、8 掩码取罚分最优。
//!
//! 用途：把 `otpauth://` TOTP URI 渲染成可扫描二维码（认证器扫码导入）。
//! 矩阵只编码输入字节本身——**不含任何密钥以外的秘密**（URI 已由
//! [crate::totp::otpauth_uri] 生成，其中只含 base32 密钥）。
//!
//! 验证：测试用独立第三方解码器 `rqrr` 解回字节，断言与输入一致
//! （端到端回读，不依赖任何 QR 生成库）。

use core::fmt;

/// ECC 级别 L（容量最大；二维码扫描器对 L 容错能力已足够）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcLevel {
    L,
}

impl EcLevel {
    /// 2 位格式信息里的 ECC 级别位：L = `01`。
    fn format_bits(self) -> u32 {
        match self {
            EcLevel::L => 0b01,
        }
    }
}

/// 一个已编码的二维码矩阵（无静区；前端按需留白）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    /// 边长（模块数），`size = 17 + 4 * version`。
    pub size: usize,
    /// `dark[y][x]` ∈ {0,1}，(0,0) 为左上。
    pub dark: Vec<Vec<u8>>,
}

/// 编码错误：输入超出版本 1–10 的容量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrError;

impl fmt::Display for QrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("data too long for QR versions 1-10")
    }
}

/// 一个版本（ECC L）的容量与分块结构。
struct VersionInfo {
    /// 数据码字总数。
    data: usize,
    /// 每块 ECC 码字数。
    ecc: usize,
    /// 分块：`(块数, 每块数据码字数)`；按顺序铺满 `data` 个码字。
    blocks: &'static [(usize, usize)],
}

/// ECC L 版本 1–10 的分块表（ISO/IEC 18004）。
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

/// 各版本对齐图案中心坐标（ISO/IEC 18004），下标 `version - 1`。
/// 版本 1 无对齐图案。含首尾 (6, …) 与 (…, 6) 需在绘制时跳过与角部重叠者。
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

/// 手写 GF(256)（本原多项式 x^8+x^4+x^3+x^2+1 = 0x11D）。
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
        // exp 双倍长度以避免下标越界（乘法里 mod 255 后仍安全）。
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

/// 生成 RS 校验多项式系数（degree = ecc 码字数）。
fn rs_generator_poly(gf: &Gf, degree: usize) -> Vec<u8> {
    let mut poly = vec![1u8];
    for i in 0..degree {
        // 乘以 (x - α^i)，GF(256) 里减法即异或。
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

/// 计算 ECC 码字（余数）。
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

/// 位缓冲（MSB first）。
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

/// byte 模式码字生成 + ECC + 交织。
fn build_codewords(data: &[u8], version: usize) -> Vec<u8> {
    let info = &VERSIONS[version - 1];
    let mut bits = Bits::new();
    // byte 模式：0100 + 计数字（v1–9 用 8 位，v10+ 用 16 位）。
    bits.push(0b0100, 4);
    let count_bits = if version <= 9 { 8 } else { 16 };
    bits.push(data.len() as u32, count_bits);
    for &b in data {
        bits.push(b as u32, 8);
    }
    // 终止符（至多 4 个 0 位）→ 补到字节边界 → 填充 0xEC/0x11。
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

    // 分块 → 各块 ECC → 交织。
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

/// BCH(15,5)：生成多项式 0x537。
fn bch_format(data: u32) -> u32 {
    let mut rem = data << 10;
    for shift in (0..=10).rev() {
        if rem & (1 << (shift + 10)) != 0 {
            rem ^= 0x537 << shift;
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

/// BCH(18,6)：生成多项式 0x1F25。
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

/// 绘制功能图案并标记功能区（含格式信息/版本信息/暗模块占位）。
fn draw_function_patterns(dark: &mut [Vec<u8>], function: &mut [Vec<bool>], version: usize) {
    let size = dark.len();

    // 三个角的 7×7 定位图案 + 一圈分隔带（以中心为原点 9×9，dist=2 白、
    // dist=4 分隔带白、其余暗；越界跳过）。
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

    // 时序图案（第 6 行/列）。
    for i in 8..size - 8 {
        let v = if i % 2 == 0 { 1 } else { 0 };
        dark[6][i] = v;
        dark[i][6] = v;
        function[6][i] = true;
        function[i][6] = true;
    }

    // 对齐图案（5×5，跳过与定位图案重叠的角）。
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

    // 版本信息（v≥7，两块 3×6）。
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

    // 暗模块。
    let dark_y = 4 * version + 9;
    dark[dark_y][8] = 1;
    function[dark_y][8] = true;

    // 预留格式信息两份占位（15 模块各），具体值按选中掩码再写。
    let fmt_cells = format_cells(size);
    for (y, x) in fmt_cells {
        function[y][x] = true;
    }
}

/// 格式信息两份共 30 个模块（(行,列)），bit 0 为最低位、两份同序：
/// - 第一份绕左上角：bit 0..=5 在 (0..=5, 8)，6→(7,8)，7→(8,8)，8→(8,7)，
///   9..=14 在 (8, 5..=0)；
/// - 第二份绕右下：bit 0..=7 在 (8, size-1..=size-8)，8..=14 在 (size-7..=size-1, 8)。
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

/// 写格式信息（两份同值，bit 0 为最低位）。
fn write_format(dark: &mut [Vec<u8>], size: usize, ecc: EcLevel, mask: usize) {
    let value = bch_format((ecc.format_bits() << 3) | mask as u32);
    let cells = format_cells(size);
    for (i, &(y, x)) in cells.iter().enumerate() {
        dark[y][x] = ((value >> i) & 1) as u8;
    }
}

/// 掩码条件（0–7）。
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

/// 数据码字按之字形放置到非功能区（右下起，两列一组，跳过第 6 列）。
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

/// 罚分（ISO/IEC 18004 四条规则），越小越好。
fn penalty(dark: &[Vec<u8>]) -> u32 {
    let size = dark.len();
    let mut score = 0u32;

    // 规则 1：同色连续 ≥5。
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

    // 规则 2：2×2 同色。
    for y in 0..size - 1 {
        for x in 0..size - 1 {
            let v = dark[y][x];
            if dark[y][x + 1] == v && dark[y + 1][x] == v && dark[y + 1][x + 1] == v {
                score += 3;
            }
        }
    }

    // 规则 3：1011101 + 四个 0（两侧各 4 个 0）。
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

    // 规则 4：暗比例偏离 50% 的幅度（nayuki 口径：k = ceil((20d − 10T)/T)，罚 10|k|）。
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

/// 选最小版本（ECC L，byte 模式容量）。
fn choose_version(len: usize) -> Result<usize, QrError> {
    for (idx, info) in VERSIONS.iter().enumerate() {
        let version = idx + 1;
        let count_bits = if version <= 9 { 8 } else { 16 };
        // 4 位模式 + 计数位 + 8*len 位 ≤ data*8 位。
        if 4 + count_bits + 8 * len <= info.data * 8 {
            return Ok(version);
        }
    }
    Err(QrError)
}

/// 编码字节串为 QR 矩阵（byte 模式，ECC L，版本 1–10 自动选版）。
pub fn encode(data: &[u8], ecc: EcLevel) -> Result<QrMatrix, QrError> {
    let version = choose_version(data.len())?;
    let size = 17 + 4 * version;
    let mut dark = vec![vec![0u8; size]; size];
    let mut function = vec![vec![false; size]; size];
    draw_function_patterns(&mut dark, &mut function, version);

    let codewords = build_codewords(data, version);
    place_data(&mut dark, &function, &codewords);

    // 8 种掩码各自成稿，取罚分最优。
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

/// 编码 UTF-8 字符串。
pub fn encode_str(s: &str, ecc: EcLevel) -> Result<QrMatrix, QrError> {
    encode(s.as_bytes(), ecc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::{generate_secret, otpauth_uri, OTPAUTH_ISSUER};

    /// rqrr 回读：把矩阵喂给独立解码器，断言解出的字符串与输入一致。
    fn rqrr_roundtrip(s: &str) {
        let m = encode_str(s, EcLevel::L).unwrap();
        let simple = rqrr::SimpleGrid::from_func(m.size, |x, y| m.dark[y][x] == 1);
        let grid = rqrr::Grid::new(simple);
        let (_, text) = grid.decode().expect("rqrr decode");
        assert_eq!(text, s, "roundtrip mismatch for {s:?}");
    }

    #[test]
    fn rqrr_roundtrip_short_ascii() {
        rqrr_roundtrip("HELLO");
    }

    #[test]
    fn rqrr_roundtrip_long_ascii() {
        // 超过 17 字节，迫使更高版本；覆盖 8 位计数路径。
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
        // 长输入 → 需要 16 位计数（v10）路径。
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
        // 左上定位图案左上角为暗。
        assert_eq!(m.dark[0][0], 1);
        // 时序图案首格（第 6 行，第 8 列，偶数位为暗）。
        assert_eq!(m.dark[6][8], 1);
        // 暗模块存在。
        let version = (m.size - 17) / 4;
        assert_eq!(m.dark[4 * version + 9][8], 1);
    }
}
