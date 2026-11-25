//! PNG encoding (deflate stored blocks, zero dependencies): no PNG crate is pulled in,
//! since 16/24px icons are only a few hundred bytes, and stored blocks (uncompressed)
//! buy a zero-dependency, auditable implementation. The encoding self-checks: the
//! roundtrip test "decodes the stream it wrote itself" to verify a conforming inflater
//! can restore the output.

/// Encode an RGBA image as a PNG byte stream. Compression uses deflate **stored** blocks (no compression): the
/// file is slightly larger, but 16/24px icons are only a few hundred bytes, buying a zero-dependency, auditable implementation.
pub fn png_encode(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(6); // color type: RGBA
    ihdr.push(0); // compression method
    ihdr.push(0); // filter method
    ihdr.push(0); // interlace
    push_chunk(&mut out, b"IHDR", &ihdr);

    // Prefix each row with filter byte 0 (None): PNG's per-row filtering.
    let row_len = 1 + width as usize * 4;
    let mut raw = Vec::with_capacity(row_len * height as usize);
    for y in 0..height as usize {
        raw.push(0);
        let row = &rgba[y * width as usize * 4..(y + 1) * width as usize * 4];
        raw.extend_from_slice(row);
    }
    push_chunk(&mut out, b"IDAT", &zlib_stream(&raw));
    push_chunk(&mut out, b"IEND", &[]);
    out
}

/// zlib container: 2-byte header + deflate stored blocks + adler32.
fn zlib_stream(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78u8, 0x01u8]; // CM=8(deflate), FLEVEL=01
    const CHUNK: usize = 0xff00;
    let mut i = 0usize;
    loop {
        let len = data.len().saturating_sub(i).min(CHUNK);
        out.push((i + len >= data.len()) as u8); // BFINAL=bit0, BTYPE=00(stored)
        out.extend_from_slice(&(len as u16).to_le_bytes());
        // NLEN = the **one's complement** of LEN (RFC 1950 stored-block checksum); an earlier version misused
        // `wrapping_neg` (two's-complement negation), which is always off by 1, and a conforming inflater (such as
        // generic zlib) rejects the whole PNG with "invalid stored block lengths" - the in-house decoder does not
        // validate NLEN, which is why it never surfaced (found in review, and evidenced with a real inflater during
        // tray triple-acceptance).
        out.extend_from_slice(&(!(len as u16)).to_le_bytes());
        out.extend_from_slice(&data[i..i + len]);
        i += len;
        if i >= data.len() {
            break;
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// Decode a zlib stream of stored blocks (test use: verifies the encoded output can be restored).
#[cfg(test)]
fn zlib_decompress(stream: &[u8]) -> Option<Vec<u8>> {
    if stream.len() < 6 || stream[0] != 0x78 {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 2usize;
    while i < stream.len().saturating_sub(4) {
        let last = stream[i] & 0x01 != 0;
        if stream[i] >> 1 != 0 {
            return None; // only stored blocks are supported (the only form this module writes)
        }
        i += 1;
        let len = u16::from_le_bytes([stream[i], stream[i + 1]]) as usize;
        i += 2;
        i += 2; // NLEN (!LEN)
        if i + len > stream.len() - 4 {
            return None;
        }
        out.extend_from_slice(&stream[i..i + len]);
        i += len;
        if last {
            break;
        }
    }
    Some(out)
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn push_chunk(out: &mut Vec<u8>, type_: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(type_);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(type_);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffffffff;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb88320
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xffffffff
}

#[cfg(test)]
mod tests {
    use super::super::state::all_states;
    use super::*;
    use crate::tray::icon::IconSize;

    /// NLEN regression (found in review): a stored block's NLEN must be the **one's complement** of
    /// LEN (RFC 1950). An earlier two's-complement negation was always off by 1, and conforming
    /// inflaters rejected the whole PNG. Covers both single-block (< 0xff00) and multi-block
    /// streams crossing the CHUNK boundary.
    #[test]
    fn zlib_stream_nlen_is_the_ones_complement_of_len() {
        for total in [100usize, 0xff00, 0xff00 + 100] {
            let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
            let stream = zlib_stream(&data);
            let mut i = 2usize;
            let mut decoded = Vec::new();
            loop {
                assert_eq!(stream[i] >> 1, 0, "only stored blocks are written");
                let len = u16::from_le_bytes([stream[i + 1], stream[i + 2]]) as usize;
                let nlen = u16::from_le_bytes([stream[i + 3], stream[i + 4]]);
                assert_eq!(nlen, !(len as u16), "NLEN must be ~LEN (RFC 1950)");
                decoded.extend_from_slice(&stream[i + 5..i + 5 + len]);
                let last = stream[i] & 0x01 != 0;
                i += 5 + len;
                if last {
                    break;
                }
            }
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn png_roundtrip_decodes_the_same_pixels() {
        for size in [IconSize::Px16, IconSize::Px24] {
            for state in all_states() {
                let (_, _, rgba) = state.icon_rgba(size);
                let png = png_encode(size.px(), size.px(), &rgba);
                assert!(png.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]));
                let idat = extract_chunk(&png, b"IDAT").expect("IDAT chunk");
                let raw = zlib_decompress(idat).expect("deflate stored stream");
                let row_len = 1 + size.px() as usize * 4;
                assert_eq!(raw.len(), row_len * size.px() as usize);
                for y in 0..size.px() as usize {
                    let row = &raw[y * row_len..(y + 1) * row_len];
                    assert_eq!(row[0], 0, "filter byte must be None");
                    let pixels = (row_len - 1) * y;
                    assert_eq!(&row[1..], &rgba[pixels..pixels + row_len - 1]);
                }
            }
        }
    }

    #[test]
    fn png_ihdr_carries_rgba_dimensions() {
        let png = png_encode(16, 16, &[0; 16 * 16 * 4]);
        let ihdr = extract_chunk(&png, b"IHDR").unwrap();
        assert_eq!(&ihdr[0..4], &16u32.to_be_bytes());
        assert_eq!(&ihdr[4..8], &16u32.to_be_bytes());
        assert_eq!(&ihdr[8..], &[8, 6, 0, 0, 0], "bit depth 8, color type RGBA");
        assert!(extract_chunk(&png, b"IEND").unwrap().is_empty());
    }

    #[test]
    fn crc32_matches_known_vector() {
        // CRC-32/ISO-HDLC check value for "123456789" (checksum self-test).
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        assert_eq!(crc32(&[]), 0x00000000);
    }

    #[test]
    fn adler32_matches_known_vector() {
        // Matches Python's `zlib.adler32` value (checksum self-test).
        assert_eq!(adler32(b"123456789"), 0x091e01de);
        assert_eq!(adler32(&[]), 0x00000001);
    }

    /// Fetch chunk data by name (skipping the length and CRC fields).
    fn extract_chunk<'a>(png: &'a [u8], type_: &[u8; 4]) -> Option<&'a [u8]> {
        let mut i = 8usize;
        while i + 8 <= png.len() {
            let len = u32::from_be_bytes([png[i], png[i + 1], png[i + 2], png[i + 3]]) as usize;
            let t = &png[i + 4..i + 8];
            let start = i + 8;
            if t == type_ {
                return Some(&png[start..start + len]);
            }
            i = start + len + 4;
        }
        None
    }
}
