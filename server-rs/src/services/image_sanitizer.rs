//! Server-side image metadata stripping.
//!
//! Strips EXIF, XMP, ICC profiles, comments, and other non-essential metadata
//! from image containers at upload time using `img-parts` (container-level
//! parsing, no pixel decoding). This removes privacy-leaking metadata (GPS
//! coordinates, device info) and prevents polyglot/injection attacks via
//! embedded scripts in metadata segments.
//!
//! GIF is handled by a manual byte-level parser since `img-parts` does not
//! support the GIF container format.

use img_parts::Bytes;
use img_parts::jpeg::Jpeg;
use img_parts::png::Png;
use img_parts::riff::RiffContent;
use img_parts::webp::WebP;

/// Strip metadata from image bytes based on detected format.
/// Returns sanitized bytes, or original bytes unchanged if the format is
/// unsupported or parsing fails (never blocks an upload).
pub fn strip_image_metadata(data: &[u8], ext: &str) -> Vec<u8> {
    match ext {
        "jpg" | "jpeg" => strip_jpeg(data),
        "png" => strip_png(data),
        "webp" => strip_webp(data),
        "gif" => strip_gif(data),
        _ => data.to_vec(),
    }
}

// ─── JPEG ────────────────────────────────────────────────────────────

fn strip_jpeg(data: &[u8]) -> Vec<u8> {
    let Ok(mut jpeg) = Jpeg::from_bytes(Bytes::copy_from_slice(data)) else {
        tracing::warn!("image_sanitizer: failed to parse JPEG, returning original");
        return data.to_vec();
    };

    // Keep: APP0 (0xE0 — JFIF header, required)
    //       APP14 (0xEE — Adobe color info, needed for CMYK decode)
    //       All image-data markers (SOF, DHT, DQT, SOS, DRI, RST, etc.)
    // Strip: APP1–APP13 (EXIF, XMP, ICC, FlashPix, Photoshop/IPTC, etc.)
    //        APP15 (misc)
    //        COM (comments — can contain scripts)
    jpeg.segments_mut()
        .retain(|seg| !matches!(seg.marker(), 0xE1..=0xED | 0xEF | 0xFE));

    jpeg.encoder().bytes().to_vec()
}

// ─── PNG ─────────────────────────────────────────────────────────────

fn strip_png(data: &[u8]) -> Vec<u8> {
    let Ok(mut png) = Png::from_bytes(Bytes::copy_from_slice(data)) else {
        tracing::warn!("image_sanitizer: failed to parse PNG, returning original");
        return data.to_vec();
    };

    // Strip text metadata (can contain scripts), EXIF, ICC, and non-essential chunks.
    // Keep: IHDR, PLTE, IDAT, IEND, tRNS, gAMA, cHRM, sRGB, acTL, fcTL, fdAT
    const STRIP: &[[u8; 4]] = &[
        *b"tEXt", *b"zTXt", *b"iTXt", // text metadata
        *b"eXIf", // EXIF
        *b"iCCP", // ICC profile (can be oversized/malicious)
        *b"tIME", *b"pHYs", *b"sBIT", // non-essential metadata
        *b"sPLT", *b"hIST", *b"bKGD",
    ];

    for kind in STRIP {
        png.remove_chunks_by_type(*kind);
    }

    png.encoder().bytes().to_vec()
}

// ─── WebP ────────────────────────────────────────────────────────────

fn strip_webp(data: &[u8]) -> Vec<u8> {
    let Ok(mut webp) = WebP::from_bytes(Bytes::copy_from_slice(data)) else {
        tracing::warn!("image_sanitizer: failed to parse WebP, returning original");
        return data.to_vec();
    };

    // Remove metadata chunks
    webp.remove_chunks_by_id(*b"EXIF");
    webp.remove_chunks_by_id(*b"XMP ");
    webp.remove_chunks_by_id(*b"ICCP");

    // Clear metadata flag bits in VP8X header so decoders don't expect
    // the metadata chunks we just removed.
    // VP8X flags byte layout: [Rsv|I|L|E|X|A|Rsv|Rsv]
    //   I = ICC profile (bit 5, 0x20)
    //   E = EXIF        (bit 3, 0x08)
    //   X = XMP         (bit 2, 0x04)
    for chunk in webp.chunks_mut().iter_mut() {
        if chunk.id() == *b"VP8X" {
            if let RiffContent::Data(bytes) = chunk.content_mut() {
                let mut v = bytes.to_vec();
                if !v.is_empty() {
                    v[0] &= !(0x20u8 | 0x08 | 0x04);
                }
                *bytes = Bytes::from(v);
            }
            break;
        }
    }

    webp.encoder().bytes().to_vec()
}

// ─── GIF (manual parser — img-parts doesn't support GIF) ────────────

fn strip_gif(data: &[u8]) -> Vec<u8> {
    strip_gif_inner(data).unwrap_or_else(|| {
        tracing::warn!("image_sanitizer: failed to parse GIF, returning original");
        data.to_vec()
    })
}

fn strip_gif_inner(data: &[u8]) -> Option<Vec<u8>> {
    // Minimum: 6 (header) + 7 (logical screen descriptor) = 13 bytes
    if data.len() < 13 {
        return None;
    }
    if !data.starts_with(b"GIF87a") && !data.starts_with(b"GIF89a") {
        return None;
    }

    let mut out = Vec::with_capacity(data.len());
    let mut pos: usize;

    // Copy header (6) + Logical Screen Descriptor (7)
    out.extend_from_slice(&data[..13]);
    let packed = data[10]; // LSD packed byte: GCT flag (bit 7) + GCT size (bits 0-2)
    pos = 13;

    // Global Color Table
    if packed & 0x80 != 0 {
        let gct_size = 3 * (1usize << ((packed & 0x07) as usize + 1));
        if pos + gct_size > data.len() {
            return None;
        }
        out.extend_from_slice(&data[pos..pos + gct_size]);
        pos += gct_size;
    }

    // Walk blocks
    loop {
        if pos >= data.len() {
            break;
        }

        match data[pos] {
            // Trailer — write and stop (trailing data after 0x3B is not copied)
            0x3B => {
                out.push(0x3B);
                break;
            }
            // Image Descriptor
            0x2C => {
                if pos + 10 > data.len() {
                    return None;
                }
                out.extend_from_slice(&data[pos..pos + 10]);
                let img_packed = data[pos + 9];
                pos += 10;

                // Local Color Table
                if img_packed & 0x80 != 0 {
                    let lct_size = 3 * (1usize << ((img_packed & 0x07) as usize + 1));
                    if pos + lct_size > data.len() {
                        return None;
                    }
                    out.extend_from_slice(&data[pos..pos + lct_size]);
                    pos += lct_size;
                }

                // LZW minimum code size byte
                if pos >= data.len() {
                    return None;
                }
                out.push(data[pos]);
                pos += 1;

                // Copy image data sub-blocks verbatim
                pos = copy_sub_blocks(data, pos, &mut out)?;
            }
            // Extension Introducer
            0x21 => {
                if pos + 1 >= data.len() {
                    return None;
                }
                let label = data[pos + 1];

                match label {
                    // Graphic Control Extension — keep (animation timing)
                    0xF9 => {
                        out.extend_from_slice(&data[pos..pos + 2]);
                        pos += 2;
                        pos = copy_sub_blocks(data, pos, &mut out)?;
                    }
                    // Application Extension — keep only NETSCAPE2.0 (loop control)
                    0xFF => {
                        let ext_start = pos;
                        pos += 2;

                        // The first sub-block should be 11 bytes: 8-byte app ID + 3-byte auth code
                        if pos < data.len() && data[pos] >= 11 && pos + 12 <= data.len() {
                            let is_netscape = &data[pos + 1..pos + 12] == b"NETSCAPE2.0";
                            if is_netscape {
                                out.extend_from_slice(&data[ext_start..ext_start + 2]);
                                pos = copy_sub_blocks(data, pos, &mut out)?;
                            } else {
                                pos = skip_sub_blocks(data, pos)?;
                            }
                        } else {
                            pos = skip_sub_blocks(data, pos)?;
                        }
                    }
                    // Comment Extension (0xFE) and Plain Text Extension (0x01) — skip
                    0xFE | 0x01 => {
                        pos += 2;
                        pos = skip_sub_blocks(data, pos)?;
                    }
                    // Unknown extension — skip for safety
                    _ => {
                        pos += 2;
                        pos = skip_sub_blocks(data, pos)?;
                    }
                }
            }
            // Unknown block type — stop
            _ => break,
        }
    }

    // Ensure trailer is present
    if out.last() != Some(&0x3B) {
        out.push(0x3B);
    }

    Some(out)
}

/// Copy sub-blocks from `data[pos..]` into `out`. Returns new position after
/// the block terminator (0x00 size byte).
fn copy_sub_blocks(data: &[u8], mut pos: usize, out: &mut Vec<u8>) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let size = data[pos] as usize;
        out.push(data[pos]);
        pos += 1;
        if size == 0 {
            return Some(pos);
        }
        if pos + size > data.len() {
            return None;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size;
    }
}

/// Skip sub-blocks from `data[pos..]` without copying. Returns new position
/// after the block terminator (0x00 size byte).
fn skip_sub_blocks(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let size = data[pos] as usize;
        pos += 1;
        if size == 0 {
            return Some(pos);
        }
        if pos + size > data.len() {
            return None;
        }
        pos += size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_ext_returns_original() {
        let data = b"hello world";
        let result = strip_image_metadata(data, "pdf");
        assert_eq!(result, data);
    }

    #[test]
    fn corrupt_jpeg_returns_original() {
        let data = b"not a jpeg";
        let result = strip_image_metadata(data, "jpg");
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn corrupt_png_returns_original() {
        let data = b"not a png";
        let result = strip_image_metadata(data, "png");
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn corrupt_webp_returns_original() {
        let data = b"not a webp";
        let result = strip_image_metadata(data, "webp");
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn corrupt_gif_returns_original() {
        let data = b"not a gif";
        let result = strip_image_metadata(data, "gif");
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn too_short_gif_returns_original() {
        let data = b"GIF89a";
        let result = strip_image_metadata(data, "gif");
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn minimal_gif_roundtrips() {
        // Minimal valid 1x1 GIF89a with GCT (2 colors = 6 bytes)
        // Header(6) + LSD(7) + GCT(6) + Image(~) + Trailer(1)
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            b'G', b'I', b'F', b'8', b'9', b'a',
            // Logical Screen Descriptor
            0x01, 0x00, // width = 1
            0x01, 0x00, // height = 1
            0x80,       // packed: GCT flag=1, color res=0, sort=0, GCT size=0 (2 colors)
            0x00,       // background color index
            0x00,       // pixel aspect ratio
            // Global Color Table (2 entries × 3 bytes = 6 bytes)
            0x00, 0x00, 0x00, // color 0: black
            0xFF, 0xFF, 0xFF, // color 1: white
            // Image Descriptor
            0x2C,
            0x00, 0x00, // left
            0x00, 0x00, // top
            0x01, 0x00, // width = 1
            0x01, 0x00, // height = 1
            0x00,       // packed: no LCT
            // LZW minimum code size
            0x02,
            // Image data sub-block (2 bytes)
            0x02, 0x4C, 0x01,
            // Sub-block terminator
            0x00,
            // Trailer
            0x3B,
        ];

        let result = strip_image_metadata(&data, "gif");
        // Should produce valid output (not fall back to original via None)
        assert!(result.starts_with(b"GIF89a"));
        assert_eq!(*result.last().unwrap(), 0x3B);
        // Packed byte at offset 10 should be preserved
        assert_eq!(result[10], 0x80);
        // GCT should be present (6 bytes after LSD)
        assert_eq!(&result[13..19], &[0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn gif_comment_stripped() {
        // GIF with a comment extension that should be stripped
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            b'G', b'I', b'F', b'8', b'9', b'a',
            // LSD (no GCT)
            0x01, 0x00, 0x01, 0x00,
            0x00, // packed: no GCT
            0x00, 0x00,
            // Comment extension
            0x21, 0xFE,
            0x05, b'H', b'e', b'l', b'l', b'o', // 5-byte comment
            0x00, // sub-block terminator
            // Image Descriptor
            0x2C,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00,
            0x00,
            // LZW data
            0x02,
            0x02, 0x4C, 0x01,
            0x00,
            // Trailer
            0x3B,
        ];

        let result = strip_image_metadata(&data, "gif");
        // Comment (0x21 0xFE) should be stripped
        assert!(!result.windows(2).any(|w| w == [0x21, 0xFE]));
        // Image data should still be present
        assert!(result.windows(1).any(|w| w == [0x2C]));
    }
}
