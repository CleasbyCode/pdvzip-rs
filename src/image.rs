use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Cursor, Read};

use crc32fast::Hasher;
use flate2::read::ZlibDecoder;
use png::{BitDepth, ColorType, DecodeOptions, Decoder, Encoder, Transformations};

use crate::binary_utils::is_linux_problem_metacharacter;

pub type ImageResult<T> = Result<T, String>;

const INDEXED_PLTE: u8 = 3;
const TRUECOLOR_RGB: u8 = 2;
const TRUECOLOR_RGBA: u8 = 6;

const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const IHDR_SIG: [u8; 4] = *b"IHDR";
const PLTE_SIG: [u8; 4] = *b"PLTE";
const TRNS_SIG: [u8; 4] = *b"tRNS";
const IDAT_SIG: [u8; 4] = *b"IDAT";
const IEND_SIG: [u8; 4] = *b"IEND";

const WIDTH_START: usize = 0x10;
const HEIGHT_END: usize = 0x18;
const CRC_START: usize = 0x1D;
const CRC_END: usize = 0x21;

const PNG_SIGNATURE_SIZE: usize = 8;
const LENGTH_FIELD_SIZE: usize = 4;
const TYPE_FIELD_SIZE: usize = 4;
const CHUNK_OVERHEAD: usize = 12;

const MIN_DIMS: u32 = 68;
const MAX_PLTE_DIMS: u32 = 4096;
const MAX_RGB_DIMS: u32 = 900;
const MIN_RGB_COLORS: usize = 257;
// A problem byte in a dimension's high byte makes a whole 256-value band of
// that dimension unsafe (0x0A and 0x0D are the only such bytes reachable,
// giving the bands 2560-2815 and 3328-3583 for indexed covers up to 4096).
// Crossing a band takes a delta of up to 256, so the budget must exceed it;
// the bands are far enough apart that one crossing is enough.
const MAX_RESIZE_DELTA: u32 = 260;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PngIhdr {
    width: u32,
    height: u32,
    bit_depth: u8,
    color_type: u8,
    interlace_method: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedColorType {
    Rgb,
    Rgba,
    Indexed,
    Unsupported,
}

// Truecolor pixels as decoded for palette conversion: 3 channels for RGB
// without a color key, otherwise 4 (an RGB color key expanded to alpha 0).
#[derive(Debug, Clone)]
struct DecodedTruecolor {
    width: u32,
    height: u32,
    has_rgb_color_key: bool,
    channels: usize,
    pixels: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DecodedPreserved {
    width: u32,
    height: u32,
    color_type: ParsedColorType,
    bit_depth: u8,
    pixels: Vec<u8>,
    palette: Option<Vec<u8>>,
    trns: Option<Vec<u8>>,
}

fn read_be_u32(data: &[u8], index: usize) -> ImageResult<u32> {
    if index > data.len() || 4 > (data.len() - index) {
        return Err("PNG Error: Truncated 32-bit field.".to_string());
    }
    Ok(u32::from_be_bytes([
        data[index],
        data[index + 1],
        data[index + 2],
        data[index + 3],
    ]))
}

fn read_png_ihdr(png_data: &[u8]) -> ImageResult<PngIhdr> {
    const MIN_IHDR_TOTAL_SIZE: usize = 33;
    const IHDR_LENGTH_INDEX: usize = 8;
    const IHDR_NAME_INDEX: usize = 12;
    const WIDTH_INDEX: usize = 16;
    const HEIGHT_INDEX: usize = 20;
    const BIT_DEPTH_INDEX: usize = 24;
    const COLOR_TYPE_INDEX: usize = 25;
    const INTERLACE_METHOD_INDEX: usize = 28;
    const IHDR_EXPECTED_DATA_LEN: usize = 13;

    if png_data.len() < MIN_IHDR_TOTAL_SIZE {
        return Err("PNG Error: File too small to contain a valid IHDR chunk.".to_string());
    }
    if png_data[0..PNG_SIG.len()] != PNG_SIG {
        return Err("PNG Error: Invalid signature.".to_string());
    }
    if png_data[IHDR_NAME_INDEX..IHDR_NAME_INDEX + IHDR_SIG.len()] != IHDR_SIG {
        return Err("PNG Error: First chunk is not IHDR.".to_string());
    }

    let ihdr_data_len = read_be_u32(png_data, IHDR_LENGTH_INDEX)? as usize;
    if ihdr_data_len != IHDR_EXPECTED_DATA_LEN {
        return Err("PNG Error: Invalid IHDR data length.".to_string());
    }

    let width = read_be_u32(png_data, WIDTH_INDEX)?;
    let height = read_be_u32(png_data, HEIGHT_INDEX)?;
    if width == 0 || height == 0 {
        return Err("PNG Error: Invalid zero image dimension.".to_string());
    }

    Ok(PngIhdr {
        width,
        height,
        bit_depth: png_data[BIT_DEPTH_INDEX],
        color_type: png_data[COLOR_TYPE_INDEX],
        interlace_method: png_data[INTERLACE_METHOD_INDEX],
    })
}

fn validate_input_png_for_decode(ihdr: PngIhdr) -> ImageResult<()> {
    let supported_color_type = matches!(
        ihdr.color_type,
        INDEXED_PLTE | TRUECOLOR_RGB | TRUECOLOR_RGBA
    );
    if !supported_color_type {
        return Err("Image File Error: Unsupported PNG color type.".to_string());
    }

    let supported_bit_depth = match ihdr.color_type {
        INDEXED_PLTE => matches!(ihdr.bit_depth, 1 | 2 | 4 | 8),
        TRUECOLOR_RGB | TRUECOLOR_RGBA => ihdr.bit_depth == 8,
        _ => false,
    };
    if !supported_bit_depth {
        return Err("Image File Error: Unsupported PNG bit depth.".to_string());
    }

    if ihdr.width < MIN_DIMS || ihdr.height < MIN_DIMS {
        return Err("Image File Error: Cover image dimensions are too small.".to_string());
    }
    if ihdr.width > MAX_PLTE_DIMS || ihdr.height > MAX_PLTE_DIMS {
        return Err(
            "Image File Error: Cover image dimensions exceed the supported limit.".to_string(),
        );
    }

    Ok(())
}

fn validate_png_chunk_stream(png_data: &[u8], ihdr: PngIhdr) -> ImageResult<()> {
    let mut chunk_start = PNG_SIGNATURE_SIZE;
    let mut saw_ihdr = false;
    let mut palette_entries = None::<usize>;
    let mut saw_trns = false;
    let mut saw_idat = false;
    let mut idat_sequence_ended = false;
    let mut saw_iend = false;

    while chunk_start < png_data.len() {
        if CHUNK_OVERHEAD > png_data.len() - chunk_start {
            return Err(
                "PNG Error: Truncated chunk header or trailing data after IEND.".to_string(),
            );
        }

        let data_length = read_be_u32(png_data, chunk_start)? as usize;
        if data_length > png_data.len() - chunk_start - CHUNK_OVERHEAD {
            return Err(format!(
                "PNG Error: Chunk at offset 0x{chunk_start:X} exceeds file size."
            ));
        }

        let name_start = chunk_start + LENGTH_FIELD_SIZE;
        let data_start = name_start + TYPE_FIELD_SIZE;
        let data_end = data_start + data_length;
        let chunk_end = data_end + LENGTH_FIELD_SIZE;
        let chunk_type = &png_data[name_start..data_start];
        if !chunk_type.iter().all(u8::is_ascii_alphabetic) {
            return Err(format!(
                "PNG Error: Invalid chunk type at offset 0x{chunk_start:X}."
            ));
        }

        let mut hasher = Hasher::new();
        hasher.update(chunk_type);
        hasher.update(&png_data[data_start..data_end]);
        let stored_crc = read_be_u32(png_data, data_end)?;
        if hasher.finalize() != stored_crc {
            return Err(format!(
                "PNG Error: CRC mismatch for {} chunk.",
                String::from_utf8_lossy(chunk_type)
            ));
        }

        if chunk_equals(chunk_type, &IHDR_SIG) {
            if saw_ihdr || chunk_start != PNG_SIGNATURE_SIZE || data_length != 13 {
                return Err("PNG Error: IHDR must be the first and only IHDR chunk.".to_string());
            }
            saw_ihdr = true;
        } else if chunk_equals(chunk_type, &PLTE_SIG) {
            if palette_entries.is_some() {
                return Err("PNG Error: Duplicate PLTE chunk.".to_string());
            }
            if saw_idat || saw_trns {
                return Err("PNG Error: PLTE must precede tRNS and IDAT.".to_string());
            }
            if data_length == 0 || data_length % 3 != 0 || data_length > 256 * 3 {
                return Err("PNG Error: PLTE has an invalid length.".to_string());
            }
            let entries = data_length / 3;
            if ihdr.color_type == INDEXED_PLTE && entries > (1usize << ihdr.bit_depth) {
                return Err(
                    "PNG Error: PLTE has too many entries for the indexed bit depth.".to_string(),
                );
            }
            palette_entries = Some(entries);
        } else if chunk_equals(chunk_type, &TRNS_SIG) {
            if saw_trns {
                return Err("PNG Error: Duplicate tRNS chunk.".to_string());
            }
            if saw_idat {
                return Err("PNG Error: tRNS must precede IDAT.".to_string());
            }
            match ihdr.color_type {
                INDEXED_PLTE => {
                    let entries = palette_entries
                        .ok_or_else(|| "PNG Error: Indexed tRNS must follow PLTE.".to_string())?;
                    if data_length == 0 || data_length > entries {
                        return Err("PNG Error: Indexed tRNS has an invalid length.".to_string());
                    }
                }
                TRUECOLOR_RGB => {
                    if data_length != 6 {
                        return Err(
                            "PNG Error: RGB tRNS must contain exactly one color key.".to_string()
                        );
                    }
                    if png_data[data_start..data_end]
                        .chunks_exact(2)
                        .any(|sample| u16::from_be_bytes([sample[0], sample[1]]) > 0xFF)
                    {
                        return Err(
                            "PNG Error: RGB tRNS color key exceeds 8-bit sample range.".to_string()
                        );
                    }
                }
                TRUECOLOR_RGBA => {
                    return Err("PNG Error: tRNS is not permitted for RGBA images.".to_string());
                }
                _ => return Err("PNG Error: tRNS is invalid for this color type.".to_string()),
            }
            saw_trns = true;
        } else if chunk_equals(chunk_type, &IDAT_SIG) {
            if idat_sequence_ended {
                return Err("PNG Error: IDAT chunks must be consecutive.".to_string());
            }
            if ihdr.color_type == INDEXED_PLTE && palette_entries.is_none() {
                return Err("PNG Error: Indexed image is missing PLTE before IDAT.".to_string());
            }
            saw_idat = true;
        } else if chunk_equals(chunk_type, &IEND_SIG) {
            if data_length != 0 {
                return Err("PNG Error: IEND chunk must have zero length.".to_string());
            }
            if !saw_idat {
                return Err("PNG Error: IEND encountered before IDAT.".to_string());
            }
            saw_iend = true;
            if chunk_end != png_data.len() {
                return Err(
                    "PNG Error: IEND must be the final chunk with no trailing data.".to_string(),
                );
            }
            chunk_start = chunk_end;
            break;
        } else if saw_idat {
            idat_sequence_ended = true;
        }

        chunk_start = chunk_end;
    }

    if !saw_ihdr {
        return Err("PNG Error: Missing IHDR chunk.".to_string());
    }
    if !saw_idat {
        return Err("PNG Error: No IDAT chunk found.".to_string());
    }
    if !saw_iend {
        return Err("PNG Error: Missing IEND chunk.".to_string());
    }
    if chunk_start != png_data.len() {
        return Err("PNG Error: Trailing data after IEND.".to_string());
    }
    Ok(())
}

fn checked_mul(lhs: usize, rhs: usize, context: &str) -> ImageResult<usize> {
    lhs.checked_mul(rhs).ok_or_else(|| context.to_string())
}

fn checked_add(lhs: usize, rhs: usize, context: &str) -> ImageResult<usize> {
    lhs.checked_add(rhs).ok_or_else(|| context.to_string())
}

fn zeroed_vec(length: usize, context: &str) -> ImageResult<Vec<u8>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| context.to_string())?;
    output.resize(length, 0);
    Ok(output)
}

fn vec_with_capacity(capacity: usize, context: &str) -> ImageResult<Vec<u8>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| context.to_string())?;
    Ok(output)
}

fn filtered_pass_size(
    pass_width: usize,
    pass_height: usize,
    bits_per_pixel: usize,
) -> ImageResult<usize> {
    const OVERFLOW: &str =
        "PNG Error: Inflated scanline size overflows the supported address space.";

    if pass_width == 0 || pass_height == 0 {
        return Ok(0);
    }

    // ceil(pass_width * bits_per_pixel / 8), arranged to avoid multiplying the
    // full width by the bit count before division.
    let whole_bytes = checked_mul(pass_width / 8, bits_per_pixel, OVERFLOW)?;
    let remaining_bits = checked_mul(pass_width % 8, bits_per_pixel, OVERFLOW)?;
    let partial_bytes = checked_add(remaining_bits, 7, OVERFLOW)? / 8;
    let pixel_bytes = checked_add(whole_bytes, partial_bytes, OVERFLOW)?;
    let filtered_row_bytes = checked_add(pixel_bytes, 1, OVERFLOW)?;
    checked_mul(pass_height, filtered_row_bytes, OVERFLOW)
}

fn png_inflated_scanline_size(ihdr: PngIhdr) -> ImageResult<usize> {
    const OVERFLOW: &str =
        "PNG Error: Inflated scanline size overflows the supported address space.";

    let channels = match ihdr.color_type {
        INDEXED_PLTE => 1usize,
        TRUECOLOR_RGB => 3usize,
        TRUECOLOR_RGBA => 4usize,
        _ => return Err("PNG Error: Unsupported color type during decoder limit setup.".into()),
    };
    if ihdr.interlace_method > 1 {
        return Err("PNG Error: Unsupported interlace method during decoder limit setup.".into());
    }

    let bits_per_pixel = checked_mul(channels, usize::from(ihdr.bit_depth), OVERFLOW)?;
    let width = usize::try_from(ihdr.width)
        .map_err(|_| "PNG Error: Image width exceeds the supported address space.".to_string())?;
    let height = usize::try_from(ihdr.height)
        .map_err(|_| "PNG Error: Image height exceeds the supported address space.".to_string())?;

    if ihdr.interlace_method == 0 {
        return filtered_pass_size(width, height, bits_per_pixel);
    }

    const X_START: [usize; 7] = [0, 4, 0, 2, 0, 1, 0];
    const Y_START: [usize; 7] = [0, 0, 4, 0, 2, 0, 1];
    const X_STEP: [usize; 7] = [8, 8, 4, 4, 2, 2, 1];
    const Y_STEP: [usize; 7] = [8, 8, 8, 4, 4, 2, 2];
    let pass_extent = |full: usize, start: usize, step: usize| {
        if full <= start {
            0
        } else {
            1 + (full - start - 1) / step
        }
    };

    let mut total = 0usize;
    for pass in 0..X_START.len() {
        let pass_width = pass_extent(width, X_START[pass], X_STEP[pass]);
        let pass_height = pass_extent(height, Y_START[pass], Y_STEP[pass]);
        total = checked_add(
            total,
            filtered_pass_size(pass_width, pass_height, bits_per_pixel)?,
            OVERFLOW,
        )?;
    }
    Ok(total)
}

fn collect_idat_data(png_data: &[u8]) -> ImageResult<Vec<u8>> {
    let mut compressed = Vec::new();
    let mut chunk_start = PNG_SIGNATURE_SIZE;
    let mut saw_idat = false;
    let mut saw_iend = false;

    while chunk_start < png_data.len() {
        if CHUNK_OVERHEAD > png_data.len() - chunk_start {
            return Err("PNG Error: Truncated chunk header.".to_string());
        }
        let data_length = read_be_u32(png_data, chunk_start)? as usize;
        if data_length > png_data.len() - chunk_start - CHUNK_OVERHEAD {
            return Err(format!(
                "PNG Error: Chunk at offset 0x{chunk_start:X} exceeds file size."
            ));
        }

        let name_index = chunk_start + LENGTH_FIELD_SIZE;
        let data_start = name_index + TYPE_FIELD_SIZE;
        let data_end = data_start + data_length;
        let chunk_type = &png_data[name_index..data_start];

        if chunk_equals(chunk_type, &IDAT_SIG) {
            compressed
                .try_reserve(data_length)
                .map_err(|_| "PNG Error: IDAT data exceeds available memory.".to_string())?;
            compressed.extend_from_slice(&png_data[data_start..data_end]);
            saw_idat = true;
        } else if chunk_equals(chunk_type, &IEND_SIG) {
            if data_length != 0 {
                return Err("PNG Error: IEND chunk must have zero length.".to_string());
            }
            saw_iend = true;
            break;
        }

        chunk_start += CHUNK_OVERHEAD + data_length;
    }

    if !saw_idat {
        return Err("PNG Error: No IDAT chunk found.".to_string());
    }
    if !saw_iend {
        return Err("PNG Error: Missing IEND chunk.".to_string());
    }
    Ok(compressed)
}

fn verify_idat_inflate_size(png_data: &[u8], ihdr: PngIhdr) -> ImageResult<()> {
    validate_png_chunk_stream(png_data, ihdr)?;
    let expected = png_inflated_scanline_size(ihdr)?;
    let compressed = collect_idat_data(png_data)?;
    let compressed_len = compressed.len();
    let mut decoder = ZlibDecoder::new(Cursor::new(compressed));
    let mut buffer = [0u8; 32 * 1024];
    let mut total = 0usize;

    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|err| format!("PNG Error: Failed to inflate IDAT data: {err}"))?;
        if read == 0 {
            break;
        }
        total = checked_add(
            total,
            read,
            "PNG Error: Inflated IDAT size overflows the supported address space.",
        )?;
        if total > expected {
            return Err(format!(
                "PNG Error: Inflated IDAT data exceeds the IHDR-derived limit of {expected} bytes."
            ));
        }
    }

    if total != expected {
        return Err(format!(
            "PNG Error: Inflated IDAT size differs from the IHDR-derived size (expected {expected}, got {total})."
        ));
    }
    // The decoder stops at the end of the zlib stream. Anything after it, such
    // as the ZIP that a pdvzip output carries in its last IDAT, is refused, as
    // the C++ build does.
    if decoder.total_in() != compressed_len as u64 {
        return Err("PNG Error: IDAT data continues after the end of its zlib stream. The cover image may already be a pdvzip output; use the original PNG instead.".to_string());
    }
    Ok(())
}

fn color_type_from_ihdr(value: u8) -> ParsedColorType {
    match value {
        TRUECOLOR_RGB => ParsedColorType::Rgb,
        TRUECOLOR_RGBA => ParsedColorType::Rgba,
        INDEXED_PLTE => ParsedColorType::Indexed,
        _ => ParsedColorType::Unsupported,
    }
}

fn chunk_equals(bytes: &[u8], sig: &[u8; 4]) -> bool {
    bytes.len() == 4 && bytes == sig
}

fn strip_and_copy_chunks(image_file_vec: &mut Vec<u8>, color_type: u8) -> ImageResult<()> {
    let mut cleaned_png = vec_with_capacity(
        image_file_vec.len(),
        "PNG Error: Optimized image exceeds available memory.",
    )?;
    cleaned_png.extend_from_slice(&image_file_vec[0..PNG_SIGNATURE_SIZE]);

    let mut chunk_start = PNG_SIGNATURE_SIZE;
    let mut saw_idat = false;
    let mut saw_iend = false;

    while chunk_start < image_file_vec.len() {
        if chunk_start > image_file_vec.len() || CHUNK_OVERHEAD > image_file_vec.len() - chunk_start
        {
            return Err("PNG Error: Truncated chunk header.".to_string());
        }

        let data_length = read_be_u32(image_file_vec, chunk_start)? as usize;
        if data_length > image_file_vec.len() - chunk_start - CHUNK_OVERHEAD {
            return Err(format!(
                "PNG Error: Chunk at offset 0x{chunk_start:X} exceeds file size."
            ));
        }

        let name_index = chunk_start + LENGTH_FIELD_SIZE;
        let chunk_type = &image_file_vec[name_index..name_index + TYPE_FIELD_SIZE];

        let is_ihdr = chunk_equals(chunk_type, &IHDR_SIG);
        let is_plte = chunk_equals(chunk_type, &PLTE_SIG);
        let is_trns = chunk_equals(chunk_type, &TRNS_SIG);
        let is_idat = chunk_equals(chunk_type, &IDAT_SIG);
        let is_iend = chunk_equals(chunk_type, &IEND_SIG);
        if is_iend && data_length != 0 {
            return Err("PNG Error: IEND chunk must have zero length.".to_string());
        }

        let keep_chunk =
            is_ihdr || is_idat || is_iend || is_trns || (color_type == INDEXED_PLTE && is_plte);

        let total_chunk_size = CHUNK_OVERHEAD + data_length;
        if keep_chunk {
            cleaned_png
                .extend_from_slice(&image_file_vec[chunk_start..chunk_start + total_chunk_size]);
        }

        saw_idat |= is_idat;
        chunk_start += total_chunk_size;

        if is_iend {
            saw_iend = true;
            break;
        }
    }

    if !saw_idat {
        return Err("PNG Error: No IDAT chunk found.".to_string());
    }
    if !saw_iend {
        return Err("PNG Error: Missing IEND chunk.".to_string());
    }

    *image_file_vec = cleaned_png;
    Ok(())
}

fn has_problem_character(image_file_vec: &[u8]) -> ImageResult<bool> {
    if image_file_vec.len() < CRC_END {
        return Err("PNG Error: IHDR chunk is truncated after optimization.".to_string());
    }

    let check_range = |start: usize, end: usize| -> bool {
        image_file_vec[start..end]
            .iter()
            .copied()
            .any(is_linux_problem_metacharacter)
    };

    Ok(check_range(WIDTH_START, HEIGHT_END) || check_range(CRC_START, CRC_END))
}

// validate_input_png_for_decode has already refused every color type other
// than indexed, RGB and RGBA, so only the dimensions are left to check.
fn check_final_compatibility(ihdr: PngIhdr) -> ImageResult<()> {
    let max_dimension = if ihdr.color_type == INDEXED_PLTE {
        MAX_PLTE_DIMS
    } else {
        MAX_RGB_DIMS
    };
    let has_valid_dimensions = (MIN_DIMS..=max_dimension).contains(&ihdr.width)
        && (MIN_DIMS..=max_dimension).contains(&ihdr.height);

    if !has_valid_dimensions {
        return Err(
            "\nImage File Error: Dimensions of cover image are not within the supported range.\n\n\
             Supported ranges:\n\
              - PNG-32/24 Truecolor: [68 x 68] to [900 x 900]\n\
              - PNG-8 Indexed-Color: [68 x 68] to [4096 x 4096]\n\
             Incompatible image. Aborting."
                .to_string(),
        );
    }

    Ok(())
}

fn map_png_error(err: png::DecodingError) -> String {
    format!("PNG Error: Failed to decode image: {err}")
}

fn map_png_encode_error(err: png::EncodingError) -> String {
    format!("PNG Error: Failed to encode image: {err}")
}

fn strict_png_decoder(png_data: &[u8]) -> Decoder<Cursor<&[u8]>> {
    let mut options = DecodeOptions::default();
    options.set_ignore_adler32(false);
    options.set_ignore_crc(false);
    options.set_skip_ancillary_crc_failures(false);
    Decoder::new_with_options(Cursor::new(png_data), options)
}

fn decode_png_truecolor(png_data: &[u8]) -> ImageResult<DecodedTruecolor> {
    let ihdr = read_png_ihdr(png_data)?;
    validate_input_png_for_decode(ihdr)?;
    verify_idat_inflate_size(png_data, ihdr)?;

    let mut decoder = strict_png_decoder(png_data);
    decoder.set_transformations(Transformations::EXPAND);

    let mut reader = decoder.read_info().map_err(map_png_error)?;
    let has_rgb_color_key =
        reader.info().color_type == ColorType::Rgb && reader.info().trns.is_some();
    let mut buf = zeroed_vec(
        reader.output_buffer_size(),
        "PNG Error: Decoded image buffer exceeds available memory.",
    )?;
    let out_info = reader.next_frame(&mut buf).map_err(map_png_error)?;
    let used = out_info.buffer_size();
    reader.finish().map_err(map_png_error)?;
    buf.truncate(used);

    // Keep key-free RGB as three channels; expanding it to opaque RGBA would
    // only cost a second image-sized buffer.
    let (channels, pixels) = match out_info.color_type {
        ColorType::Rgb => {
            if used % 3 != 0 {
                return Err("PNG Error: Decoded RGB buffer is truncated.".to_string());
            }
            (3, buf)
        }
        ColorType::Rgba => (4, buf),
        ColorType::Grayscale => {
            let capacity = checked_mul(used, 4, "PNG Error: Expanded RGBA buffer size overflow.")?;
            let mut out = vec_with_capacity(
                capacity,
                "PNG Error: Expanded RGBA buffer exceeds available memory.",
            )?;
            for gray in buf {
                out.extend_from_slice(&[gray, gray, gray, 0xFF]);
            }
            (4, out)
        }
        ColorType::GrayscaleAlpha => {
            if used % 2 != 0 {
                return Err("PNG Error: Decoded grayscale-alpha buffer is truncated.".to_string());
            }
            let capacity = checked_mul(
                used / 2,
                4,
                "PNG Error: Expanded RGBA buffer size overflow.",
            )?;
            let mut out = vec_with_capacity(
                capacity,
                "PNG Error: Expanded RGBA buffer exceeds available memory.",
            )?;
            for px in buf.chunks_exact(2) {
                out.extend_from_slice(&[px[0], px[0], px[0], px[1]]);
            }
            (4, out)
        }
        ColorType::Indexed => {
            return Err("PNG Error: Unexpected indexed output after expansion.".to_string());
        }
    };

    let pixel_count = checked_mul(
        usize::try_from(out_info.width)
            .map_err(|_| "PNG Error: Decoded image width is unsupported.".to_string())?,
        usize::try_from(out_info.height)
            .map_err(|_| "PNG Error: Decoded image height is unsupported.".to_string())?,
        "PNG Error: Decoded image dimensions overflow.",
    )?;
    let expected_len = checked_mul(
        pixel_count,
        channels,
        "PNG Error: Decoded truecolor buffer size overflow.",
    )?;
    if pixels.len() != expected_len {
        return Err("PNG Error: Decoded truecolor buffer length mismatch.".to_string());
    }

    Ok(DecodedTruecolor {
        width: out_info.width,
        height: out_info.height,
        has_rgb_color_key,
        channels,
        pixels,
    })
}

fn bit_depth_from_u8(bit_depth: u8) -> ImageResult<BitDepth> {
    match bit_depth {
        1 => Ok(BitDepth::One),
        2 => Ok(BitDepth::Two),
        4 => Ok(BitDepth::Four),
        8 => Ok(BitDepth::Eight),
        _ => Err("PNG Error: Unsupported indexed bit depth.".to_string()),
    }
}

// Test reference: the decode-then-resize path optimize_image avoids.
#[cfg(test)]
fn decode_png_preserving(png_data: &[u8]) -> ImageResult<DecodedPreserved> {
    decode_png_native(png_data, true)
}

// Validation uses native packed indices; resizing requests unpacked indices.
fn decode_png_native(png_data: &[u8], unpack_indices: bool) -> ImageResult<DecodedPreserved> {
    let ihdr = read_png_ihdr(png_data)?;
    validate_input_png_for_decode(ihdr)?;
    verify_idat_inflate_size(png_data, ihdr)?;

    let mut decoder = strict_png_decoder(png_data);
    decoder.set_transformations(Transformations::IDENTITY);
    let mut reader = decoder.read_info().map_err(map_png_error)?;

    let color_type = match reader.info().color_type {
        ColorType::Rgb => ParsedColorType::Rgb,
        ColorType::Rgba => ParsedColorType::Rgba,
        ColorType::Indexed => ParsedColorType::Indexed,
        _ => ParsedColorType::Unsupported,
    };
    let palette = reader.info().palette.as_deref().map(<[u8]>::to_vec);
    // png normalizes an 8-bit RGB color key from its six-byte on-disk form to
    // three raw sample bytes. Convert it back so re-encoding preserves tRNS.
    let trns = match (color_type, reader.info().trns.as_deref()) {
        (ParsedColorType::Rgb, Some([red, green, blue])) => {
            Some(vec![0, *red, 0, *green, 0, *blue])
        }
        (_, Some(value)) => Some(value.to_vec()),
        (_, None) => None,
    };

    let mut encoded_pixels = zeroed_vec(
        reader.output_buffer_size(),
        "PNG Error: Decoded image buffer exceeds available memory.",
    )?;
    let out_info = reader
        .next_frame(&mut encoded_pixels)
        .map_err(map_png_error)?;
    reader.finish().map_err(map_png_error)?;
    encoded_pixels.truncate(out_info.buffer_size());

    if out_info.width != ihdr.width || out_info.height != ihdr.height {
        return Err("PNG Error: Decoded dimensions differ from IHDR.".to_string());
    }

    let width = usize::try_from(out_info.width)
        .map_err(|_| "PNG Error: Decoded image width is unsupported.".to_string())?;
    let height = usize::try_from(out_info.height)
        .map_err(|_| "PNG Error: Decoded image height is unsupported.".to_string())?;
    let pixel_count = checked_mul(
        width,
        height,
        "PNG Error: Decoded image dimensions overflow.",
    )?;

    let pixels = match color_type {
        ParsedColorType::Indexed => {
            let depth = usize::from(ihdr.bit_depth);
            let palette = palette
                .as_deref()
                .ok_or_else(|| "PNG Error: Indexed image is missing PLTE.".to_string())?;
            if palette.is_empty() || palette.len() % 3 != 0 || palette.len() > 256 * 3 {
                return Err("PNG Error: Indexed image has an invalid palette.".to_string());
            }
            if palette.len() / 3 > (1usize << depth) {
                return Err(
                    "PNG Error: Palette has too many entries for its bit depth.".to_string()
                );
            }
            if trns
                .as_ref()
                .is_some_and(|alpha| alpha.len() > palette.len() / 3)
            {
                return Err("PNG Error: Indexed tRNS exceeds the palette size.".to_string());
            }

            let expected_packed = checked_mul(
                out_info.line_size,
                height,
                "PNG Error: Packed indexed buffer size overflow.",
            )?;
            if encoded_pixels.len() != expected_packed {
                return Err("PNG Error: Packed indexed buffer length mismatch.".to_string());
            }

            let palette_size = palette.len() / 3;
            if depth == 8 && out_info.line_size == width {
                // One byte per index, already unpacked: a max reduction
                // vectorizes, where the bit-unpacking loop below does not.
                let highest = encoded_pixels.iter().copied().fold(0u8, u8::max);
                if usize::from(highest) >= palette_size {
                    return Err("PNG Error: Palette index exceeds PLTE size.".to_string());
                }
                encoded_pixels
            } else {
                let mut unpacked = if unpack_indices {
                    Some(zeroed_vec(
                        pixel_count,
                        "PNG Error: Unpacked indexed image exceeds available memory.",
                    )?)
                } else {
                    None
                };
                let mask = (1u16 << depth) - 1;
                for (y, row) in encoded_pixels.chunks_exact(out_info.line_size).enumerate() {
                    let output_row = y * width;
                    for x in 0..width {
                        let bit_offset =
                            checked_mul(x, depth, "PNG Error: Indexed row bit offset overflow.")?;
                        let shift = 8usize - depth - (bit_offset % 8);
                        let index = (u16::from(row[bit_offset / 8]) >> shift) & mask;
                        if usize::from(index) >= palette_size {
                            return Err("PNG Error: Palette index exceeds PLTE size.".to_string());
                        }
                        if let Some(output) = &mut unpacked {
                            output[output_row + x] = index as u8;
                        }
                    }
                }
                unpacked.unwrap_or(encoded_pixels)
            }
        }
        ParsedColorType::Rgb | ParsedColorType::Rgba => {
            let channels = if color_type == ParsedColorType::Rgb {
                3
            } else {
                4
            };
            let expected = checked_mul(
                pixel_count,
                channels,
                "PNG Error: Decoded truecolor buffer size overflow.",
            )?;
            if encoded_pixels.len() != expected {
                return Err("PNG Error: Decoded truecolor buffer length mismatch.".to_string());
            }
            if color_type == ParsedColorType::Rgb && trns.as_ref().is_some_and(|key| key.len() != 6)
            {
                return Err("PNG Error: RGB tRNS must contain exactly one color key.".to_string());
            }
            encoded_pixels
        }
        ParsedColorType::Unsupported => {
            return Err("Image File Error: Unsupported PNG color type.".to_string());
        }
    };

    Ok(DecodedPreserved {
        width: out_info.width,
        height: out_info.height,
        color_type,
        bit_depth: ihdr.bit_depth,
        pixels,
        palette,
        trns,
    })
}

fn validate_pixel_buffer(
    width: u32,
    height: u32,
    channels: usize,
    pixels: &[u8],
) -> ImageResult<()> {
    let pixel_count = checked_mul(
        usize::try_from(width)
            .map_err(|_| "Image Error: Image width is unsupported.".to_string())?,
        usize::try_from(height)
            .map_err(|_| "Image Error: Image height is unsupported.".to_string())?,
        "Image Error: Image dimensions overflow.",
    )?;
    let expected = checked_mul(
        pixel_count,
        channels,
        "Image Error: Image buffer size overflow.",
    )?;
    if pixels.len() != expected {
        return Err("Image Error: Image buffer length mismatch.".to_string());
    }
    Ok(())
}

fn encode_rgb_png(
    width: u32,
    height: u32,
    rgb: &[u8],
    trns: Option<&[u8]>,
) -> ImageResult<Vec<u8>> {
    validate_pixel_buffer(width, height, 3, rgb)?;
    if trns.is_some_and(|key| key.len() != 6) {
        return Err("PNG Error: RGB tRNS must contain exactly one color key.".to_string());
    }
    let mut out = Vec::<u8>::new();
    {
        let mut encoder = Encoder::new(&mut out, width, height);
        encoder.set_color(ColorType::Rgb);
        encoder.set_depth(BitDepth::Eight);
        if let Some(key) = trns {
            encoder.set_trns(key.to_vec());
        }
        let mut writer = encoder.write_header().map_err(map_png_encode_error)?;
        writer.write_image_data(rgb).map_err(map_png_encode_error)?;
    }
    Ok(out)
}

fn encode_rgba_png(width: u32, height: u32, rgba: &[u8]) -> ImageResult<Vec<u8>> {
    validate_pixel_buffer(width, height, 4, rgba)?;
    let mut out = Vec::<u8>::new();
    {
        let mut encoder = Encoder::new(&mut out, width, height);
        encoder.set_color(ColorType::Rgba);
        encoder.set_depth(BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(map_png_encode_error)?;
        writer
            .write_image_data(rgba)
            .map_err(map_png_encode_error)?;
    }
    Ok(out)
}

// An 8-bit palette image built from RGBA pixels, not yet encoded, so a safety
// resize can run on the indices before the only encode.
struct PaletteImage {
    indices: Vec<u8>,
    palette: Vec<u8>,
    trns: Option<Vec<u8>>,
}

// Map RGB or RGBA pixels to 8-bit palette indices in one pass, numbering
// colors (alpha included) in order of first appearance. Stops at the first
// color past 256 and returns None: such an image stays truecolor.
fn palettize(
    width: u32,
    height: u32,
    pixels: &[u8],
    channels: usize,
) -> ImageResult<Option<PaletteImage>> {
    if !matches!(channels, 3 | 4) {
        return Err("Image Error: Palette conversion expects RGB or RGBA pixels.".to_string());
    }
    validate_pixel_buffer(width, height, channels, pixels)?;
    let pixel_count = checked_mul(
        usize::try_from(width)
            .map_err(|_| "Image Error: Image width is unsupported.".to_string())?,
        usize::try_from(height)
            .map_err(|_| "Image Error: Image height is unsupported.".to_string())?,
        "Image Error: Pixel count overflow.",
    )?;

    let mut color_to_index = HashMap::<u32, u8>::new();
    color_to_index
        .try_reserve(MIN_RGB_COLORS)
        .map_err(|_| "Image Error: Palette lookup exceeds available memory.".to_string())?;
    let mut palette_rgba = Vec::<[u8; 4]>::new();
    palette_rgba
        .try_reserve_exact(256)
        .map_err(|_| "Image Error: Palette exceeds available memory.".to_string())?;
    let mut indices = vec_with_capacity(
        pixel_count,
        "Image Error: Indexed image exceeds available memory.",
    )?;

    let mut previous: Option<(u32, u8)> = None;
    for px in pixels.chunks_exact(channels) {
        let alpha = if channels == 4 { px[3] } else { 0xFF };
        let key = (u32::from(px[0]) << 24)
            | (u32::from(px[1]) << 16)
            | (u32::from(px[2]) << 8)
            | u32::from(alpha);

        // Runs of one color are common in images with few colors.
        let idx = match previous {
            Some((previous_key, previous_idx)) if previous_key == key => previous_idx,
            _ => {
                let idx = if let Some(existing) = color_to_index.get(&key) {
                    *existing
                } else {
                    if palette_rgba.len() == MIN_RGB_COLORS - 1 {
                        return Ok(None);
                    }
                    let next = palette_rgba.len() as u8;
                    palette_rgba.push([px[0], px[1], px[2], alpha]);
                    color_to_index.insert(key, next);
                    next
                };
                previous = Some((key, idx));
                idx
            }
        };
        indices.push(idx);
    }

    if palette_rgba.is_empty() {
        return Err("Image Error: Palette conversion produced empty palette.".to_string());
    }

    let palette_capacity =
        checked_mul(palette_rgba.len(), 3, "Image Error: Palette size overflow.")?;
    let mut palette = vec_with_capacity(
        palette_capacity,
        "Image Error: Palette exceeds available memory.",
    )?;
    let mut trns = vec_with_capacity(
        palette_rgba.len(),
        "Image Error: Transparency palette exceeds available memory.",
    )?;
    let mut last_non_opaque = None::<usize>;

    for (i, color) in palette_rgba.iter().enumerate() {
        palette.extend_from_slice(&[color[0], color[1], color[2]]);
        trns.push(color[3]);
        if color[3] != 0xFF {
            last_non_opaque = Some(i);
        }
    }

    let trns = last_non_opaque.map(|last_idx| {
        trns.truncate(last_idx + 1);
        trns
    });
    Ok(Some(PaletteImage {
        indices,
        palette,
        trns,
    }))
}

fn pack_palette_indices(
    width: u32,
    height: u32,
    bit_depth: u8,
    indices: &[u8],
) -> ImageResult<Vec<u8>> {
    validate_pixel_buffer(width, height, 1, indices)?;
    let depth = usize::from(bit_depth);
    if !matches!(bit_depth, 1 | 2 | 4 | 8) {
        return Err("PNG Error: Unsupported indexed bit depth.".to_string());
    }

    let width = usize::try_from(width)
        .map_err(|_| "Image Error: Indexed width is unsupported.".to_string())?;
    let height = usize::try_from(height)
        .map_err(|_| "Image Error: Indexed height is unsupported.".to_string())?;
    let row_bits = checked_mul(
        width,
        depth,
        "Image Error: Packed indexed row size overflow.",
    )?;
    let row_bytes = checked_add(
        row_bits,
        7,
        "Image Error: Packed indexed row size overflow.",
    )? / 8;
    let packed_len = checked_mul(
        row_bytes,
        height,
        "Image Error: Packed indexed image size overflow.",
    )?;
    let mut packed = zeroed_vec(
        packed_len,
        "Image Error: Packed indexed image exceeds available memory.",
    )?;
    let max_index = (1u16 << depth) - 1;

    for y in 0..height {
        let input_row = y * width;
        let output_row = y * row_bytes;
        for x in 0..width {
            let index = indices[input_row + x];
            if u16::from(index) > max_index {
                return Err("PNG Error: Palette index exceeds the indexed bit depth.".to_string());
            }
            let bit_offset =
                checked_mul(x, depth, "Image Error: Packed indexed bit offset overflow.")?;
            let shift = 8usize - depth - (bit_offset % 8);
            packed[output_row + bit_offset / 8] |= index << shift;
        }
    }
    Ok(packed)
}

fn encode_indexed_preserving(
    width: u32,
    height: u32,
    bit_depth: u8,
    indices: &[u8],
    palette: &[u8],
    trns: Option<&[u8]>,
) -> ImageResult<Vec<u8>> {
    if palette.is_empty() || palette.len() % 3 != 0 || palette.len() > 256 * 3 {
        return Err("PNG Error: Indexed image has an invalid palette.".to_string());
    }
    let depth = usize::from(bit_depth);
    if palette.len() / 3 > (1usize << depth) {
        return Err("PNG Error: Palette has too many entries for its bit depth.".to_string());
    }
    if trns.is_some_and(|alpha| alpha.len() > palette.len() / 3) {
        return Err("PNG Error: Indexed tRNS exceeds the palette size.".to_string());
    }

    // 8-bit indices are already in PNG row layout.
    let packed = if bit_depth == 8 {
        validate_pixel_buffer(width, height, 1, indices)?;
        Cow::Borrowed(indices)
    } else {
        Cow::Owned(pack_palette_indices(width, height, bit_depth, indices)?)
    };
    let mut out = Vec::<u8>::new();
    {
        let mut encoder = Encoder::new(&mut out, width, height);
        encoder.set_color(ColorType::Indexed);
        encoder.set_depth(bit_depth_from_u8(bit_depth)?);
        encoder.set_palette(palette.to_vec());
        if let Some(alpha) = trns {
            encoder.set_trns(alpha.to_vec());
        }
        let mut writer = encoder.write_header().map_err(map_png_encode_error)?;
        writer
            .write_image_data(&packed)
            .map_err(map_png_encode_error)?;
    }
    Ok(out)
}

fn resize_interleaved(
    src: &[u8],
    width: u32,
    height: u32,
    new_width: u32,
    new_height: u32,
    channels: usize,
    nearest: bool,
) -> ImageResult<Vec<u8>> {
    if width == 0 || height == 0 || new_width == 0 || new_height == 0 || channels == 0 {
        return Err(
            "Image Error: Resize dimensions and channel count must be nonzero.".to_string(),
        );
    }
    validate_pixel_buffer(width, height, channels, src)?;

    let output_pixels = checked_mul(
        usize::try_from(new_width)
            .map_err(|_| "Image Error: Resize width is unsupported.".to_string())?,
        usize::try_from(new_height)
            .map_err(|_| "Image Error: Resize height is unsupported.".to_string())?,
        "Image Error: Resized image dimensions overflow.",
    )?;
    let output_len = checked_mul(
        output_pixels,
        channels,
        "Image Error: Resized image buffer size overflow.",
    )?;
    let mut out = zeroed_vec(
        output_len,
        "Image Error: Resized image exceeds available memory.",
    )?;

    let x_ratio = width as f64 / new_width as f64;
    let y_ratio = height as f64 / new_height as f64;
    let sample_offset = 0.5f64;

    for y in 0..new_height {
        for x in 0..new_width {
            let src_x = ((x as f64 + sample_offset) * x_ratio - sample_offset)
                .clamp(0.0, (width - 1) as f64);
            let src_y = ((y as f64 + sample_offset) * y_ratio - sample_offset)
                .clamp(0.0, (height - 1) as f64);

            let out_base = ((y as usize) * (new_width as usize) + x as usize) * channels;

            if nearest {
                let ix = src_x.round() as u32;
                let iy = src_y.round() as u32;
                let src_base = ((iy as usize) * (width as usize) + ix as usize) * channels;
                out[out_base..out_base + channels]
                    .copy_from_slice(&src[src_base..src_base + channels]);
                continue;
            }

            let x0 = src_x.floor() as u32;
            let y0 = src_y.floor() as u32;
            let x1 = (x0 + 1).min(width - 1);
            let y1 = (y0 + 1).min(height - 1);
            let dx = (src_x - x0 as f64) as f32;
            let dy = (src_y - y0 as f64) as f32;
            let mut top_left_weight = (1.0 - dx) * (1.0 - dy);
            let mut top_right_weight = dx * (1.0 - dy);
            let mut bottom_left_weight = (1.0 - dx) * dy;
            let mut bottom_right_weight = dx * dy;
            let mut alpha = 1.0;
            let color_channels = if channels == 4 {
                // Weight color by coverage so transparent RGB cannot darken edges.
                top_left_weight *=
                    src[((y0 as usize) * (width as usize) + x0 as usize) * channels + 3] as f32;
                top_right_weight *=
                    src[((y0 as usize) * (width as usize) + x1 as usize) * channels + 3] as f32;
                bottom_left_weight *=
                    src[((y1 as usize) * (width as usize) + x0 as usize) * channels + 3] as f32;
                bottom_right_weight *=
                    src[((y1 as usize) * (width as usize) + x1 as usize) * channels + 3] as f32;
                alpha = (top_left_weight + top_right_weight)
                    + (bottom_left_weight + bottom_right_weight);
                if alpha < 0.5 {
                    // The output was zero-initialized: transparent black.
                    continue;
                }
                out[out_base + 3] = alpha.round().clamp(0.0, 255.0) as u8;
                3
            } else {
                channels
            };

            for c in 0..color_channels {
                let p00 =
                    src[((y0 as usize) * (width as usize) + x0 as usize) * channels + c] as f32;
                let p10 =
                    src[((y0 as usize) * (width as usize) + x1 as usize) * channels + c] as f32;
                let p01 =
                    src[((y1 as usize) * (width as usize) + x0 as usize) * channels + c] as f32;
                let p11 =
                    src[((y1 as usize) * (width as usize) + x1 as usize) * channels + c] as f32;

                let value = (top_left_weight * p00 + top_right_weight * p10)
                    + (bottom_left_weight * p01 + bottom_right_weight * p11);
                out[out_base + c] = (value / alpha).round().clamp(0.0, 255.0) as u8;
            }
        }
    }

    Ok(out)
}

// Test reference: the decode-then-resize path optimize_image avoids.
#[cfg(test)]
fn resize_image(image_file_vec: &mut Vec<u8>, new_width: u32, new_height: u32) -> ImageResult<()> {
    let decoded = decode_png_preserving(image_file_vec)?;
    if new_width == decoded.width && new_height == decoded.height {
        // Nothing to resample — keep the current encoding untouched.
        validate_resize_target(&decoded, new_width, new_height)?;
        return Ok(());
    }
    resize_decoded(image_file_vec, decoded, new_width, new_height)
}

fn validate_resize_target(decoded: &DecodedPreserved, new_width: u32, new_height: u32) -> ImageResult<()> {
    if new_width < MIN_DIMS || new_height < MIN_DIMS {
        return Err("Image Error: Resize target dimensions are below the minimum.".to_string());
    }
    if new_width > decoded.width || new_height > decoded.height {
        return Err("Image Error: Resize target must not exceed source dimensions.".to_string());
    }
    Ok(())
}

// Resample pixels that are already decoded (unpacked indices, RGB or RGBA) and
// re-encode them into image_file_vec. Spares callers that hold the pixels a
// second decode of the PNG.
fn resize_decoded(
    image_file_vec: &mut Vec<u8>,
    mut decoded: DecodedPreserved,
    new_width: u32,
    new_height: u32,
) -> ImageResult<()> {
    validate_resize_target(&decoded, new_width, new_height)?;

    // RGB color keys cannot represent the partial coverage created by filtering.
    if decoded.color_type == ParsedColorType::Rgb {
        if let Some(key) = &decoded.trns {
            let capacity = checked_mul(
                decoded.pixels.len() / 3,
                4,
                "PNG Error: RGBA conversion size overflow.",
            )?;
            let mut rgba = vec_with_capacity(
                capacity,
                "PNG Error: RGBA conversion exceeds available memory.",
            )?;
            let key = [key[1], key[3], key[5]];
            for pixel in decoded.pixels.chunks_exact(3) {
                rgba.extend_from_slice(pixel);
                rgba.push(if pixel == key { 0 } else { 255 });
            }
            decoded.pixels = rgba;
            decoded.color_type = ParsedColorType::Rgba;
            decoded.trns = None;
        }
    }

    let channels = match decoded.color_type {
        ParsedColorType::Indexed => 1,
        ParsedColorType::Rgb => 3,
        ParsedColorType::Rgba => 4,
        ParsedColorType::Unsupported => {
            return Err("Image File Error: Unsupported PNG color type.".to_string());
        }
    };
    let resized = resize_interleaved(
        &decoded.pixels,
        decoded.width,
        decoded.height,
        new_width,
        new_height,
        channels,
        decoded.color_type == ParsedColorType::Indexed,
    )?;

    *image_file_vec = match decoded.color_type {
        ParsedColorType::Indexed => encode_indexed_preserving(
            new_width,
            new_height,
            decoded.bit_depth,
            &resized,
            decoded
                .palette
                .as_deref()
                .ok_or_else(|| "PNG Error: Indexed image is missing PLTE.".to_string())?,
            decoded.trns.as_deref(),
        )?,
        ParsedColorType::Rgb => {
            encode_rgb_png(new_width, new_height, &resized, decoded.trns.as_deref())?
        }
        ParsedColorType::Rgba => encode_rgba_png(new_width, new_height, &resized)?,
        ParsedColorType::Unsupported => unreachable!(),
    };

    Ok(())
}

fn candidate_ihdr_is_linux_safe(width: u32, height: u32, bit_depth: u8, color_type: u8) -> bool {
    let mut ihdr = [0u8; 17];
    ihdr[0..4].copy_from_slice(&IHDR_SIG);
    ihdr[4..8].copy_from_slice(&width.to_be_bytes());
    ihdr[8..12].copy_from_slice(&height.to_be_bytes());
    ihdr[12] = bit_depth;
    ihdr[13] = color_type;

    if ihdr[4..12]
        .iter()
        .copied()
        .any(is_linux_problem_metacharacter)
    {
        return false;
    }

    let mut hasher = Hasher::new();
    hasher.update(&ihdr);
    !hasher
        .finalize()
        .to_be_bytes()
        .into_iter()
        .any(is_linux_problem_metacharacter)
}

fn find_linux_safe_resize_target(current: PngIhdr) -> Option<(u32, u32)> {
    let max_width_delta = MAX_RESIZE_DELTA.min(current.width - MIN_DIMS);
    let max_height_delta = MAX_RESIZE_DELTA.min(current.height - MIN_DIMS);

    for total_delta in 1..=max_width_delta + max_height_delta {
        let first_width_delta = total_delta.saturating_sub(max_height_delta);
        let last_width_delta = total_delta.min(max_width_delta);
        let mut best = None;
        let mut best_aspect_distortion = u64::MAX;

        for width_delta in first_width_delta..=last_width_delta {
            let height_delta = total_delta - width_delta;
            let candidate_width = current.width - width_delta;
            let candidate_height = current.height - height_delta;
            if !candidate_ihdr_is_linux_safe(
                candidate_width,
                candidate_height,
                current.bit_depth,
                current.color_type,
            ) {
                continue;
            }

            let width_scale = u64::from(width_delta) * u64::from(current.height);
            let height_scale = u64::from(height_delta) * u64::from(current.width);
            let distortion = width_scale.abs_diff(height_scale);
            if best.is_none() || distortion < best_aspect_distortion {
                best = Some((candidate_width, candidate_height));
                best_aspect_distortion = distortion;
            }
        }
        if best.is_some() {
            return best;
        }
    }
    None
}

// Expand packed 1/2/4-bit indices (PNG row layout) to one byte per pixel.
fn unpack_palette_indices(packed: &[u8], width: u32, height: u32, bit_depth: u8) -> ImageResult<Vec<u8>> {
    if bit_depth == 8 {
        validate_pixel_buffer(width, height, 1, packed)?;
        return Ok(packed.to_vec());
    }
    let depth = usize::from(bit_depth);
    let width = usize::try_from(width)
        .map_err(|_| "Image Error: Indexed width is unsupported.".to_string())?;
    let height = usize::try_from(height)
        .map_err(|_| "Image Error: Indexed height is unsupported.".to_string())?;
    let row_bytes = checked_add(
        checked_mul(width, depth, "Image Error: Packed indexed row size overflow.")?,
        7,
        "Image Error: Packed indexed row size overflow.",
    )? / 8;
    if packed.len() != checked_mul(row_bytes, height, "Image Error: Packed indexed image size overflow.")? {
        return Err("PNG Error: Packed indexed buffer length mismatch.".to_string());
    }
    let mut unpacked = zeroed_vec(
        checked_mul(width, height, "Image Error: Pixel count overflow.")?,
        "PNG Error: Unpacked indexed image exceeds available memory.",
    )?;
    let mask = (1u8 << depth) - 1;
    for (row, output) in packed.chunks_exact(row_bytes).zip(unpacked.chunks_exact_mut(width)) {
        for (x, index) in output.iter_mut().enumerate() {
            let bit_offset = x * depth;
            let shift = 8 - depth - (bit_offset % 8);
            *index = (row[bit_offset / 8] >> shift) & mask;
        }
    }
    Ok(unpacked)
}

// Dimensions whose IHDR (width/height and CRC) avoids every problem byte.
fn linux_safe_resize_target(mut current: PngIhdr, has_rgb_color_key: bool) -> ImageResult<(u32, u32)> {
    if current.color_type == TRUECOLOR_RGB && has_rgb_color_key {
        // Predict the actual RGBA IHDR emitted after color-key conversion.
        current.color_type = TRUECOLOR_RGBA;
    }
    find_linux_safe_resize_target(current).ok_or_else(|| {
        "Image Error: Could not eliminate problem characters from IHDR within the resize iteration limit."
            .to_string()
    })
}

// Sanity-check that the encoder produced the IHDR we predicted.
fn require_linux_safe_ihdr(image_file_vec: &[u8]) -> ImageResult<()> {
    if has_problem_character(image_file_vec)? {
        return Err(
            "Image Error: Post-resize IHDR still contains problem characters. Encoder produced an unexpected IHDR layout."
                .to_string(),
        );
    }
    Ok(())
}

pub fn optimize_image(image_file_vec: &mut Vec<u8>) -> ImageResult<()> {
    let initial_ihdr = read_png_ihdr(image_file_vec)?;
    validate_input_png_for_decode(initial_ihdr)?;

    // Each path below checks the final color class's size limit before any
    // safety resize. That resize only shrinks, never below the minimum, and
    // keeps the truecolor or indexed class, so it can neither rescue an
    // oversized cover (a 901-pixel truecolor image whose header happens to need
    // a resize would otherwise be accepted, while one that needs none is
    // refused) nor make a valid one invalid; and a truecolor cover too big to
    // accept is not resampled first.
    //
    // The pixels decoded here are resized at most once, so no path decodes or
    // encodes the PNG twice.
    let (decoded, has_rgb_color_key) = match color_type_from_ihdr(initial_ihdr.color_type) {
        ParsedColorType::Rgb | ParsedColorType::Rgba => {
            let decoded = decode_png_truecolor(image_file_vec)?;
            let (width, height) = (decoded.width, decoded.height);
            if let Some(palette_image) =
                palettize(width, height, &decoded.pixels, decoded.channels)?
            {
                drop(decoded);
                // The encoder writes zero compression, filter and interlace
                // fields, so the output IHDR is known before encoding.
                let palette_ihdr = PngIhdr {
                    width,
                    height,
                    bit_depth: 8,
                    color_type: INDEXED_PLTE,
                    interlace_method: 0,
                };
                check_final_compatibility(palette_ihdr)?;
                let (new_width, new_height) =
                    if candidate_ihdr_is_linux_safe(width, height, 8, INDEXED_PLTE) {
                        (width, height)
                    } else {
                        linux_safe_resize_target(palette_ihdr, false)?
                    };
                let indices = if (new_width, new_height) == (width, height) {
                    palette_image.indices
                } else {
                    resize_interleaved(
                        &palette_image.indices,
                        width,
                        height,
                        new_width,
                        new_height,
                        1,
                        true,
                    )?
                };
                *image_file_vec = encode_indexed_preserving(
                    new_width,
                    new_height,
                    8,
                    &indices,
                    &palette_image.palette,
                    palette_image.trns.as_deref(),
                )?;
                return require_linux_safe_ihdr(image_file_vec);
            }
            let has_rgb_color_key = decoded.has_rgb_color_key;
            (Decoded::Truecolor(decoded), has_rgb_color_key)
        }
        ParsedColorType::Indexed => {
            // Indexed images do not need expansion for color statistics, but
            // they still need a full bounded decode to validate IDAT and PLTE.
            (Decoded::Native(decode_png_native(image_file_vec, false)?), false)
        }
        ParsedColorType::Unsupported => {
            unreachable!("input validation rejects unsupported PNG color types");
        }
    };

    // Keep the cover's own encoding. Its IHDR may carry an interlace flag, so
    // check the actual header bytes rather than a predicted one.
    strip_and_copy_chunks(image_file_vec, initial_ihdr.color_type)?;
    check_final_compatibility(initial_ihdr)?;
    if !has_problem_character(image_file_vec)? {
        return Ok(());
    }
    let (new_width, new_height) = linux_safe_resize_target(initial_ihdr, has_rgb_color_key)?;

    resize_decoded(image_file_vec, decoded.into_resize_input()?, new_width, new_height)?;
    require_linux_safe_ihdr(image_file_vec)
}

// The pixels optimize_image decoded, kept for a possible safety resize.
enum Decoded {
    Truecolor(DecodedTruecolor),
    Native(DecodedPreserved),
}

impl Decoded {
    // The unpacked, native-format pixels resize_decoded expects: the same
    // input decoding the PNG again with decode_png_preserving would give.
    fn into_resize_input(self) -> ImageResult<DecodedPreserved> {
        Ok(match self {
            Decoded::Native(mut native) => {
                native.pixels = unpack_palette_indices(
                    &native.pixels,
                    native.width,
                    native.height,
                    native.bit_depth,
                )?;
                native
            }
            // RGBA expanded from RGB already carries any color key as alpha,
            // which is the RGBA the resize would build; key-free RGB is native.
            Decoded::Truecolor(truecolor) => DecodedPreserved {
                width: truecolor.width,
                height: truecolor.height,
                color_type: if truecolor.channels == 4 {
                    ParsedColorType::Rgba
                } else {
                    ParsedColorType::Rgb
                },
                bit_depth: 8,
                pixels: truecolor.pixels,
                palette: None,
                trns: None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crc32fast::Hasher;
    use flate2::{Compression, write::ZlibEncoder};
    use png::{BitDepth, ColorType, Encoder};

    use super::{
        IEND_SIG, INDEXED_PLTE, MIN_DIMS, PngIhdr, TRUECOLOR_RGB, candidate_ihdr_is_linux_safe,
        decode_png_preserving, encode_indexed_preserving, find_linux_safe_resize_target,
        optimize_image, png_inflated_scanline_size, read_png_ihdr, resize_image,
    };

    fn png_chunk(name: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::<u8>::with_capacity(12 + data.len());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(data);

        let mut hasher = Hasher::new();
        hasher.update(name);
        hasher.update(data);
        out.extend_from_slice(&hasher.finalize().to_be_bytes());
        out
    }

    fn insert_text_chunk_before_iend(mut png_data: Vec<u8>) -> Vec<u8> {
        let iend_marker = png_data
            .windows(4)
            .rposition(|w| w == b"IEND")
            .expect("IEND should exist");
        let iend_chunk_start = iend_marker - 4;
        let text_chunk = png_chunk(b"tEXt", b"author\0unit-test");
        png_data.splice(iend_chunk_start..iend_chunk_start, text_chunk);
        png_data
    }

    fn find_chunk(png_data: &[u8], name: &[u8; 4]) -> (usize, usize) {
        let mut start = 8usize;
        while start + 12 <= png_data.len() {
            let length =
                u32::from_be_bytes(png_data[start..start + 4].try_into().expect("chunk length"))
                    as usize;
            let end = start + 12 + length;
            assert!(end <= png_data.len(), "well-formed test PNG chunks");
            if &png_data[start + 4..start + 8] == name {
                return (start, end);
            }
            start = end;
        }
        panic!("chunk not found: {}", String::from_utf8_lossy(name));
    }

    fn replace_idat(png_data: &[u8], compressed: &[u8]) -> Vec<u8> {
        let mut output = png_data[0..8].to_vec();
        let mut start = 8usize;
        let mut wrote_idat = false;
        while start + 12 <= png_data.len() {
            let length =
                u32::from_be_bytes(png_data[start..start + 4].try_into().expect("chunk length"))
                    as usize;
            let end = start + 12 + length;
            assert!(end <= png_data.len(), "well-formed test PNG chunks");
            let name: &[u8; 4] = png_data[start + 4..start + 8]
                .try_into()
                .expect("chunk name");
            if name == b"IDAT" {
                if !wrote_idat {
                    output.extend_from_slice(&png_chunk(b"IDAT", compressed));
                    wrote_idat = true;
                }
            } else {
                output.extend_from_slice(&png_data[start..end]);
            }
            start = end;
            if name == &IEND_SIG {
                break;
            }
        }
        assert!(wrote_idat, "test PNG has IDAT");
        output
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("compress test data");
        encoder.finish().expect("finish test compression")
    }

    fn high_color_rgb(width: u32, height: u32) -> Vec<u8> {
        let mut rgb = Vec::with_capacity((width * height * 3) as usize);
        for i in 0..width * height {
            rgb.extend_from_slice(&[
                (i & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                (i.wrapping_mul(37) & 0xFF) as u8,
            ]);
        }
        rgb
    }

    fn encode_adam7_rgb_png(width: u32, height: u32) -> Vec<u8> {
        const X_START: [u32; 7] = [0, 4, 0, 2, 0, 1, 0];
        const Y_START: [u32; 7] = [0, 0, 4, 0, 2, 0, 1];
        const X_STEP: [u32; 7] = [8, 8, 4, 4, 2, 2, 1];
        const Y_STEP: [u32; 7] = [8, 8, 8, 4, 4, 2, 2];

        let mut raw = Vec::new();
        for pass in 0..7 {
            let mut y = Y_START[pass];
            while y < height {
                raw.push(0); // None filter for each reduced-image row.
                let mut x = X_START[pass];
                while x < width {
                    let i = y * width + x;
                    raw.extend_from_slice(&[
                        (i & 0xFF) as u8,
                        ((i >> 8) & 0xFF) as u8,
                        (i.wrapping_mul(37) & 0xFF) as u8,
                    ]);
                    x += X_STEP[pass];
                }
                y += Y_STEP[pass];
            }
        }

        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, TRUECOLOR_RGB, 0, 0, 1]);

        let mut png = super::PNG_SIG.to_vec();
        png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
        png.extend_from_slice(&png_chunk(b"IDAT", &zlib_compress(&raw)));
        png.extend_from_slice(&png_chunk(b"IEND", b""));
        png
    }

    fn encode_rgb_png(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        {
            let mut encoder = Encoder::new(&mut out, width, height);
            encoder.set_color(ColorType::Rgb);
            encoder.set_depth(BitDepth::Eight);
            let mut writer = encoder.write_header().expect("header");
            writer.write_image_data(rgb).expect("data");
        }
        out
    }

    fn encode_rgb_png_with_trns(width: u32, height: u32, rgb: &[u8], trns: &[u8]) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        {
            let mut encoder = Encoder::new(&mut out, width, height);
            encoder.set_color(ColorType::Rgb);
            encoder.set_depth(BitDepth::Eight);
            encoder.set_trns(trns.to_vec());
            let mut writer = encoder.write_header().expect("header");
            writer.write_image_data(rgb).expect("data");
        }
        out
    }

    fn encode_rgb16_png(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        {
            let mut encoder = Encoder::new(&mut out, width, height);
            encoder.set_color(ColorType::Rgb);
            encoder.set_depth(BitDepth::Sixteen);
            let mut writer = encoder.write_header().expect("header");
            writer.write_image_data(rgb).expect("data");
        }
        out
    }

    fn encode_grayscale_png(width: u32, height: u32, gray: &[u8]) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        {
            let mut encoder = Encoder::new(&mut out, width, height);
            encoder.set_color(ColorType::Grayscale);
            encoder.set_depth(BitDepth::Eight);
            let mut writer = encoder.write_header().expect("header");
            writer.write_image_data(gray).expect("data");
        }
        out
    }

    fn encode_indexed_png(width: u32, height: u32, indices: &[u8], palette: &[u8]) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        {
            let mut encoder = Encoder::new(&mut out, width, height);
            encoder.set_color(ColorType::Indexed);
            encoder.set_depth(BitDepth::Eight);
            encoder.set_palette(palette.to_vec());
            let mut writer = encoder.write_header().expect("header");
            writer.write_image_data(indices).expect("data");
        }
        out
    }

    #[test]
    fn palettizes_low_color_truecolor_images() {
        let width = 100u32;
        let height = 100u32;
        let mut rgb = Vec::<u8>::with_capacity((width * height * 3) as usize);
        for y in 0..height {
            for x in 0..width {
                if (x + y) % 2 == 0 {
                    rgb.extend_from_slice(&[255, 0, 0]);
                } else {
                    rgb.extend_from_slice(&[0, 0, 255]);
                }
            }
        }

        let mut png = encode_rgb_png(width, height, &rgb);
        optimize_image(&mut png).expect("optimize should succeed");

        let ihdr = read_png_ihdr(&png).expect("ihdr");
        assert_eq!(ihdr.color_type, INDEXED_PLTE);
        assert!(ihdr.width <= width);
        assert!(ihdr.height <= height);
    }

    #[test]
    fn strips_ancillary_chunk_when_not_palettized() {
        let width = 100u32;
        let height = 100u32;
        let mut rgb = Vec::<u8>::with_capacity((width * height * 3) as usize);
        for i in 0..(width * height) {
            let v = (i % 255) as u8;
            rgb.extend_from_slice(&[v, v.wrapping_add(1), v.wrapping_add(2)]);
        }

        let png = encode_rgb_png(width, height, &rgb);
        let mut png_with_text = insert_text_chunk_before_iend(png);
        assert!(png_with_text.windows(4).any(|w| w == b"tEXt"));

        optimize_image(&mut png_with_text).expect("optimize should succeed");
        assert!(!png_with_text.windows(4).any(|w| w == b"tEXt"));
    }

    #[test]
    fn keeps_indexed_images_supported() {
        let width = 96u32;
        let height = 96u32;
        let indices = vec![0u8; (width * height) as usize];
        let palette = vec![0u8, 0u8, 0u8, 255u8, 255u8, 255u8];
        let mut png = encode_indexed_png(width, height, &indices, &palette);

        optimize_image(&mut png).expect("indexed image should optimize");

        let ihdr = read_png_ihdr(&png).expect("ihdr");
        assert_eq!(ihdr.color_type, INDEXED_PLTE);
    }

    #[test]
    fn rejects_unsupported_color_type() {
        let width = 100u32;
        let height = 100u32;
        let gray = vec![200u8; (width * height) as usize];
        let mut png = encode_grayscale_png(width, height, &gray);
        let err = optimize_image(&mut png).expect_err("grayscale should be rejected");
        assert!(err.contains("Unsupported PNG color type"));
    }

    #[test]
    fn rejects_out_of_range_truecolor_dimensions() {
        let width = 1000u32;
        let height = 100u32;
        let mut rgb = Vec::<u8>::with_capacity((width * height * 3) as usize);
        for i in 0..(width * height) {
            let idx = i;
            let r = (idx & 0xFF) as u8;
            let g = ((idx >> 8) & 0xFF) as u8;
            let b = ((idx >> 16) & 0xFF) as u8;
            rgb.extend_from_slice(&[r, g, b]);
        }
        let mut png = encode_rgb_png(width, height, &rgb);
        let err = optimize_image(&mut png).expect_err("dimensions should be rejected");
        assert!(err.contains("Dimensions of cover image are not within the supported range"));
    }

    #[test]
    fn resizes_when_ihdr_contains_problematic_bytes() {
        let width = 96u32;
        let height = 96u32;
        let mut rgb = Vec::<u8>::with_capacity((width * height * 3) as usize);
        for i in 0..(width * height) {
            let idx = i;
            let r = (idx & 0xFF) as u8;
            let g = ((idx >> 8) & 0xFF) as u8;
            let b = ((idx >> 16) & 0xFF) as u8;
            rgb.extend_from_slice(&[r, g, b]);
        }
        let mut png = encode_rgb_png(width, height, &rgb);

        optimize_image(&mut png).expect("image should be resized to avoid IHDR metacharacters");

        let ihdr = read_png_ihdr(&png).expect("ihdr");
        assert_eq!(ihdr.color_type, TRUECOLOR_RGB);
        assert!(ihdr.width < width || ihdr.height < height);
    }

    #[test]
    fn line_feed_high_byte_band_is_resized_out() {
        // 0x0A as a dimension's high byte makes the whole 2560-2815 band unsafe
        // for indexed covers; escaping it needs a delta of up to 256.
        for width in [2560u32, 2687, 2815] {
            assert!(
                !candidate_ihdr_is_linux_safe(width, MIN_DIMS, 8, INDEXED_PLTE),
                "width {width} with a 0x0A high byte must be rejected"
            );
        }
        let current = PngIhdr {
            width: 2815, // 0x0AFF
            height: MIN_DIMS,
            bit_depth: 8,
            color_type: INDEXED_PLTE,
            interlace_method: 0,
        };
        let (width, height) =
            find_linux_safe_resize_target(current).expect("band fixture must find a safe target");
        assert_eq!(height, MIN_DIMS, "only the width axis had room to move");
        assert!(width < 2560, "width must move below the 0x0A band, got {width}");
        assert!(
            candidate_ihdr_is_linux_safe(width, height, 8, INDEXED_PLTE),
            "chosen target must be Linux-safe"
        );
    }

    #[test]
    fn carriage_return_high_byte_band_is_resized_out() {
        // 0x0D (refused for CMD) as a dimension's high byte makes the whole
        // 3328-3583 band unsafe; the worst cases sit at the top of the band with
        // the other axis at the minimum, so only one axis can move.
        for depth in [1u8, 2, 4, 8] {
            for band_width in [3328u32, 3455, 3583] {
                assert!(
                    !candidate_ihdr_is_linux_safe(band_width, MIN_DIMS, depth, INDEXED_PLTE),
                    "width {band_width} with a 0x0D high byte must be rejected"
                );
            }
            for (width, height) in [(3583u32, MIN_DIMS), (MIN_DIMS, 3583)] {
                let current = PngIhdr {
                    width,
                    height,
                    bit_depth: depth,
                    color_type: INDEXED_PLTE,
                    interlace_method: 0,
                };
                let (new_width, new_height) = find_linux_safe_resize_target(current)
                    .unwrap_or_else(|| panic!("{depth}-bit {width}x{height}: no safe target"));
                assert!(
                    new_width.max(new_height) < 3328 && new_width.min(new_height) == MIN_DIMS,
                    "{depth}-bit {width}x{height} -> {new_width}x{new_height}"
                );
                assert!(candidate_ihdr_is_linux_safe(new_width, new_height, depth, INDEXED_PLTE));
            }
        }
    }

    #[test]
    fn oversized_truecolor_is_rejected_before_safety_resize() {
        // One pixel over the limit, with a header whose cheapest fix is cutting
        // that one column: (900, height) is safe, (901, height) is not.
        let width = 901u32;
        let height = (MIN_DIMS..900)
            .find(|&h| {
                !candidate_ihdr_is_linux_safe(width, h, 8, TRUECOLOR_RGB)
                    && candidate_ihdr_is_linux_safe(width - 1, h, 8, TRUECOLOR_RGB)
            })
            .expect("oversized fixture height");
        let mut png = encode_rgb_png(width, height, &high_color_rgb(width, height));
        let err = optimize_image(&mut png).expect_err("oversized truecolor cover must be refused");
        assert!(err.contains("Incompatible image"), "{err}");
    }

    #[test]
    fn rejects_nonzero_length_iend() {
        let mut png = encode_rgb_png(80, 80, &high_color_rgb(80, 80));
        let (start, end) = find_chunk(&png, b"IEND");
        png.splice(start..end, png_chunk(b"IEND", b"x"));

        let err = optimize_image(&mut png).expect_err("noncanonical IEND must be rejected");
        assert!(err.contains("IEND chunk must have zero length"));
    }

    #[test]
    fn rejects_bad_iend_crc_and_post_iend_bytes() {
        let original = encode_rgb_png(80, 80, &high_color_rgb(80, 80));

        let mut bad_crc = original.clone();
        let (_, iend_end) = find_chunk(&bad_crc, b"IEND");
        bad_crc[iend_end - 1] ^= 1;
        let err = optimize_image(&mut bad_crc).expect_err("bad IEND CRC must be rejected");
        assert!(err.contains("CRC mismatch for IEND"));

        let mut trailing = original;
        trailing.extend_from_slice(b"post-IEND bytes");
        let err = optimize_image(&mut trailing).expect_err("post-IEND bytes must be rejected");
        assert!(err.contains("IEND must be the final chunk"));
    }

    #[test]
    fn rejects_malformed_crc_bad_late_and_duplicate_trns() {
        let rgb = high_color_rgb(80, 80);
        let trns = [0, rgb[0], 0, rgb[1], 0, rgb[2]];
        let original = encode_rgb_png_with_trns(80, 80, &rgb, &trns);

        let mut malformed = original.clone();
        let (trns_start, trns_end) = find_chunk(&malformed, b"tRNS");
        malformed.splice(trns_start..trns_end, png_chunk(b"tRNS", &[0, 1, 0, 2, 0]));
        let err = optimize_image(&mut malformed).expect_err("short RGB tRNS must be rejected");
        assert!(err.contains("RGB tRNS must contain exactly one color key"));

        let mut bad_crc = original.clone();
        let (_, trns_end) = find_chunk(&bad_crc, b"tRNS");
        bad_crc[trns_end - 1] ^= 1;
        let err = optimize_image(&mut bad_crc).expect_err("bad tRNS CRC must be rejected");
        assert!(err.contains("CRC mismatch for tRNS"));

        let mut late = original.clone();
        let (trns_start, trns_end) = find_chunk(&late, b"tRNS");
        let trns_chunk = late[trns_start..trns_end].to_vec();
        late.drain(trns_start..trns_end);
        let (iend_start, _) = find_chunk(&late, b"IEND");
        late.splice(iend_start..iend_start, trns_chunk);
        let err = optimize_image(&mut late).expect_err("late tRNS must be rejected");
        assert!(err.contains("tRNS must precede IDAT"));

        let mut duplicate = original;
        let (trns_start, trns_end) = find_chunk(&duplicate, b"tRNS");
        let trns_chunk = duplicate[trns_start..trns_end].to_vec();
        duplicate.splice(trns_end..trns_end, trns_chunk);
        let err = optimize_image(&mut duplicate).expect_err("duplicate tRNS must be rejected");
        assert!(err.contains("Duplicate tRNS"));
    }

    #[test]
    fn rejects_bad_or_duplicate_plte_and_nonconsecutive_idat() {
        let indices = vec![0u8; 80 * 80];
        let palette = [0, 0, 0, 255, 255, 255];
        let indexed = encode_indexed_png(80, 80, &indices, &palette);

        let mut empty_trns = indexed.clone();
        let (idat_start, _) = find_chunk(&empty_trns, b"IDAT");
        empty_trns.splice(idat_start..idat_start, png_chunk(b"tRNS", b""));
        let err = optimize_image(&mut empty_trns).expect_err("empty tRNS must be rejected");
        assert!(err.contains("Indexed tRNS has an invalid length"));

        let mut bad_crc = indexed.clone();
        let (_, plte_end) = find_chunk(&bad_crc, b"PLTE");
        bad_crc[plte_end - 1] ^= 1;
        let err = optimize_image(&mut bad_crc).expect_err("bad PLTE CRC must be rejected");
        assert!(err.contains("CRC mismatch for PLTE"));

        let mut malformed = indexed.clone();
        let (plte_start, plte_end) = find_chunk(&malformed, b"PLTE");
        malformed.splice(plte_start..plte_end, png_chunk(b"PLTE", &[0, 0, 0, 1]));
        let err = optimize_image(&mut malformed).expect_err("malformed PLTE must be rejected");
        assert!(err.contains("PLTE has an invalid length"));

        let mut duplicate = indexed;
        let (plte_start, plte_end) = find_chunk(&duplicate, b"PLTE");
        let plte_chunk = duplicate[plte_start..plte_end].to_vec();
        duplicate.splice(plte_end..plte_end, plte_chunk);
        let err = optimize_image(&mut duplicate).expect_err("duplicate PLTE must be rejected");
        assert!(err.contains("Duplicate PLTE"));

        let mut separated = encode_rgb_png(80, 80, &high_color_rgb(80, 80));
        let (idat_start, idat_end) = find_chunk(&separated, b"IDAT");
        let compressed = separated[idat_start + 8..idat_end - 4].to_vec();
        let split = compressed.len() / 2;
        assert!(split > 0 && split < compressed.len());
        let mut replacement = png_chunk(b"IDAT", &compressed[..split]);
        replacement.extend_from_slice(&png_chunk(b"tEXt", b"note\0valid ancillary"));
        replacement.extend_from_slice(&png_chunk(b"IDAT", &compressed[split..]));
        separated.splice(idat_start..idat_end, replacement);
        let err = optimize_image(&mut separated).expect_err("nonconsecutive IDAT must be rejected");
        assert!(err.contains("IDAT chunks must be consecutive"));
    }

    #[test]
    fn retained_iend_is_canonical_and_final() {
        let mut png =
            insert_text_chunk_before_iend(encode_rgb_png(80, 80, &high_color_rgb(80, 80)));

        optimize_image(&mut png).expect("valid PNG should optimize");
        assert!(png.ends_with(&png_chunk(b"IEND", b"")));
        let (start, end) = find_chunk(&png, b"IEND");
        assert_eq!(end - start, 12);
        assert_eq!(end, png.len());
    }

    #[test]
    fn rgb_transparency_key_becomes_alpha_on_resize() {
        let width = 80;
        let height = 80;
        let rgb = high_color_rgb(width, height);
        let trns = [0, rgb[0], 0, rgb[1], 0, rgb[2]];
        let mut png = encode_rgb_png_with_trns(width, height, &rgb, &trns);

        resize_image(&mut png, width - 1, height).expect("RGB image should resize");
        let decoded = decode_png_preserving(&png).expect("resized RGB should decode");
        assert_eq!(decoded.color_type, super::ParsedColorType::Rgba);
        assert!(decoded.trns.is_none());
        assert!(decoded.pixels[3] > 0 && decoded.pixels[3] < 255);
    }

    #[test]
    fn subbyte_palette_and_one_axis_safety_resize_are_preserved() {
        let width = MIN_DIMS;
        let height = 80;
        assert!(!candidate_ihdr_is_linux_safe(
            width,
            height,
            2,
            INDEXED_PLTE
        ));
        assert!(candidate_ihdr_is_linux_safe(
            width,
            height - 1,
            2,
            INDEXED_PLTE
        ));

        let indices = (0..width * height)
            .map(|i| (i % 4) as u8)
            .collect::<Vec<_>>();
        let palette = [0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255];
        let trns = [0, 85, 170, 255];
        let mut png = encode_indexed_preserving(width, height, 2, &indices, &palette, Some(&trns))
            .expect("encode 2-bit indexed fixture");

        optimize_image(&mut png).expect("one-axis safety resize should succeed");
        let ihdr = read_png_ihdr(&png).expect("resized IHDR");
        assert_eq!((ihdr.width, ihdr.height), (width, height - 1));
        assert_eq!((ihdr.bit_depth, ihdr.color_type), (2, INDEXED_PLTE));
        let decoded = decode_png_preserving(&png).expect("resized indexed image should decode");
        assert_eq!(decoded.palette.as_deref(), Some(palette.as_slice()));
        assert_eq!(decoded.trns.as_deref(), Some(trns.as_slice()));
    }

    #[test]
    fn exact_scanline_sizes_cover_noninterlaced_and_adam7() {
        let base = PngIhdr {
            width: MIN_DIMS,
            height: MIN_DIMS,
            bit_depth: 8,
            color_type: TRUECOLOR_RGB,
            interlace_method: 0,
        };
        assert_eq!(png_inflated_scanline_size(base).expect("size"), 13_940);
        assert_eq!(
            png_inflated_scanline_size(PngIhdr {
                interlace_method: 1,
                ..base
            })
            .expect("Adam7 size"),
            14_000
        );

        let adam7 = encode_adam7_rgb_png(MIN_DIMS, MIN_DIMS);
        let decoded = decode_png_preserving(&adam7).expect("bounded Adam7 PNG should decode");
        assert_eq!((decoded.width, decoded.height), (MIN_DIMS, MIN_DIMS));
        assert_eq!(decoded.pixels.len(), (MIN_DIMS * MIN_DIMS * 3) as usize);
    }

    #[test]
    fn oversized_and_short_idat_inflation_are_rejected() {
        let png = encode_rgb_png(MIN_DIMS, MIN_DIMS, &high_color_rgb(MIN_DIMS, MIN_DIMS));
        let expected =
            png_inflated_scanline_size(read_png_ihdr(&png).expect("IHDR")).expect("scanline size");

        let oversized = zlib_compress(&vec![0u8; 4 * 1024 * 1024]);
        let mut bomb = replace_idat(&png, &oversized);
        let err = optimize_image(&mut bomb).expect_err("inflate bomb must be bounded");
        assert!(err.contains("exceeds the IHDR-derived limit"));

        let short = zlib_compress(&vec![0u8; expected - 1]);
        let mut truncated = replace_idat(&png, &short);
        let err = optimize_image(&mut truncated).expect_err("short inflate must be rejected");
        assert!(err.contains("Inflated IDAT size differs"));
    }

    #[test]
    fn idat_data_after_the_zlib_stream_is_rejected() {
        // A pdvzip output carries its ZIP in an IDAT after the image's zlib
        // stream; as in the C++ build, that is not accepted as a cover.
        let indices = (0..MIN_DIMS * MIN_DIMS).map(|i| (i % 7) as u8).collect::<Vec<_>>();
        let palette = (0..7u8).flat_map(|i| [i, 40 * i, 255 - i]).collect::<Vec<_>>();
        let covers = [
            ("truecolor", encode_rgb_png(MIN_DIMS, MIN_DIMS, &high_color_rgb(MIN_DIMS, MIN_DIMS))),
            (
                "indexed",
                encode_indexed_preserving(MIN_DIMS, MIN_DIMS, 8, &indices, &palette, None)
                    .expect("indexed fixture"),
            ),
        ];
        for (label, png) in covers {
            let mut accepted = png.clone();
            optimize_image(&mut accepted).unwrap_or_else(|err| panic!("{label}: {err}"));

            let (idat_start, idat_end) = find_chunk(&png, b"IDAT");
            let mut with_tail = png[idat_start + 8..idat_end - 4].to_vec();
            with_tail.extend_from_slice(b"PK\x03\x04");
            let mut same_chunk = replace_idat(&png, &with_tail);

            let (iend_start, _) = find_chunk(&png, b"IEND");
            let mut separate_chunk = png[..iend_start].to_vec();
            separate_chunk.extend_from_slice(&png_chunk(b"IDAT", b"PK\x03\x04 zip data"));
            separate_chunk.extend_from_slice(&png[iend_start..]);

            for (case, cover) in [("same IDAT", &mut same_chunk), ("separate IDAT", &mut separate_chunk)] {
                let err = optimize_image(cover).expect_err("trailing IDAT data must be rejected");
                assert!(
                    err.contains("continues after the end of its zlib stream")
                        && err.contains("may already be a pdvzip output"),
                    "{label}, {case}: {err}"
                );
            }
        }
    }

    #[test]
    fn rejects_truecolor_16_bit_before_decode() {
        let rgb16 = vec![0u8; (MIN_DIMS * MIN_DIMS * 6) as usize];
        let mut png = encode_rgb16_png(MIN_DIMS, MIN_DIMS, &rgb16);
        let err = optimize_image(&mut png).expect_err("16-bit truecolor is unsupported");
        assert!(err.contains("Unsupported PNG bit depth"));
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[test]
    fn bilinear_filter_uses_alpha_weighted_colors() {
        for (pixels, expected) in [
            ([0, 0, 0, 0, 255, 255, 255, 255], [255, 255, 255, 128]),
            ([255, 0, 0, 64, 0, 0, 255, 192], [64, 0, 191, 128]),
            ([255, 17, 0, 0, 0, 93, 255, 0], [0, 0, 0, 0]),
            ([0, 0, 0, 255, 255, 255, 255, 255], [128, 128, 128, 255]),
        ] {
            assert_eq!(
                resize_interleaved(&pixels, 2, 1, 1, 1, 4, false).unwrap(),
                expected
            );
        }
        let tile = [0, 0, 0, 0, 255, 0, 0, 64, 0, 255, 0, 128, 0, 0, 255, 192];
        assert_eq!(
            resize_interleaved(&tile, 2, 2, 1, 1, 4, false).unwrap(),
            [43, 85, 128, 96]
        );
        assert_eq!(
            resize_interleaved(&[0, 0, 0, 255, 255, 255], 2, 1, 1, 1, 3, false).unwrap(),
            [128, 128, 128]
        );
    }

    #[test]
    fn rgb_color_key_resize_keeps_fractional_coverage() {
        for key in [[0, 0, 0], [12, 34, 56]] {
            let visible = [255, 90, 127];
            let pixels = (0..136 * 68)
                .flat_map(|i| if i % 2 == 0 { key } else { visible })
                .collect::<Vec<_>>();
            let mut png =
                encode_rgb_png(136, 68, &pixels, Some(&[0, key[0], 0, key[1], 0, key[2]])).unwrap();
            resize_image(&mut png, 68, 68).unwrap();
            let decoded = decode_png_preserving(&png).unwrap();
            assert_eq!(decoded.color_type, ParsedColorType::Rgba);
            assert!(decoded.trns.is_none());
            assert!(
                decoded
                    .pixels
                    .chunks_exact(4)
                    .all(|pixel| pixel == [255, 90, 127, 128])
            );
        }
    }

    #[test]
    fn indexed_validation_retains_packed_pixels_at_every_depth() {
        for depth in [1u8, 2, 4, 8] {
            let width = 69;
            let height = 71;
            let indices = (0..width * height)
                .map(|i| (i % 2) as u8)
                .collect::<Vec<_>>();
            let png = encode_indexed_preserving(
                width,
                height,
                depth,
                &indices,
                &[0, 0, 0, 255, 255, 255],
                Some(&[0, 255]),
            )
            .unwrap();
            let native = decode_png_native(&png, false).unwrap();
            assert_eq!(
                native.pixels.len(),
                (width as usize * depth as usize).div_ceil(8) * height as usize
            );
            let unpacked = decode_png_preserving(&png).unwrap();
            assert_eq!(unpacked.pixels, indices);
            let mut optimized = png;
            optimize_image(&mut optimized).unwrap();
            let result = decode_png_preserving(&optimized).unwrap();
            assert_eq!(result.bit_depth, depth);
            assert_eq!(result.palette, unpacked.palette);
            assert_eq!(result.trns, unpacked.trns);
        }
    }

    #[test]
    fn packed_indexed_validation_still_rejects_out_of_palette_indices() {
        // A 2-bit sample of 3 cannot refer to this two-entry palette.
        let png = encode_indexed_preserving(
            68,
            68,
            2,
            &vec![3; 68 * 68],
            &[0, 0, 0, 255, 255, 255],
            None,
        )
        .unwrap();
        assert!(
            decode_png_native(&png, false)
                .unwrap_err()
                .contains("Palette index")
        );
    }

    #[test]
    fn indexed_validation_finds_a_single_out_of_palette_index() {
        // One bad index anywhere is found, not only in the first bytes; the
        // largest valid index next to it is accepted and kept as decoded.
        for depth in [2u8, 4, 8] {
            let entries = (1usize << depth) - 1;
            let palette = (0..entries).flat_map(|i| [i as u8, 0, 255]).collect::<Vec<_>>();
            let (width, height) = (69u32, 70u32);
            let count = (width * height) as usize;
            for pixel in [count - 1, count / 2 + 1] {
                let mut indices = vec![0u8; count];
                indices[pixel] = (entries - 1) as u8;
                let png =
                    encode_indexed_preserving(width, height, depth, &indices, &palette, None)
                        .unwrap();
                for unpack in [false, true] {
                    let decoded = decode_png_native(&png, unpack).unwrap();
                    if depth == 8 || unpack {
                        assert_eq!(decoded.pixels, indices, "{depth}-bit pixel {pixel}");
                    }
                }
                indices[pixel] = entries as u8;
                let png =
                    encode_indexed_preserving(width, height, depth, &indices, &palette, None)
                        .unwrap();
                for unpack in [false, true] {
                    assert!(
                        decode_png_native(&png, unpack)
                            .unwrap_err()
                            .contains("Palette index"),
                        "{depth}-bit pixel {pixel} unpack {unpack}"
                    );
                }
            }
        }
    }

    #[test]
    fn safety_resize_predicts_rgba_header_for_rgb_color_keys() {
        let width = (258..=600)
            .find(|width| {
                let current = PngIhdr {
                    width: *width,
                    height: 68,
                    bit_depth: 8,
                    color_type: TRUECOLOR_RGB,
                    interlace_method: 0,
                };
                !candidate_ihdr_is_linux_safe(*width, 68, 8, TRUECOLOR_RGB)
                    && find_linux_safe_resize_target(current).is_some_and(|(w, h)| {
                        !candidate_ihdr_is_linux_safe(w, h, 8, TRUECOLOR_RGBA)
                    })
            })
            .expect("color-type-dependent header fixture");
        let pixels = (0..width * 68)
            .flat_map(|i| {
                if i % 2 == 0 {
                    [0, 0, 0]
                } else {
                    [(i % 251 + 1) as u8, ((i / 251) % 251 + 1) as u8, 255]
                }
            })
            .collect::<Vec<_>>();
        let mut png = encode_rgb_png(width, 68, &pixels, Some(&[0; 6])).unwrap();
        optimize_image(&mut png).unwrap();
        assert_eq!(read_png_ihdr(&png).unwrap().color_type, TRUECOLOR_RGBA);
        assert!(!has_problem_character(&png).unwrap());
        let decoded = decode_png_preserving(&png).unwrap();
        assert!(
            decoded
                .pixels
                .chunks_exact(4)
                .any(|pixel| pixel[3] > 0 && pixel[3] < 255)
        );
    }

    // optimize_image resizes the pixels it already decoded instead of decoding
    // the PNG a second time. That must give the same bytes as resizing from the
    // encoded file.
    #[test]
    fn decoded_resize_matches_file_resize() {
        const WIDTH: u32 = 120;
        const HEIGHT: u32 = 100;
        let truecolor = |channels: usize| -> Vec<u8> {
            (0..WIDTH as usize * HEIGHT as usize * channels)
                .map(|i| ((i * 37 + i / 11 * 5) & 0xFF) as u8)
                .collect()
        };
        let rgb = truecolor(3);
        let key = [0, rgb[0], 0, rgb[1], 0, rgb[2]];
        let palette: Vec<u8> = (0..16u8).flat_map(|i| [i * 16, 255 - i * 9, i * 5]).collect();
        let indices: Vec<u8> = (0..WIDTH as usize * HEIGHT as usize)
            .map(|i| ((i * 7 + i / WIDTH as usize * 3) % 16) as u8)
            .collect();
        let cases = [
            ("RGB", encode_rgb_png(WIDTH, HEIGHT, &rgb, None).unwrap()),
            ("RGB+tRNS", encode_rgb_png(WIDTH, HEIGHT, &rgb, Some(&key)).unwrap()),
            ("RGBA", encode_rgba_png(WIDTH, HEIGHT, &truecolor(4)).unwrap()),
            (
                "4-bit indexed",
                encode_indexed_preserving(WIDTH, HEIGHT, 4, &indices, &palette, Some(&[0, 60, 120, 180]))
                    .unwrap(),
            ),
        ];
        for (label, png) in cases {
            let mut expected = png.clone();
            resize_image(&mut expected, 101, 87).unwrap();

            // Decode exactly as optimize_image does.
            let decoded = if read_png_ihdr(&png).unwrap().color_type == INDEXED_PLTE {
                Decoded::Native(decode_png_native(&png, false).unwrap())
            } else {
                Decoded::Truecolor(decode_png_truecolor(&png).unwrap())
            };
            let mut actual = Vec::new();
            resize_decoded(&mut actual, decoded.into_resize_input().unwrap(), 101, 87).unwrap();
            assert!(actual == expected, "{label}: decoded resize differs from file resize");
        }
    }

    // Covers with up to 256 colors (alpha included; an RGB color key counts as
    // transparent) become an indexed PNG whose palette lists the colors in
    // order of first appearance. A 257th color keeps the cover truecolor.
    #[test]
    fn palette_conversion_limit() {
        const HEIGHT: u32 = 68;
        const KEY_INDEX: usize = 3;
        for (label, color_type, keyed) in [
            ("RGB", TRUECOLOR_RGB, false),
            ("RGB+tRNS", TRUECOLOR_RGB, true),
            ("RGBA", TRUECOLOR_RGBA, false),
        ] {
            let mut width = MIN_DIMS;
            while !candidate_ihdr_is_linux_safe(width, HEIGHT, 8, INDEXED_PLTE)
                || !candidate_ihdr_is_linux_safe(width, HEIGHT, 8, color_type)
            {
                width += 1;
            }
            let channels = if color_type == TRUECOLOR_RGBA { 4 } else { 3 };
            let color = |i: usize| -> [u8; 4] {
                let alpha = if channels == 4 && i % 5 == 0 { 128 } else { 255 };
                [(i & 0xFF) as u8, (i >> 8) as u8, (i * 7) as u8, alpha]
            };
            for colors in [1usize, 256, 257] {
                let pixel_count = (width * HEIGHT) as usize;
                let pixels: Vec<u8> = (0..pixel_count)
                    .flat_map(|i| color(i % colors).into_iter().take(channels))
                    .collect();
                let key = color(KEY_INDEX);
                let mut png = if channels == 4 {
                    encode_rgba_png(width, HEIGHT, &pixels).unwrap()
                } else {
                    let trns = [0, key[0], 0, key[1], 0, key[2]];
                    encode_rgb_png(width, HEIGHT, &pixels, keyed.then_some(&trns[..])).unwrap()
                };
                optimize_image(&mut png).unwrap();

                let ihdr = read_png_ihdr(&png).unwrap();
                assert_eq!((ihdr.width, ihdr.height), (width, HEIGHT), "{label} {colors}: resized");
                if colors > 256 {
                    assert_eq!(ihdr.color_type, color_type, "{label}: 257 colors not kept truecolor");
                    continue;
                }
                assert_eq!((ihdr.color_type, ihdr.bit_depth), (INDEXED_PLTE, 8), "{label} {colors}");
                let decoded = decode_png_preserving(&png).unwrap();
                let palette = decoded.palette.unwrap();
                let trns = decoded.trns.unwrap_or_default();
                assert_eq!(palette.len(), colors * 3, "{label} {colors}: palette size");
                for i in 0..colors {
                    let mut expected = color(i);
                    if keyed && i == KEY_INDEX {
                        expected[3] = 0;
                    }
                    let alpha = trns.get(i).copied().unwrap_or(255);
                    assert_eq!(
                        [palette[i * 3], palette[i * 3 + 1], palette[i * 3 + 2], alpha],
                        expected,
                        "{label} {colors}: palette entry {i} out of first-appearance order"
                    );
                }
                assert!(
                    decoded.pixels.iter().enumerate().all(|(i, index)| usize::from(*index) == i % colors),
                    "{label} {colors}: pixel maps to the wrong palette index"
                );
            }
        }
    }
}
