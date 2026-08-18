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
const IHDR_SIG: [u8; 4] = [b'I', b'H', b'D', b'R'];
const PLTE_SIG: [u8; 4] = [b'P', b'L', b'T', b'E'];
const TRNS_SIG: [u8; 4] = [b't', b'R', b'N', b'S'];
const IDAT_SIG: [u8; 4] = [b'I', b'D', b'A', b'T'];
const IEND_SIG: [u8; 4] = [b'I', b'E', b'N', b'D'];

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
const MAX_RESIZE_DELTA: u32 = 200;

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

#[derive(Debug, Clone)]
struct DecodedRgba {
    width: u32,
    height: u32,
    original_color_type: ParsedColorType,
    rgba: Vec<u8>,
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

fn check_final_compatibility(ihdr: PngIhdr) -> ImageResult<()> {
    let has_valid_color_type = matches!(
        ihdr.color_type,
        INDEXED_PLTE | TRUECOLOR_RGB | TRUECOLOR_RGBA
    );

    let has_valid_dimensions = ((ihdr.color_type == TRUECOLOR_RGB
        || ihdr.color_type == TRUECOLOR_RGBA)
        && ihdr.width >= MIN_DIMS
        && ihdr.width <= MAX_RGB_DIMS
        && ihdr.height >= MIN_DIMS
        && ihdr.height <= MAX_RGB_DIMS)
        || (ihdr.color_type == INDEXED_PLTE
            && ihdr.width >= MIN_DIMS
            && ihdr.width <= MAX_PLTE_DIMS
            && ihdr.height >= MIN_DIMS
            && ihdr.height <= MAX_PLTE_DIMS);

    if !has_valid_color_type {
        return Err(
            "\nImage File Error: Color type of cover image is not supported.\n\n\
             Supported types: PNG-32/24 (Truecolor) or PNG-8 (Indexed-Color).\n\
             Incompatible image. Aborting."
                .to_string(),
        );
    }
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

fn decode_png_to_rgba(png_data: &[u8]) -> ImageResult<DecodedRgba> {
    let ihdr = read_png_ihdr(png_data)?;
    validate_input_png_for_decode(ihdr)?;
    verify_idat_inflate_size(png_data, ihdr)?;

    let mut decoder = strict_png_decoder(png_data);
    decoder.set_transformations(Transformations::EXPAND);

    let mut reader = decoder.read_info().map_err(map_png_error)?;
    let original_color_type = match reader.info().color_type {
        ColorType::Rgb => ParsedColorType::Rgb,
        ColorType::Rgba => ParsedColorType::Rgba,
        ColorType::Indexed => ParsedColorType::Indexed,
        _ => ParsedColorType::Unsupported,
    };

    let mut buf = zeroed_vec(
        reader.output_buffer_size(),
        "PNG Error: Decoded image buffer exceeds available memory.",
    )?;
    let out_info = reader.next_frame(&mut buf).map_err(map_png_error)?;
    let used = out_info.buffer_size();
    reader.finish().map_err(map_png_error)?;
    buf.truncate(used);

    let rgba = match out_info.color_type {
        ColorType::Rgb => {
            if used % 3 != 0 {
                return Err("PNG Error: Decoded RGB buffer is truncated.".to_string());
            }
            let capacity = checked_mul(
                used / 3,
                4,
                "PNG Error: Expanded RGBA buffer size overflow.",
            )?;
            let mut out = vec_with_capacity(
                capacity,
                "PNG Error: Expanded RGBA buffer exceeds available memory.",
            )?;
            for px in buf.chunks_exact(3) {
                out.extend_from_slice(&[px[0], px[1], px[2], 0xFF]);
            }
            out
        }
        ColorType::Rgba => buf,
        ColorType::Grayscale => {
            let capacity = checked_mul(used, 4, "PNG Error: Expanded RGBA buffer size overflow.")?;
            let mut out = vec_with_capacity(
                capacity,
                "PNG Error: Expanded RGBA buffer exceeds available memory.",
            )?;
            for gray in buf {
                out.extend_from_slice(&[gray, gray, gray, 0xFF]);
            }
            out
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
            out
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
    let expected_rgba = checked_mul(
        pixel_count,
        4,
        "PNG Error: Decoded RGBA buffer size overflow.",
    )?;
    if rgba.len() != expected_rgba {
        return Err("PNG Error: Decoded RGBA buffer length mismatch.".to_string());
    }

    Ok(DecodedRgba {
        width: out_info.width,
        height: out_info.height,
        original_color_type,
        rgba,
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

fn decode_png_preserving(png_data: &[u8]) -> ImageResult<DecodedPreserved> {
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

            let mut unpacked = zeroed_vec(
                pixel_count,
                "PNG Error: Unpacked indexed image exceeds available memory.",
            )?;
            let mask = (1u16 << depth) - 1;
            for (y, row) in encoded_pixels.chunks_exact(out_info.line_size).enumerate() {
                let output_row = y * width;
                for x in 0..width {
                    let bit_offset =
                        checked_mul(x, depth, "PNG Error: Indexed row bit offset overflow.")?;
                    let shift = 8usize - depth - (bit_offset % 8);
                    let index = (u16::from(row[bit_offset / 8]) >> shift) & mask;
                    if usize::from(index) >= palette.len() / 3 {
                        return Err("PNG Error: Palette index exceeds PLTE size.".to_string());
                    }
                    unpacked[output_row + x] = index as u8;
                }
            }
            unpacked
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

fn encode_indexed_from_rgba(width: u32, height: u32, rgba: &[u8]) -> ImageResult<Vec<u8>> {
    validate_pixel_buffer(width, height, 4, rgba)?;
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

    for px in rgba.chunks_exact(4) {
        let key = (u32::from(px[0]) << 24)
            | (u32::from(px[1]) << 16)
            | (u32::from(px[2]) << 8)
            | u32::from(px[3]);

        let idx = if let Some(existing) = color_to_index.get(&key) {
            *existing
        } else {
            if palette_rgba.len() >= 256 {
                return Err("Image Error: Palette conversion exceeded 256 colors.".to_string());
            }
            let next = palette_rgba.len() as u8;
            palette_rgba.push([px[0], px[1], px[2], px[3]]);
            color_to_index.insert(key, next);
            next
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

    let mut out = Vec::<u8>::new();
    {
        let mut encoder = Encoder::new(&mut out, width, height);
        encoder.set_color(ColorType::Indexed);
        encoder.set_depth(BitDepth::Eight);
        encoder.set_palette(palette);

        if let Some(last_idx) = last_non_opaque {
            trns.truncate(last_idx + 1);
            encoder.set_trns(trns);
        }

        let mut writer = encoder.write_header().map_err(map_png_encode_error)?;
        writer
            .write_image_data(&indices)
            .map_err(map_png_encode_error)?;
    }
    Ok(out)
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

    let packed = pack_palette_indices(width, height, bit_depth, indices)?;
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

fn can_palettize(decoded: &DecodedRgba) -> ImageResult<bool> {
    if !matches!(
        decoded.original_color_type,
        ParsedColorType::Rgb | ParsedColorType::Rgba
    ) {
        return Ok(false);
    }

    let mut color_to_seen = HashMap::<u32, ()>::new();
    color_to_seen
        .try_reserve(MIN_RGB_COLORS)
        .map_err(|_| "Image Error: Color statistics exceed available memory.".to_string())?;
    for px in decoded.rgba.chunks_exact(4) {
        let key = (u32::from(px[0]) << 24)
            | (u32::from(px[1]) << 16)
            | (u32::from(px[2]) << 8)
            | u32::from(px[3]);
        color_to_seen.insert(key, ());
        if color_to_seen.len() >= MIN_RGB_COLORS {
            return Ok(false);
        }
    }

    Ok(!color_to_seen.is_empty())
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
            let top_left_weight = (1.0 - dx) * (1.0 - dy);
            let top_right_weight = dx * (1.0 - dy);
            let bottom_left_weight = (1.0 - dx) * dy;
            let bottom_right_weight = dx * dy;

            for c in 0..channels {
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
                out[out_base + c] = value.round().clamp(0.0, 255.0) as u8;
            }
        }
    }

    Ok(out)
}

fn resize_image(image_file_vec: &mut Vec<u8>, new_width: u32, new_height: u32) -> ImageResult<()> {
    let decoded = decode_png_preserving(image_file_vec)?;
    if new_width < MIN_DIMS || new_height < MIN_DIMS {
        return Err("Image Error: Resize target dimensions are below the minimum.".to_string());
    }
    if new_width > decoded.width || new_height > decoded.height {
        return Err("Image Error: Resize target must not exceed source dimensions.".to_string());
    }
    if new_width == decoded.width && new_height == decoded.height {
        return Ok(());
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

fn ensure_linux_safe_ihdr(image_file_vec: &mut Vec<u8>) -> ImageResult<()> {
    if !has_problem_character(image_file_vec)? {
        return Ok(());
    }

    let current = read_png_ihdr(image_file_vec)?;
    let (new_width, new_height) = find_linux_safe_resize_target(current).ok_or_else(|| {
        "Image Error: Could not eliminate problem characters from IHDR within the resize iteration limit."
            .to_string()
    })?;
    resize_image(image_file_vec, new_width, new_height)?;

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

    match color_type_from_ihdr(initial_ihdr.color_type) {
        ParsedColorType::Rgb | ParsedColorType::Rgba => {
            let decoded = decode_png_to_rgba(image_file_vec)?;
            if can_palettize(&decoded)? {
                *image_file_vec =
                    encode_indexed_from_rgba(decoded.width, decoded.height, &decoded.rgba)?;
            } else {
                strip_and_copy_chunks(image_file_vec, initial_ihdr.color_type)?;
            }
        }
        ParsedColorType::Indexed => {
            // Indexed images do not need expansion for color statistics, but
            // they still need a full bounded decode to validate IDAT and PLTE.
            let _ = decode_png_preserving(image_file_vec)?;
            strip_and_copy_chunks(image_file_vec, initial_ihdr.color_type)?;
        }
        ParsedColorType::Unsupported => {
            unreachable!("input validation rejects unsupported PNG color types");
        }
    }

    ensure_linux_safe_ihdr(image_file_vec)?;

    let final_ihdr = read_png_ihdr(image_file_vec)?;
    check_final_compatibility(final_ihdr)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crc32fast::Hasher;
    use flate2::{Compression, write::ZlibEncoder};
    use png::{BitDepth, ColorType, Encoder};

    use super::{
        IEND_SIG, INDEXED_PLTE, MIN_DIMS, PngIhdr, TRUECOLOR_RGB, candidate_ihdr_is_linux_safe,
        decode_png_preserving, encode_indexed_preserving, optimize_image,
        png_inflated_scanline_size, read_png_ihdr, resize_image,
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
    fn rgb_transparency_key_survives_resize() {
        let width = 80;
        let height = 80;
        let rgb = high_color_rgb(width, height);
        let trns = [0, rgb[0], 0, rgb[1], 0, rgb[2]];
        let mut png = encode_rgb_png_with_trns(width, height, &rgb, &trns);

        resize_image(&mut png, width - 1, height).expect("RGB image should resize");
        let decoded = decode_png_preserving(&png).expect("resized RGB should decode");
        assert_eq!(decoded.color_type, super::ParsedColorType::Rgb);
        assert_eq!(decoded.trns.as_deref(), Some(trns.as_slice()));
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
    fn rejects_truecolor_16_bit_before_decode() {
        let rgb16 = vec![0u8; (MIN_DIMS * MIN_DIMS * 6) as usize];
        let mut png = encode_rgb16_png(MIN_DIMS, MIN_DIMS, &rgb16);
        let err = optimize_image(&mut png).expect_err("16-bit truecolor is unsupported");
        assert!(err.contains("Unsupported PNG bit depth"));
    }
}
