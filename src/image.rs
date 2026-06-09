use std::collections::HashMap;
use std::io::Cursor;

use png::{BitDepth, ColorType, Decoder, Encoder, Transformations};

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

const LINUX_PROBLEM_METACHARACTERS: [u8; 7] = [0x22, 0x27, 0x28, 0x29, 0x3B, 0x3E, 0x60];

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
const MAX_RESIZE_ITERATIONS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PngIhdr {
    width: u32,
    height: u32,
    color_type: u8,
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
    const COLOR_TYPE_INDEX: usize = 25;
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
        color_type: png_data[COLOR_TYPE_INDEX],
    })
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
    let mut cleaned_png = Vec::<u8>::with_capacity(image_file_vec.len());
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
            .any(|byte| LINUX_PROBLEM_METACHARACTERS.contains(byte))
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

fn decode_png_to_rgba(png_data: &[u8]) -> ImageResult<DecodedRgba> {
    let mut decoder = Decoder::new(Cursor::new(png_data));
    decoder.set_transformations(Transformations::EXPAND | Transformations::STRIP_16);

    let mut reader = decoder.read_info().map_err(map_png_error)?;
    let info = reader.info();
    let original_color_type = match info.color_type {
        ColorType::Rgb => ParsedColorType::Rgb,
        ColorType::Rgba => ParsedColorType::Rgba,
        ColorType::Indexed => ParsedColorType::Indexed,
        _ => ParsedColorType::Unsupported,
    };

    let mut buf = vec![0u8; reader.output_buffer_size()];
    let out_info = reader.next_frame(&mut buf).map_err(map_png_error)?;
    let used = out_info.buffer_size();
    buf.truncate(used);

    let rgba = match out_info.color_type {
        ColorType::Rgb => {
            let mut out = Vec::<u8>::with_capacity((used / 3) * 4);
            for px in buf.chunks_exact(3) {
                out.extend_from_slice(&[px[0], px[1], px[2], 0xFF]);
            }
            out
        }
        ColorType::Rgba => buf,
        ColorType::Grayscale => {
            let mut out = Vec::<u8>::with_capacity(used * 4);
            for gray in buf {
                out.extend_from_slice(&[gray, gray, gray, 0xFF]);
            }
            out
        }
        ColorType::GrayscaleAlpha => {
            let mut out = Vec::<u8>::with_capacity((used / 2) * 4);
            for px in buf.chunks_exact(2) {
                out.extend_from_slice(&[px[0], px[0], px[0], px[1]]);
            }
            out
        }
        ColorType::Indexed => {
            return Err("PNG Error: Unexpected indexed output after expansion.".to_string());
        }
    };

    Ok(DecodedRgba {
        width: out_info.width,
        height: out_info.height,
        original_color_type,
        rgba,
    })
}

fn encode_rgb_png(width: u32, height: u32, rgb: &[u8]) -> ImageResult<Vec<u8>> {
    let mut out = Vec::<u8>::new();
    {
        let mut encoder = Encoder::new(&mut out, width, height);
        encoder.set_color(ColorType::Rgb);
        encoder.set_depth(BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(map_png_encode_error)?;
        writer.write_image_data(rgb).map_err(map_png_encode_error)?;
    }
    Ok(out)
}

fn encode_rgba_png(width: u32, height: u32, rgba: &[u8]) -> ImageResult<Vec<u8>> {
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
    let pixel_count = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| "Image Error: Pixel count overflow.".to_string())?;
    if rgba.len() != pixel_count * 4 {
        return Err("Image Error: RGBA buffer length mismatch.".to_string());
    }

    let mut color_to_index = HashMap::<u32, u8>::new();
    let mut palette_rgba = Vec::<[u8; 4]>::new();
    let mut indices = Vec::<u8>::with_capacity(pixel_count);

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

    let mut palette = Vec::<u8>::with_capacity(palette_rgba.len() * 3);
    let mut trns = Vec::<u8>::with_capacity(palette_rgba.len());
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

fn can_palettize(decoded: &DecodedRgba) -> bool {
    if !matches!(
        decoded.original_color_type,
        ParsedColorType::Rgb | ParsedColorType::Rgba
    ) {
        return false;
    }

    let mut color_to_seen = HashMap::<u32, ()>::new();
    for px in decoded.rgba.chunks_exact(4) {
        let key = (u32::from(px[0]) << 24)
            | (u32::from(px[1]) << 16)
            | (u32::from(px[2]) << 8)
            | u32::from(px[3]);
        color_to_seen.insert(key, ());
        if color_to_seen.len() >= MIN_RGB_COLORS {
            return false;
        }
    }

    !color_to_seen.is_empty()
}

fn resize_rgba(
    src: &[u8],
    width: u32,
    height: u32,
    new_width: u32,
    new_height: u32,
    nearest: bool,
) -> Vec<u8> {
    let mut out = vec![0u8; (new_width as usize) * (new_height as usize) * 4];

    let x_ratio = width as f64 / new_width as f64;
    let y_ratio = height as f64 / new_height as f64;
    let sample_offset = 0.5f64;

    for y in 0..new_height {
        for x in 0..new_width {
            let src_x = ((x as f64 + sample_offset) * x_ratio - sample_offset)
                .clamp(0.0, (width - 1) as f64);
            let src_y = ((y as f64 + sample_offset) * y_ratio - sample_offset)
                .clamp(0.0, (height - 1) as f64);

            let out_base = ((y as usize) * (new_width as usize) + x as usize) * 4;

            if nearest {
                let ix = src_x.round() as u32;
                let iy = src_y.round() as u32;
                let src_base = ((iy as usize) * (width as usize) + ix as usize) * 4;
                out[out_base..out_base + 4].copy_from_slice(&src[src_base..src_base + 4]);
                continue;
            }

            let x0 = src_x.floor() as u32;
            let y0 = src_y.floor() as u32;
            let x1 = (x0 + 1).min(width - 1);
            let y1 = (y0 + 1).min(height - 1);
            let dx = src_x - x0 as f64;
            let dy = src_y - y0 as f64;

            for c in 0..4usize {
                let p00 = src[((y0 as usize) * (width as usize) + x0 as usize) * 4 + c] as f64;
                let p10 = src[((y0 as usize) * (width as usize) + x1 as usize) * 4 + c] as f64;
                let p01 = src[((y1 as usize) * (width as usize) + x0 as usize) * 4 + c] as f64;
                let p11 = src[((y1 as usize) * (width as usize) + x1 as usize) * 4 + c] as f64;

                let value = (1.0 - dx) * (1.0 - dy) * p00
                    + dx * (1.0 - dy) * p10
                    + (1.0 - dx) * dy * p01
                    + dx * dy * p11;
                out[out_base + c] = value.round().clamp(0.0, 255.0) as u8;
            }
        }
    }

    out
}

fn resize_image_one_pixel(image_file_vec: &mut Vec<u8>) -> ImageResult<()> {
    let ihdr = read_png_ihdr(image_file_vec)?;
    if ihdr.width <= MIN_DIMS || ihdr.height <= MIN_DIMS {
        return Err("Image dimensions too small to reduce.".to_string());
    }

    let decoded = decode_png_to_rgba(image_file_vec)?;
    let new_width = decoded.width - 1;
    let new_height = decoded.height - 1;
    let use_nearest = ihdr.color_type == INDEXED_PLTE;

    let resized_rgba = resize_rgba(
        &decoded.rgba,
        decoded.width,
        decoded.height,
        new_width,
        new_height,
        use_nearest,
    );

    *image_file_vec = match ihdr.color_type {
        INDEXED_PLTE => encode_indexed_from_rgba(new_width, new_height, &resized_rgba)?,
        TRUECOLOR_RGB => {
            let mut rgb =
                Vec::<u8>::with_capacity((new_width as usize) * (new_height as usize) * 3);
            for px in resized_rgba.chunks_exact(4) {
                rgb.extend_from_slice(&px[0..3]);
            }
            encode_rgb_png(new_width, new_height, &rgb)?
        }
        TRUECOLOR_RGBA => encode_rgba_png(new_width, new_height, &resized_rgba)?,
        _ => {
            return Err(
                "Image File Error: Color type of cover image is not supported.".to_string(),
            );
        }
    };

    Ok(())
}

pub fn optimize_image(image_file_vec: &mut Vec<u8>) -> ImageResult<()> {
    let initial_ihdr = read_png_ihdr(image_file_vec)?;

    match color_type_from_ihdr(initial_ihdr.color_type) {
        ParsedColorType::Rgb | ParsedColorType::Rgba => {
            let decoded = decode_png_to_rgba(image_file_vec)?;
            if can_palettize(&decoded) {
                *image_file_vec =
                    encode_indexed_from_rgba(decoded.width, decoded.height, &decoded.rgba)?;
            } else {
                strip_and_copy_chunks(image_file_vec, initial_ihdr.color_type)?;
            }
        }
        ParsedColorType::Indexed => {
            strip_and_copy_chunks(image_file_vec, initial_ihdr.color_type)?;
        }
        ParsedColorType::Unsupported => {
            return check_final_compatibility(initial_ihdr);
        }
    }

    let mut iterations = 0usize;
    while has_problem_character(image_file_vec)? {
        iterations += 1;
        if iterations > MAX_RESIZE_ITERATIONS {
            return Err(
                "Image Error: Could not eliminate problem characters from IHDR within the resize iteration limit."
                    .to_string(),
            );
        }
        resize_image_one_pixel(image_file_vec)?;
    }

    let final_ihdr = read_png_ihdr(image_file_vec)?;
    check_final_compatibility(final_ihdr)
}

#[cfg(test)]
mod tests {
    use crc32fast::Hasher;
    use png::{BitDepth, ColorType, Encoder};

    use super::{INDEXED_PLTE, TRUECOLOR_RGB, optimize_image, read_png_ihdr};

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
        let text_chunk = png_chunk(b"tEXt", b"author=unit-test");
        png_data.splice(iend_chunk_start..iend_chunk_start, text_chunk);
        png_data
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
        assert_eq!(ihdr.width, width);
        assert_eq!(ihdr.height, height);
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
        assert!(err.contains("Color type of cover image is not supported"));
    }

    #[test]
    fn rejects_out_of_range_truecolor_dimensions() {
        let width = 1000u32;
        let height = 100u32;
        let mut rgb = Vec::<u8>::with_capacity((width * height * 3) as usize);
        for i in 0..(width * height) {
            let idx = i as u32;
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
            let idx = i as u32;
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
}
