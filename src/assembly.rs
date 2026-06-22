use crate::binary_utils::{self, ByteOrder, write_value_at};
use crc32fast::Hasher;

pub type AssemblyResult<T> = Result<T, String>;

const ZIP_LOCAL_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const END_CENTRAL_DIR_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const CENTRAL_DIR_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZipEocdInfo {
    index: usize,
    total_records: u16,
    central_size: u32,
    central_offset: u32,
    comment_length: u16,
}

fn read_le16(data: &[u8], offset: usize) -> AssemblyResult<u16> {
    binary_utils::read_le16(data, offset).map_err(|err| format!("ZIP Error: {err}"))
}

fn read_le32(data: &[u8], offset: usize) -> AssemblyResult<u32> {
    binary_utils::read_le32(data, offset).map_err(|err| format!("ZIP Error: {err}"))
}

fn write_le16(data: &mut [u8], offset: usize, value: u16) -> AssemblyResult<()> {
    binary_utils::write_le16(data, offset, value).map_err(|err| format!("ZIP Error: {err}"))
}

fn write_le32(data: &mut [u8], offset: usize, value: u32) -> AssemblyResult<()> {
    binary_utils::write_le32(data, offset, value).map_err(|err| format!("ZIP Error: {err}"))
}

fn find_zip_eocd(image_vec: &[u8], zip_base_offset: usize) -> AssemblyResult<ZipEocdInfo> {
    const EOCD_MIN_SIZE: usize = 22;
    const EOCD_TOTAL_RECORDS_OFFSET: usize = 10;
    const EOCD_CENTRAL_SIZE_OFFSET: usize = 12;
    const EOCD_CENTRAL_OFFSET: usize = 16;
    const EOCD_COMMENT_LENGTH: usize = 20;
    const MAX_EOCD_SEARCH_DISTANCE: usize = 65557; // EOCD_MIN_SIZE + max 65535-byte comment.

    if image_vec.len() < EOCD_MIN_SIZE {
        return Err("ZIP Error: Archive is too small.".to_string());
    }

    // Bound the backward search to the archive region and the maximum
    // possible EOCD distance from the end of the file.
    let distance_floor = image_vec.len().saturating_sub(MAX_EOCD_SEARCH_DISTANCE);
    let search_floor = zip_base_offset.max(distance_floor);

    let mut saw_empty_records = false;
    let mut saw_zip64 = false;

    let mut pos = image_vec.len() - END_CENTRAL_DIR_SIG.len();
    loop {
        if image_vec[pos..pos + END_CENTRAL_DIR_SIG.len()] == END_CENTRAL_DIR_SIG {
            if let Some(eocd_end_min) = pos.checked_add(EOCD_MIN_SIZE) {
                if eocd_end_min <= image_vec.len() {
                    let info = ZipEocdInfo {
                        index: pos,
                        total_records: read_le16(image_vec, pos + EOCD_TOTAL_RECORDS_OFFSET)?,
                        central_size: read_le32(image_vec, pos + EOCD_CENTRAL_SIZE_OFFSET)?,
                        central_offset: read_le32(image_vec, pos + EOCD_CENTRAL_OFFSET)?,
                        comment_length: read_le16(image_vec, pos + EOCD_COMMENT_LENGTH)?,
                    };

                    let comment_end = binary_utils::checked_add(
                        eocd_end_min,
                        usize::from(info.comment_length),
                        "ZIP Error: End of Central Directory comment exceeds file size.",
                    );

                    if let Ok(comment_end) = comment_end {
                        if comment_end <= image_vec.len() {
                            if info.total_records == 0 {
                                saw_empty_records = true;
                            } else if info.total_records == u16::MAX
                                || info.central_size == u32::MAX
                                || info.central_offset == u32::MAX
                            {
                                saw_zip64 = true;
                            } else {
                                let central_start = binary_utils::checked_add(
                                    zip_base_offset,
                                    info.central_offset as usize,
                                    "ZIP Error: Central directory offset overflow.",
                                )?;
                                let central_end = binary_utils::checked_add(
                                    central_start,
                                    info.central_size as usize,
                                    "ZIP Error: Central directory size overflow.",
                                )?;

                                if central_start <= image_vec.len()
                                    && central_end <= image_vec.len()
                                    && central_end == pos
                                {
                                    return Ok(info);
                                }
                            }
                        }
                    }
                }
            }
        }

        if pos <= search_floor {
            break;
        }
        pos -= 1;
    }

    if saw_zip64 {
        return Err("ZIP Error: ZIP64 archives are not supported.".to_string());
    }
    if saw_empty_records {
        return Err("ZIP Error: Archive contains no records.".to_string());
    }
    Err("ZIP Error: End of Central Directory signature not found.".to_string())
}

fn fix_zip_offsets(
    image_vec: &mut [u8],
    original_image_size: usize,
    script_data_size: usize,
) -> AssemblyResult<()> {
    const ZIP_BASE_SHIFT: usize = 8;
    const PNG_TRAILING_BYTES: usize = 16;
    const CENTRAL_RECORD_MIN_SIZE: usize = 46;
    const CENTRAL_NAME_LENGTH_OFFSET: usize = 28;
    const CENTRAL_EXTRA_LENGTH_OFFSET: usize = 30;
    const CENTRAL_COMMENT_LENGTH_OFFSET: usize = 32;
    const CENTRAL_LOCAL_OFFSET_OFFSET: usize = 42;

    let zip_base_offset = binary_utils::checked_add(
        binary_utils::checked_add(
            original_image_size,
            script_data_size,
            "ZIP Error: Base offset overflow.",
        )?,
        ZIP_BASE_SHIFT,
        "ZIP Error: Base offset overflow.",
    )?;

    let eocd = find_zip_eocd(image_vec, zip_base_offset)?;
    let central_start = binary_utils::checked_add(
        zip_base_offset,
        eocd.central_offset as usize,
        "ZIP Error: Central directory offset overflow.",
    )?;
    let central_end = binary_utils::checked_add(
        central_start,
        eocd.central_size as usize,
        "ZIP Error: Central directory size overflow.",
    )?;

    if central_start > image_vec.len() || central_end > image_vec.len() || central_end != eocd.index
    {
        return Err("ZIP Error: Central directory bounds are invalid.".to_string());
    }
    if central_start > u32::MAX as usize {
        return Err("ZIP Error: Central directory offset exceeds ZIP32 limits.".to_string());
    }
    if usize::from(eocd.comment_length) > (u16::MAX as usize - PNG_TRAILING_BYTES) {
        return Err("ZIP Error: Comment length overflow.".to_string());
    }

    write_le16(
        image_vec,
        eocd.index + 20,
        (usize::from(eocd.comment_length) + PNG_TRAILING_BYTES) as u16,
    )?;
    write_le32(image_vec, eocd.index + 16, central_start as u32)?;

    let mut cursor = central_start;
    for record_index in 0..usize::from(eocd.total_records) {
        if cursor > image_vec.len() || CENTRAL_RECORD_MIN_SIZE > image_vec.len() - cursor {
            return Err("ZIP Error: Truncated central directory file header.".to_string());
        }
        if image_vec[cursor..cursor + CENTRAL_DIR_SIG.len()] != CENTRAL_DIR_SIG {
            return Err(format!(
                "ZIP Error: Invalid central directory file header signature at record {}.",
                record_index + 1
            ));
        }

        let name_length = read_le16(image_vec, cursor + CENTRAL_NAME_LENGTH_OFFSET)? as usize;
        let extra_length = read_le16(image_vec, cursor + CENTRAL_EXTRA_LENGTH_OFFSET)? as usize;
        let comment_length = read_le16(image_vec, cursor + CENTRAL_COMMENT_LENGTH_OFFSET)? as usize;
        let record_size = binary_utils::checked_add(
            binary_utils::checked_add(
                binary_utils::checked_add(
                    CENTRAL_RECORD_MIN_SIZE,
                    name_length,
                    "ZIP Error: Central directory entry size overflow.",
                )?,
                extra_length,
                "ZIP Error: Central directory entry size overflow.",
            )?,
            comment_length,
            "ZIP Error: Central directory entry size overflow.",
        )?;

        if record_size > image_vec.len() - cursor || cursor + record_size > central_end {
            return Err("ZIP Error: Central directory entry exceeds archive bounds.".to_string());
        }

        let local_offset = binary_utils::checked_add(
            zip_base_offset,
            read_le32(image_vec, cursor + CENTRAL_LOCAL_OFFSET_OFFSET)? as usize,
            "ZIP Error: Local file header offset overflow.",
        )?;
        if local_offset > u32::MAX as usize {
            return Err("ZIP Error: Local file header offset exceeds ZIP32 limits.".to_string());
        }
        if local_offset >= central_start || 4 > image_vec.len() - local_offset {
            return Err("ZIP Error: Local file header offset is out of bounds.".to_string());
        }
        if image_vec[local_offset..local_offset + ZIP_LOCAL_SIG.len()] != ZIP_LOCAL_SIG {
            return Err(format!(
                "ZIP Error: Local file header signature mismatch for record {}.",
                record_index + 1
            ));
        }

        write_le32(
            image_vec,
            cursor + CENTRAL_LOCAL_OFFSET_OFFSET,
            local_offset as u32,
        )?;
        cursor += record_size;
    }

    if cursor != central_end {
        return Err("ZIP Error: Central directory size does not match parsed records.".to_string());
    }

    Ok(())
}

pub fn embed_chunks(
    image_vec: &mut Vec<u8>,
    mut script_vec: Vec<u8>,
    mut archive_vec: Vec<u8>,
    original_image_size: usize,
) -> AssemblyResult<()> {
    const ICCP_CHUNK_INDEX: usize = 0x21;
    const VALUE_BYTE_LENGTH_FOUR: usize = 4;
    const ARCHIVE_INSERT_INDEX_DIFF: usize = 12;
    const EXCLUDE_SIZE_AND_CRC_LENGTH: usize = 8;
    const LAST_IDAT_INDEX_DIFF: usize = 4;
    const LAST_IDAT_CRC_INDEX_DIFF: usize = 16;
    const CHUNK_FIELDS_COMBINED_LENGTH: usize = 12;

    if script_vec.len() < CHUNK_FIELDS_COMBINED_LENGTH {
        return Err("Script Error: iCCP chunk is truncated.".to_string());
    }
    if image_vec.len() < ICCP_CHUNK_INDEX {
        return Err("PNG Error: Cover image is too small for iCCP insertion.".to_string());
    }
    if image_vec.len() < ARCHIVE_INSERT_INDEX_DIFF {
        return Err("PNG Error: Cover image is truncated before IEND.".to_string());
    }
    if archive_vec.len() < EXCLUDE_SIZE_AND_CRC_LENGTH {
        return Err("ZIP Error: Archive data is truncated.".to_string());
    }

    let script_data_size = script_vec.len() - CHUNK_FIELDS_COMBINED_LENGTH;
    let archive_file_size = archive_vec.len();

    image_vec.reserve(image_vec.len() + script_vec.len() + archive_vec.len());

    image_vec.splice(ICCP_CHUNK_INDEX..ICCP_CHUNK_INDEX, script_vec.drain(..));
    let archive_insert_index = image_vec.len() - ARCHIVE_INSERT_INDEX_DIFF;
    image_vec.splice(
        archive_insert_index..archive_insert_index,
        archive_vec.drain(..),
    );

    fix_zip_offsets(image_vec, original_image_size, script_data_size)?;

    let last_idat_index = binary_utils::checked_add(
        binary_utils::checked_add(
            original_image_size,
            script_data_size,
            "ZIP Error: Size overflow while computing CRC start.",
        )?,
        LAST_IDAT_INDEX_DIFF,
        "ZIP Error: Size overflow while computing CRC start.",
    )?;
    let crc_len = archive_file_size - EXCLUDE_SIZE_AND_CRC_LENGTH;
    let crc_end = binary_utils::checked_add(
        last_idat_index,
        crc_len,
        "ZIP Error: Size overflow while computing CRC range.",
    )?;
    if crc_end > image_vec.len() {
        return Err("ZIP Error: Invalid IDAT CRC range.".to_string());
    }

    let mut hasher = Hasher::new();
    hasher.update(&image_vec[last_idat_index..crc_end]);
    let last_idat_crc = hasher.finalize();

    let complete_size = image_vec.len();
    if complete_size < LAST_IDAT_CRC_INDEX_DIFF {
        return Err("ZIP Error: Output is truncated before final IDAT CRC.".to_string());
    }
    let crc_index = complete_size - LAST_IDAT_CRC_INDEX_DIFF;
    write_value_at(
        image_vec,
        crc_index,
        last_idat_crc as usize,
        VALUE_BYTE_LENGTH_FOUR,
        ByteOrder::Big,
    )
    .map_err(|err| format!("ZIP Error: {err}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::embed_chunks;
    use crate::binary_utils::{ByteOrder, read_value_at, write_value_at};

    fn base_image() -> Vec<u8> {
        include_bytes!("../tests/fixtures/assembly_base_image.bin").to_vec()
    }

    fn base_image_size() -> usize {
        include_str!("../tests/fixtures/assembly_base_image_size.txt")
            .trim()
            .parse()
            .expect("base image size fixture must parse")
    }

    #[test]
    fn parity_zip_video_fixture() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let archive = include_bytes!("../tests/fixtures/assembly_zip_video.archive.bin").to_vec();
        let expected = include_bytes!("../tests/fixtures/assembly_zip_video.out.bin").to_vec();

        embed_chunks(&mut image, script, archive, base_image_size()).expect("embed zip fixture");
        assert_eq!(image, expected);
    }

    #[test]
    fn parity_jar_fixture() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_jar_manifest.script.bin").to_vec();
        let archive =
            include_bytes!("../tests/fixtures/assembly_jar_manifest.archive.bin").to_vec();
        let expected = include_bytes!("../tests/fixtures/assembly_jar_manifest.out.bin").to_vec();

        embed_chunks(&mut image, script, archive, base_image_size()).expect("embed jar fixture");
        assert_eq!(image, expected);
    }

    #[test]
    fn rejects_truncated_script_chunk() {
        let mut image = vec![0u8; 64];
        let script = vec![0u8; 11];
        let archive = vec![0u8; 8];
        let err =
            embed_chunks(&mut image, script, archive, 0).expect_err("expected truncation error");
        assert!(err.contains("iCCP chunk is truncated"));
    }

    #[test]
    fn rejects_archive_without_eocd() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let archive = vec![0u8; 8];
        let err = embed_chunks(&mut image, script, archive, base_image_size())
            .expect_err("expected EOCD lookup failure");
        assert!(err.contains("End of Central Directory signature not found"));
    }

    #[test]
    fn rewrites_zip_offsets_to_rebased_locations() {
        const EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
        const CENTRAL_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
        const LOCAL_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

        let mut image = base_image();
        let original_image_size = image.len();

        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let mut archive =
            include_bytes!("../tests/fixtures/assembly_zip_video.archive.bin").to_vec();
        let archive_data_len = archive.len() - 12;
        write_value_at(&mut archive, 0, archive_data_len, 4, ByteOrder::Big)
            .expect("archive length update");

        embed_chunks(&mut image, script, archive, original_image_size).expect("embed");

        let eocd_index = image
            .windows(EOCD_SIG.len())
            .rposition(|window| window == EOCD_SIG)
            .expect("EOCD");

        assert_eq!(
            read_value_at(&image, eocd_index + 20, 2, ByteOrder::Little).expect("comment"),
            16
        );
        let total_records =
            read_value_at(&image, eocd_index + 10, 2, ByteOrder::Little).expect("records");
        assert!(total_records >= 1);

        let central_start =
            read_value_at(&image, eocd_index + 16, 4, ByteOrder::Little).expect("central start");
        assert!(central_start > original_image_size);

        let mut cursor = central_start;
        for _ in 0..total_records {
            assert!(cursor + 46 <= image.len());
            assert_eq!(&image[cursor..cursor + 4], &CENTRAL_SIG);

            let local_offset =
                read_value_at(&image, cursor + 42, 4, ByteOrder::Little).expect("local offset");
            assert!(local_offset + 30 <= image.len());
            assert_eq!(&image[local_offset..local_offset + 4], &LOCAL_SIG);

            let name_length =
                read_value_at(&image, cursor + 28, 2, ByteOrder::Little).expect("name length");
            let extra_length =
                read_value_at(&image, cursor + 30, 2, ByteOrder::Little).expect("extra length");
            let comment_length =
                read_value_at(&image, cursor + 32, 2, ByteOrder::Little).expect("comment len");
            cursor += 46 + name_length + extra_length + comment_length;
        }

        assert_eq!(cursor, eocd_index);
    }
}
