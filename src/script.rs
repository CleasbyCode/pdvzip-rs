use crate::types::{FileType, UserArguments};
use crc32fast::Hasher;

pub type ScriptResult<T> = Result<T, String>;

const CHUNK_FIELDS_COMBINED_LENGTH: usize = 12;
const MAX_SCRIPT_SIZE: usize = 1500;
const CRLF: &str = "\r\n";

const TOKEN_LINUX_FILENAME_ARG: &str = "{{LINUX_FILENAME_ARG}}";
const TOKEN_WINDOWS_FILENAME_ARG: &str = "{{WINDOWS_FILENAME_ARG}}";
const TOKEN_LINUX_ARGS: &str = "{{LINUX_ARGS}}";
const TOKEN_WINDOWS_ARGS: &str = "{{WINDOWS_ARGS}}";
const TOKEN_LINUX_ARGS_COMBINED: &str = "{{LINUX_ARGS_COMBINED}}";
const TOKEN_WINDOWS_ARGS_COMBINED: &str = "{{WINDOWS_ARGS_COMBINED}}";

const LINUX_PROBLEM_METACHARACTERS: [u8; 7] = [0x22, 0x27, 0x28, 0x29, 0x3B, 0x3E, 0x60];

// ============================================================================
// v4.7 Linux extraction macros (verbatim from script_text_builder.cpp)
// ============================================================================

const LINUX_EXTRACT_ITEM: &str = r#"ITEM={{LINUX_FILENAME_ARG}};SELF=$(basename -- "$0");DIR="pdvzip_$$";clear;mkdir "$DIR"||exit;mv -- "$0" "$DIR"||exit;cd "$DIR"||exit;unzip -qo -- "$SELF"||exit;"#;
const LINUX_EXTRACT_ITEM_HASH: &str = r#"ITEM={{LINUX_FILENAME_ARG}};SELF=$(basename -- "$0");DIR="pdvzip_$$";clear;mkdir "$DIR"||exit;mv -- "$0" "$DIR"||exit;cd "$DIR"||exit;unzip -qo -- "$SELF"||exit;hash -r;"#;
const LINUX_EXTRACT_ITEM_HASH_NULL: &str = r#"ITEM={{LINUX_FILENAME_ARG}};SELF=$(basename -- "$0");DIR="pdvzip_$$";NUL="/dev/null";clear;mkdir "$DIR"||exit;mv -- "$0" "$DIR"||exit;cd "$DIR"||exit;unzip -qo -- "$SELF"||exit;hash -r;"#;
const LINUX_EXTRACT_NO_ITEM: &str = r#"SELF=$(basename -- "$0");DIR="pdvzip_$$";clear;mkdir "$DIR"||exit;mv -- "$0" "$DIR"||exit;cd "$DIR"||exit;unzip -qo -- "$SELF"||exit;"#;

// ============================================================================
// v4.7 Windows extraction macros (verbatim from script_text_builder.cpp)
// ============================================================================

const WINDOWS_EXTRACT: &str = r#"#&cls&setlocal EnableDelayedExpansion&set "DIR=pdvzip_!RANDOM!"&mkdir ".\!DIR!"||exit /b&move "%~dpnx0" ".\!DIR!"||exit /b&cd ".\!DIR!"||exit /b&cls&tar -xf "%~n0%~x0"||exit /b&ren "%~n0%~x0" *.png&"#;
const WINDOWS_PYTHON_EXTRACT: &str = r#"#&cls&setlocal EnableDelayedExpansion&set "APP=python3"&set "DIR=pdvzip_!RANDOM!"&mkdir ".\!DIR!"||exit /b&move "%~dpnx0" ".\!DIR!"||exit /b&cd ".\!DIR!"||exit /b&cls&tar -xf "%~n0%~x0"||exit /b&ren "%~n0%~x0" *.png&"#;
const WINDOWS_POWERSHELL_EXTRACT: &str = r#"#&cls&setlocal EnableDelayedExpansion&set "PDIR=%SystemDrive%\Program Files\PowerShell\"&set "DIR=pdvzip_!RANDOM!"&mkdir ".\!DIR!"||exit /b&move "%~dpnx0" ".\!DIR!"||exit /b&cd ".\!DIR!"||exit /b&cls&tar -xf "%~n0%~x0"||exit /b&ren "%~n0%~x0" *.png&"#;

struct ScriptTemplate {
    linux_part: String,
    windows_part: String,
}

fn get_script_template(file_type: FileType) -> ScriptTemplate {
    match file_type {
        FileType::VideoAudio => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM_HASH_NULL}{}",
                r#"if command -v mpv >$NUL 2>&1;then clear;mpv --quiet --geometry=50%:50% "$ITEM" &> $NUL;elif command -v vlc >$NUL 2>&1;then clear;vlc --play-and-exit --no-video-title-show "$ITEM" &> $NUL;elif command -v firefox >$NUL 2>&1;then clear;firefox "$ITEM" &> $NUL;else clear;fi;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_EXTRACT}{}",
                r#"start "" {{WINDOWS_FILENAME_ARG}}&exit"#
            ),
        },
        FileType::Pdf => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM_HASH_NULL}{}",
                r#"if command -v evince >$NUL 2>&1;then clear;evince "$ITEM" &> $NUL;else firefox "$ITEM" &> $NUL;clear;fi;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_EXTRACT}{}",
                r#"start "" {{WINDOWS_FILENAME_ARG}}&exit"#
            ),
        },
        FileType::Python => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM_HASH}{}",
                r#"if command -v python3 >/dev/null 2>&1;then clear;python3 "$ITEM" {{LINUX_ARGS}};else clear;fi;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_PYTHON_EXTRACT}{}",
                r#"where "!APP!" >nul 2>&1 && ("!APP!" {{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}} ) || (cls&exit)&echo.&exit"#
            ),
        },
        FileType::Powershell => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM_HASH}{}",
                r#"if command -v pwsh >/dev/null 2>&1;then clear;pwsh "$ITEM" {{LINUX_ARGS}};else clear;fi;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_POWERSHELL_EXTRACT}{}",
                r#"IF EXIST "!PDIR!" (pwsh -ExecutionPolicy Bypass -File {{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}&echo.&exit) ELSE (powershell -ExecutionPolicy Bypass -File {{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}&echo.&exit)"#
            ),
        },
        FileType::BashShell => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM}{}",
                r#"chmod +x -- "$ITEM";"$ITEM" {{LINUX_ARGS}};exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_EXTRACT}{}",
                r#"{{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}&cls&exit"#
            ),
        },
        FileType::WindowsExecutable => ScriptTemplate {
            linux_part: format!("{LINUX_EXTRACT_NO_ITEM}{}", r#"clear;exit;"#),
            windows_part: format!(
                "{WINDOWS_EXTRACT}{}",
                r#"{{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS_COMBINED}}&echo.&exit"#
            ),
        },
        FileType::Folder => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM}{}",
                r#"xdg-open "$ITEM" >/dev/null 2>&1;clear;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_EXTRACT}{}",
                r#"start "" {{WINDOWS_FILENAME_ARG}}&cls&exit"#
            ),
        },
        FileType::LinuxExecutable => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM}{}",
                r#"chmod +x -- "$ITEM";"$ITEM" {{LINUX_ARGS_COMBINED}};exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_EXTRACT}{}",
                r#"cls&exit"#
            ),
        },
        FileType::Jar => ScriptTemplate {
            linux_part: r#"clear;hash -r;if command -v java >/dev/null 2>&1;then clear;java -jar "$0" {{LINUX_ARGS}};else clear;fi;exit;"#.to_string(),
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "APP=java"&cls&where "!APP!" >nul 2>&1 && ("!APP!" -jar "%~dpnx0" {{WINDOWS_ARGS}} ) || (cls)&ren "%~dpnx0" *.png&echo.&exit"#.to_string(),
        },
        FileType::UnknownFileType => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM}{}",
                r#"xdg-open "$ITEM" >/dev/null 2>&1;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_EXTRACT}{}",
                r#"start "" {{WINDOWS_FILENAME_ARG}}&echo.&exit"#
            ),
        },
    }
}

fn validate_script_input(value: &str, field_name: &str) -> ScriptResult<()> {
    // Mirrors C++ std::iscntrl: control characters are bytes 0x00-0x1F and 0x7F.
    if value.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(format!(
            "Arguments Error: {field_name} contains unsupported control characters."
        ));
    }
    Ok(())
}

fn reject_template_delimiters(value: &str, field_name: &str) -> ScriptResult<()> {
    if value.contains("{{") {
        return Err(format!(
            "Script Error: {field_name} contains reserved template delimiter '{{}}'."
        ));
    }
    Ok(())
}

fn make_posix_command_path(path: &str) -> ScriptResult<String> {
    if path.is_empty() {
        return Err("Script Error: Archive filename is empty.".to_string());
    }
    Ok(format!("./{path}"))
}

fn make_windows_command_path(path: &str) -> ScriptResult<String> {
    if path.is_empty() {
        return Err("Script Error: Archive filename is empty.".to_string());
    }
    let mut out = String::with_capacity(path.len() + 2);
    out.push_str(".\\");
    for ch in path.chars() {
        out.push(if ch == '/' { '\\' } else { ch });
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    None,
    Single,
    Double,
}

fn split_posix_arguments(input: &str, field_name: &str) -> ScriptResult<Vec<String>> {
    let syntax_error =
        |reason: &str| -> String { format!("Arguments Error: {field_name} {reason}") };

    let mut args = Vec::<String>::new();
    let mut current = String::new();
    let mut state = QuoteState::None;
    let mut escaped = false;
    let mut token_started = false;

    for ch in input.chars() {
        if state == QuoteState::Single {
            if ch == '\'' {
                state = QuoteState::None;
            } else {
                current.push(ch);
            }
            token_started = true;
            continue;
        }

        if escaped {
            current.push(ch);
            escaped = false;
            token_started = true;
            continue;
        }

        if state == QuoteState::Double {
            if ch == '"' {
                state = QuoteState::None;
            } else if ch == '\\' {
                escaped = true;
            } else {
                current.push(ch);
            }
            token_started = true;
            continue;
        }

        if ch.is_ascii_whitespace() {
            if token_started {
                args.push(std::mem::take(&mut current));
                token_started = false;
            }
            continue;
        }

        match ch {
            '\\' => {
                escaped = true;
                token_started = true;
            }
            '\'' => {
                state = QuoteState::Single;
                token_started = true;
            }
            '"' => {
                state = QuoteState::Double;
                token_started = true;
            }
            _ => {
                current.push(ch);
                token_started = true;
            }
        }
    }

    if escaped {
        return Err(syntax_error("end with an unfinished escape sequence."));
    }
    if state != QuoteState::None {
        return Err(syntax_error("contain unmatched quotes."));
    }
    if token_started {
        args.push(current);
    }

    Ok(args)
}

fn split_windows_arguments(input: &str, field_name: &str) -> ScriptResult<Vec<String>> {
    let syntax_error =
        |reason: &str| -> String { format!("Arguments Error: {field_name} {reason}") };

    let bytes = input.as_bytes();
    let mut args = Vec::<String>::new();
    let mut i = 0usize;

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let mut current = String::new();
        let mut in_quotes = false;
        let mut backslashes = 0usize;

        while i < bytes.len() {
            let ch = bytes[i] as char;
            if ch == '\\' {
                backslashes += 1;
                i += 1;
                continue;
            }

            if ch == '"' {
                if backslashes % 2 == 0 {
                    current.push_str(&"\\".repeat(backslashes / 2));
                    backslashes = 0;

                    if in_quotes && (i + 1) < bytes.len() && bytes[i + 1] == b'"' {
                        current.push('"');
                        i += 2;
                        continue;
                    }

                    in_quotes = !in_quotes;
                    i += 1;
                    continue;
                }

                current.push_str(&"\\".repeat(backslashes / 2));
                current.push('"');
                backslashes = 0;
                i += 1;
                continue;
            }

            if backslashes > 0 {
                current.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
            }

            if !in_quotes && ch.is_ascii_whitespace() {
                break;
            }

            current.push(ch);
            i += 1;
        }

        if backslashes > 0 {
            current.push_str(&"\\".repeat(backslashes));
        }
        if in_quotes {
            return Err(syntax_error("contain unmatched double quotes."));
        }

        args.push(current);

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
    }

    Ok(args)
}

fn quote_posix_argument(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn quote_windows_argument_for_cmd(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() * 2 + 2);
    out.push('"');

    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }

        if ch == '"' {
            out.push_str(&"\\".repeat(backslashes * 2 + 1));
            out.push('"');
            backslashes = 0;
            continue;
        }

        if backslashes > 0 {
            out.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
        }

        // Prevent percent-expansion in CMD (including inside quoted args).
        if ch == '%' {
            out.push_str("%%");
        } else if ch == '!' {
            // Inside double quotes with delayed expansion enabled, '!' cannot be
            // escaped by any means. Break out of the quoted region, emit ^!
            // (literal '!' outside quotes), then immediately reopen the quoted
            // region.
            out.push_str("\"^!\"");
        } else {
            out.push(ch);
        }
    }

    if backslashes > 0 {
        out.push_str(&"\\".repeat(backslashes * 2));
    }

    out.push('"');
    out
}

fn render_posix_arguments(raw_args: &str, field_name: &str) -> ScriptResult<String> {
    let args = split_posix_arguments(raw_args, field_name)?;
    if args.is_empty() {
        return Ok(String::new());
    }

    let mut rendered = String::with_capacity(raw_args.len() + args.len());
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            rendered.push(' ');
        }
        rendered.push_str(&quote_posix_argument(arg));
    }
    Ok(rendered)
}

fn render_windows_arguments(raw_args: &str, field_name: &str) -> ScriptResult<String> {
    let args = split_windows_arguments(raw_args, field_name)?;
    if args.is_empty() {
        return Ok(String::new());
    }

    let mut rendered = String::with_capacity(raw_args.len() * 2 + args.len());
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            rendered.push(' ');
        }
        rendered.push_str(&quote_windows_argument_for_cmd(arg));
    }
    Ok(rendered)
}

fn ensure_no_unresolved_placeholders(script_text: &str) -> ScriptResult<()> {
    let tokens = [
        TOKEN_LINUX_FILENAME_ARG,
        TOKEN_WINDOWS_FILENAME_ARG,
        TOKEN_LINUX_ARGS,
        TOKEN_WINDOWS_ARGS,
        TOKEN_LINUX_ARGS_COMBINED,
        TOKEN_WINDOWS_ARGS_COMBINED,
    ];

    if tokens.iter().any(|token| script_text.contains(token)) {
        return Err(
            "Script Error: Unresolved placeholder token in extraction script template.".to_string(),
        );
    }
    Ok(())
}

struct PlaceholderReplacement {
    token: &'static str,
    value: String,
}

/// Mirrors C++ `renderTemplate`: scans for `{{` markers, matches against the
/// known replacement tokens, and substitutes their resolved values. Any `{{`
/// marker that does not match a known token is an error.
fn render_template(template_text: &str, replacements: &[PlaceholderReplacement]) -> ScriptResult<String> {
    let mut rendered = String::with_capacity(template_text.len() + 256);
    let mut position = 0usize;

    while position < template_text.len() {
        match template_text[position..].find("{{") {
            None => {
                rendered.push_str(&template_text[position..]);
                break;
            }
            Some(rel_marker) => {
                let marker = position + rel_marker;
                rendered.push_str(&template_text[position..marker]);

                let mut matched = false;
                for replacement in replacements {
                    let token = replacement.token;
                    if template_text.len() - marker >= token.len()
                        && &template_text[marker..marker + token.len()] == token
                    {
                        rendered.push_str(&replacement.value);
                        position = marker + token.len();
                        matched = true;
                        break;
                    }
                }

                if !matched {
                    return Err(
                        "Script Error: Unknown placeholder token in extraction script template."
                            .to_string(),
                    );
                }
            }
        }
    }

    Ok(rendered)
}

fn validate_script_inputs(first_filename: &str, user_args: &UserArguments) -> ScriptResult<()> {
    validate_script_input(first_filename, "Archive filename")?;
    validate_script_input(&user_args.linux_args, "Linux arguments")?;
    validate_script_input(&user_args.windows_args, "Windows arguments")?;

    // Reject values that contain template token delimiters, so user input cannot
    // impersonate a placeholder while the template is rendered.
    reject_template_delimiters(first_filename, "Archive filename")?;
    reject_template_delimiters(&user_args.linux_args, "Linux arguments")?;
    reject_template_delimiters(&user_args.windows_args, "Windows arguments")?;
    Ok(())
}

fn combined_arguments_raw(user_args: &UserArguments) -> &str {
    if user_args.linux_args.is_empty() {
        user_args.windows_args.as_str()
    } else {
        user_args.linux_args.as_str()
    }
}

fn make_placeholder_replacements(
    first_filename: &str,
    user_args: &UserArguments,
) -> ScriptResult<[PlaceholderReplacement; 6]> {
    let args_combined_raw = combined_arguments_raw(user_args);

    Ok([
        PlaceholderReplacement {
            token: TOKEN_LINUX_FILENAME_ARG,
            value: quote_posix_argument(&make_posix_command_path(first_filename)?),
        },
        PlaceholderReplacement {
            token: TOKEN_WINDOWS_FILENAME_ARG,
            value: quote_windows_argument_for_cmd(&make_windows_command_path(first_filename)?),
        },
        PlaceholderReplacement {
            token: TOKEN_LINUX_ARGS,
            value: render_posix_arguments(&user_args.linux_args, "Linux arguments")?,
        },
        PlaceholderReplacement {
            token: TOKEN_WINDOWS_ARGS,
            value: render_windows_arguments(&user_args.windows_args, "Windows arguments")?,
        },
        PlaceholderReplacement {
            token: TOKEN_LINUX_ARGS_COMBINED,
            value: render_posix_arguments(args_combined_raw, "Combined Linux arguments")?,
        },
        PlaceholderReplacement {
            token: TOKEN_WINDOWS_ARGS_COMBINED,
            value: render_windows_arguments(args_combined_raw, "Combined Windows arguments")?,
        },
    ])
}

fn join_script_template(script_template: &ScriptTemplate) -> String {
    let mut template_text = String::with_capacity(
        script_template.linux_part.len() + CRLF.len() + script_template.windows_part.len(),
    );
    template_text.push_str(&script_template.linux_part);
    template_text.push_str(CRLF);
    template_text.push_str(&script_template.windows_part);
    template_text
}

fn build_script_text(
    file_type: FileType,
    first_filename: &str,
    user_args: &UserArguments,
) -> ScriptResult<String> {
    validate_script_inputs(first_filename, user_args)?;
    let script_template = get_script_template(file_type);
    let replacements = make_placeholder_replacements(first_filename, user_args)?;
    let template_text = join_script_template(&script_template);
    let script_text = render_template(&template_text, &replacements)?;
    ensure_no_unresolved_placeholders(&script_text)?;
    Ok(script_text)
}

fn update_be_u32(data: &mut [u8], index: usize, value: usize) -> ScriptResult<()> {
    if value > u32::MAX as usize {
        return Err("Script Error: Value exceeds 32-bit range.".to_string());
    }
    if index > data.len() || 4 > (data.len() - index) {
        return Err("Script Error: Index out of bounds while writing 32-bit value.".to_string());
    }

    let value = value as u32;
    data[index..index + 4].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn build_extraction_script(
    file_type: FileType,
    first_filename: &str,
    user_args: &UserArguments,
) -> ScriptResult<Vec<u8>> {
    const SCRIPT_INDEX: usize = 0x16;
    const ICCP_CHUNK_NAME_INDEX: usize = 0x04;
    const ICCP_CHUNK_NAME_LENGTH: usize = 4;
    const ICCP_CRC_INDEX_DIFF: usize = 8;
    const LENGTH_FIRST_BYTE_INDEX: usize = 3;

    let mut script_vec = vec![
        0x00, 0x00, 0x00, 0x00, 0x69, 0x43, 0x43, 0x50, 0x44, 0x56, 0x5A, 0x49, 0x50, 0x5F, 0x5F,
        0x00, 0x00, 0x0D, 0x52, 0x45, 0x4D, 0x3B, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00,
    ];
    script_vec.reserve(script_vec.len() + MAX_SCRIPT_SIZE);

    let script_text = build_script_text(file_type, first_filename, user_args)?;
    script_vec.splice(SCRIPT_INDEX..SCRIPT_INDEX, script_text.bytes());

    let mut chunk_data_size = script_vec
        .len()
        .checked_sub(CHUNK_FIELDS_COMBINED_LENGTH)
        .ok_or_else(|| "Script Error: Invalid chunk size.".to_string())?;
    update_be_u32(&mut script_vec, 0, chunk_data_size)?;

    const PAD: &[u8] = b"........";
    const PAD_OFFSET: usize = 8;
    const MAX_PAD_ATTEMPTS: usize = 32;

    let mut pad_attempts = 0usize;
    while LINUX_PROBLEM_METACHARACTERS.contains(&script_vec[LENGTH_FIRST_BYTE_INDEX]) {
        pad_attempts += 1;
        if pad_attempts > MAX_PAD_ATTEMPTS {
            return Err("Script Error: Could not make iCCP chunk length Linux-safe.".to_string());
        }

        let pad_index = chunk_data_size + PAD_OFFSET;
        script_vec.splice(pad_index..pad_index, PAD.iter().copied());
        chunk_data_size = script_vec
            .len()
            .checked_sub(CHUNK_FIELDS_COMBINED_LENGTH)
            .ok_or_else(|| "Script Error: Invalid chunk size.".to_string())?;
        update_be_u32(&mut script_vec, 0, chunk_data_size)?;
    }

    if chunk_data_size > MAX_SCRIPT_SIZE {
        return Err("Script Size Error: Extraction script exceeds size limit.".to_string());
    }

    let iccp_chunk_length = chunk_data_size + ICCP_CHUNK_NAME_LENGTH;
    let crc_start = ICCP_CHUNK_NAME_INDEX;
    let crc_end = crc_start + iccp_chunk_length;
    if crc_end > script_vec.len() {
        return Err("Script Error: Invalid CRC range.".to_string());
    }

    let mut hasher = Hasher::new();
    hasher.update(&script_vec[crc_start..crc_end]);
    let crc = hasher.finalize();

    let crc_index = chunk_data_size + ICCP_CRC_INDEX_DIFF;
    update_be_u32(&mut script_vec, crc_index, crc as usize)?;
    Ok(script_vec)
}

#[cfg(test)]
mod tests {
    use super::build_extraction_script;
    use super::{make_posix_command_path, quote_posix_argument, quote_windows_argument_for_cmd};
    use crate::types::{FileType, UserArguments};

    #[test]
    fn posix_quote() {
        assert_eq!(quote_posix_argument("a'b"), "'a'\\''b'");
        assert_eq!(quote_posix_argument("x y"), "'x y'");
    }

    #[test]
    fn windows_quote_percent_and_bang() {
        assert_eq!(quote_windows_argument_for_cmd("a%b"), "\"a%%b\"");
        assert_eq!(quote_windows_argument_for_cmd("a!b"), "\"a\"^!\"b\"");
    }

    #[test]
    fn posix_path() {
        assert_eq!(make_posix_command_path("doc.pdf").unwrap(), "./doc.pdf");
    }

    #[test]
    fn rejects_control_characters() {
        let args = UserArguments {
            linux_args: "--ok\n--bad".to_string(),
            windows_args: String::new(),
        };
        assert!(build_extraction_script(FileType::Python, "tool.py", &args).is_err());
    }

    #[test]
    fn template_replacement() {
        let args = UserArguments {
            linux_args: "--linux-flag".to_string(),
            windows_args: "--win-flag".to_string(),
        };
        let script = build_extraction_script(FileType::Python, "tool.py", &args).expect("script");
        let text = String::from_utf8_lossy(&script);

        assert!(!text.contains("{{LINUX_FILENAME_ARG}}"));
        assert!(!text.contains("{{WINDOWS_FILENAME_ARG}}"));
        assert!(!text.contains("{{LINUX_ARGS}}"));
        assert!(!text.contains("{{WINDOWS_ARGS}}"));
        assert!(text.contains("tool.py"));
        assert!(text.contains("--linux-flag"));
        assert!(text.contains("--win-flag"));

        let args = UserArguments {
            linux_args: String::new(),
            windows_args: "--combined".to_string(),
        };
        let script =
            build_extraction_script(FileType::LinuxExecutable, "runner", &args).expect("script");
        let text = String::from_utf8_lossy(&script);

        assert!(text.contains("runner"));
        assert!(text.contains("--combined"));
    }

    #[test]
    fn argument_escaping() {
        let args = UserArguments {
            linux_args: r#"--alpha "two words" "O'Reilly""#.to_string(),
            windows_args: r#"%USERPROFILE% "C:\Path With Spaces\tool.exe""#.to_string(),
        };
        let script = build_extraction_script(FileType::Python, "tool.py", &args).expect("script");
        let text = String::from_utf8_lossy(&script);

        assert!(text.contains("'--alpha' 'two words' 'O'\\''Reilly'"));
        assert!(text.contains("\"%%USERPROFILE%%\" \"C:\\Path With Spaces\\tool.exe\""));

        let args = UserArguments {
            linux_args: String::new(),
            windows_args: r#"--run "%TEMP%\app.exe""#.to_string(),
        };
        let script =
            build_extraction_script(FileType::WindowsExecutable, "app.exe", &args).expect("script");
        let text = String::from_utf8_lossy(&script);
        assert!(text.contains("\"--run\" \"%%TEMP%%\\app.exe\""));
    }

    #[test]
    fn invalid_argument_syntax() {
        let args = UserArguments {
            linux_args: "'unterminated".to_string(),
            windows_args: String::new(),
        };
        assert!(build_extraction_script(FileType::Python, "tool.py", &args).is_err());

        let args = UserArguments {
            linux_args: String::new(),
            windows_args: "\"unterminated".to_string(),
        };
        assert!(build_extraction_script(FileType::Python, "tool.py", &args).is_err());
    }
}
