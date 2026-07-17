use crate::binary_utils::is_linux_problem_metacharacter;
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

// ============================================================================
// v4.7 Linux extraction macros (verbatim from script_text_builder.cpp)
// ============================================================================

const LINUX_EXTRACT_ITEM: &str = r#"ITEM={{LINUX_FILENAME_ARG}};SELF=${0##*/};DIR=${SELF%.*};case $DIR in ''|.|..|"$SELF")DIR=${SELF}_files;;esac;PATH_DIR=./$DIR;clear;mkdir -- "$PATH_DIR"||exit;mv -- "$0" "$PATH_DIR"||exit;cd "$PATH_DIR"||exit;unzip -qo -- "$SELF"||exit;"#;
const LINUX_EXTRACT_ITEM_HASH: &str = r#"ITEM={{LINUX_FILENAME_ARG}};SELF=${0##*/};DIR=${SELF%.*};case $DIR in ''|.|..|"$SELF")DIR=${SELF}_files;;esac;PATH_DIR=./$DIR;clear;mkdir -- "$PATH_DIR"||exit;mv -- "$0" "$PATH_DIR"||exit;cd "$PATH_DIR"||exit;unzip -qo -- "$SELF"||exit;hash -r;"#;
const LINUX_EXTRACT_ITEM_HASH_NULL: &str = r#"ITEM={{LINUX_FILENAME_ARG}};SELF=${0##*/};DIR=${SELF%.*};case $DIR in ''|.|..|"$SELF")DIR=${SELF}_files;;esac;PATH_DIR=./$DIR;NUL="/dev/null";clear;mkdir -- "$PATH_DIR"||exit;mv -- "$0" "$PATH_DIR"||exit;cd "$PATH_DIR"||exit;unzip -qo -- "$SELF"||exit;hash -r;"#;
const LINUX_EXTRACT_NO_ITEM: &str = r#"SELF=${0##*/};DIR=${SELF%.*};case $DIR in ''|.|..|"$SELF")DIR=${SELF}_files;;esac;PATH_DIR=./$DIR;clear;mkdir -- "$PATH_DIR"||exit;mv -- "$0" "$PATH_DIR"||exit;cd "$PATH_DIR"||exit;unzip -qo -- "$SELF"||exit;"#;

// ============================================================================
// v4.7 Windows extraction macros (verbatim from script_text_builder.cpp)
// ============================================================================

const WINDOWS_BASE: &str = concat!(
    r#"#&cls&@echo off&setlocal EnableExtensions DisableDelayedExpansion"#,
    "\r\n",
    r#"set "ERRORLEVEL=""#,
    "\r\n",
);
const WINDOWS_EXTRACT: &str = concat!(
    r#"set "DIR=%~n0""#,
    "\r\n",
    r#"mkdir ".\%DIR%"||exit /b"#,
    "\r\n",
    r#"cd ".\%DIR%"||exit /b"#,
    "\r\n",
    r#"for %%I in (".\%~n0.png") do set "PDVZIP_RESTORE_TARGET=%%~fI""#,
    "\r\n",
    r#"cls&tar -xf "%~dpnx0"||exit /b"#,
    "\r\n",
);
const WINDOWS_POWERSHELL_EXTRACT: &str = concat!(
    r#"set "APP=""#,
    "\r\n",
    r#"set "DIR=%~n0""#,
    "\r\n",
    r#"mkdir ".\%DIR%"||exit /b"#,
    "\r\n",
    r#"cd ".\%DIR%"||exit /b"#,
    "\r\n",
    r#"for %%I in (".\%~n0.png") do set "PDVZIP_RESTORE_TARGET=%%~fI""#,
    "\r\n",
    r#"cls&tar -xf "%~dpnx0"||exit /b"#,
    "\r\n",
);
const WINDOWS_RESTORE: &str = concat!(
    r#":PDVZIP_RESTORE"#,
    "\r\n",
    r#"if exist "%PDVZIP_RESTORE_TARGET%" (>&2 echo pdvzip: PNG restore target already exists.&exit /b 1)"#,
    "\r\n",
    r#"(goto) 2>nul&move /-Y "%~f0" "%PDVZIP_RESTORE_TARGET%" <nul >nul&if errorlevel 1 ("%ComSpec%" /d /c exit 1) else ("%ComSpec%" /d /c exit %STATUS%)"#,
    "\r\n",
);
const WINDOWS_JAR_RESTORE: &str = concat!(
    r#":PDVZIP_RESTORE"#,
    "\r\n",
    r#"if exist "%~dpn0.png" (>&2 echo pdvzip: PNG restore target already exists.&exit /b 1)"#,
    "\r\n",
    r#"(goto) 2>nul&ren "%~f0" "%~n0.png" >nul&if errorlevel 1 ("%ComSpec%" /d /c exit 1) else ("%ComSpec%" /d /c exit %STATUS%)"#,
    "\r\n",
);

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
                "{WINDOWS_BASE}{WINDOWS_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(
                    r#"start "" {{WINDOWS_FILENAME_ARG}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                )
            ),
        },
        FileType::Pdf => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM_HASH_NULL}{}",
                r#"if command -v evince >$NUL 2>&1;then clear;evince "$ITEM" &> $NUL;else firefox "$ITEM" &> $NUL;clear;fi;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_BASE}{WINDOWS_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(
                    r#"start "" {{WINDOWS_FILENAME_ARG}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                )
            ),
        },
        FileType::Python => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM_HASH}{}",
                r#"if command -v python3 >/dev/null 2>&1;then clear;python3 "$ITEM" {{LINUX_ARGS}};STATUS=$?;exit "$STATUS";else clear;printf '%s\n' 'pdvzip: required runtime python3 was not found.' >&2;exit 127;fi;"#
            ),
            windows_part: format!(
                "{WINDOWS_BASE}{WINDOWS_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(
                    r#"where python3 >nul 2>&1"#,
                    "\r\n",
                    r#"if errorlevel 1 (>&2 echo pdvzip: required runtime python3 was not found.&set "STATUS=127"&goto :PDVZIP_RESTORE)"#,
                    "\r\n",
                    r#"python3 {{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                )
            ),
        },
        FileType::Powershell => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM_HASH}{}",
                r#"if command -v pwsh >/dev/null 2>&1;then clear;pwsh "$ITEM" {{LINUX_ARGS}};STATUS=$?;exit "$STATUS";else clear;printf '%s\n' 'pdvzip: required runtime pwsh was not found.' >&2;exit 127;fi;"#
            ),
            windows_part: format!(
                "{WINDOWS_BASE}{WINDOWS_POWERSHELL_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(
                    r#"where pwsh >nul 2>&1"#,
                    "\r\n",
                    r#"if not errorlevel 1 set "APP=pwsh""#,
                    "\r\n",
                    r#"if not defined APP where powershell >nul 2>&1"#,
                    "\r\n",
                    r#"if not defined APP if not errorlevel 1 set "APP=powershell""#,
                    "\r\n",
                    r#"if not defined APP (>&2 echo pdvzip: required PowerShell runtime was not found.&set "STATUS=127"&goto :PDVZIP_RESTORE)"#,
                    "\r\n",
                    r#"%APP% -ExecutionPolicy Bypass -File {{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                )
            ),
        },
        FileType::BashShell => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM}{}",
                r#"chmod +x -- "$ITEM";"$ITEM" {{LINUX_ARGS}};exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_BASE}{WINDOWS_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(
                    r#"{{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                    r#"cls"#,
                    "\r\n",
                )
            ),
        },
        FileType::WindowsExecutable => ScriptTemplate {
            linux_part: format!("{LINUX_EXTRACT_NO_ITEM}{}", r#"clear;exit;"#),
            windows_part: format!(
                "{WINDOWS_BASE}{WINDOWS_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(
                    r#"{{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS_COMBINED}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                    r#"echo."#,
                    "\r\n",
                )
            ),
        },
        FileType::Folder => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM}{}",
                r#"xdg-open "$ITEM" >/dev/null 2>&1;clear;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_BASE}{WINDOWS_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(
                    r#"start "" {{WINDOWS_FILENAME_ARG}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                    r#"cls"#,
                    "\r\n",
                )
            ),
        },
        FileType::LinuxExecutable => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM}{}",
                r#"chmod +x -- "$ITEM";"$ITEM" {{LINUX_ARGS_COMBINED}};exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_BASE}{WINDOWS_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(r#"cls"#, "\r\n", r#"set "STATUS=0""#, "\r\n",)
            ),
        },
        FileType::Jar => ScriptTemplate {
            linux_part: r#"clear;hash -r;if command -v java >/dev/null 2>&1;then clear;java -jar "$0" {{LINUX_ARGS}};STATUS=$?;exit "$STATUS";else clear;printf '%s\n' 'pdvzip: required runtime java was not found.' >&2;exit 127;fi;"#.to_string(),
            windows_part: format!(
                "{WINDOWS_BASE}{}{WINDOWS_JAR_RESTORE}",
                concat!(
                    r#"where java >nul 2>&1"#,
                    "\r\n",
                    r#"if errorlevel 1 (>&2 echo pdvzip: required runtime java was not found.&set "STATUS=127"&goto :PDVZIP_RESTORE)"#,
                    "\r\n",
                    r#"java -jar "%~dpnx0" {{WINDOWS_ARGS}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                )
            ),
        },
        FileType::UnknownFileType => ScriptTemplate {
            linux_part: format!(
                "{LINUX_EXTRACT_ITEM}{}",
                r#"xdg-open "$ITEM" >/dev/null 2>&1;exit;"#
            ),
            windows_part: format!(
                "{WINDOWS_BASE}{WINDOWS_EXTRACT}{}{WINDOWS_RESTORE}",
                concat!(
                    r#"start "" {{WINDOWS_FILENAME_ARG}}"#,
                    "\r\n",
                    r#"set "STATUS=%ERRORLEVEL%""#,
                    "\r\n",
                    r#"echo."#,
                    "\r\n",
                )
            ),
        },
    }
}

fn validate_script_input(value: &[u8], field_name: &str) -> ScriptResult<()> {
    // Mirrors C++ std::iscntrl: control characters are bytes 0x00-0x1F and 0x7F.
    if value.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
        return Err(format!(
            "Arguments Error: {field_name} contains unsupported control characters."
        ));
    }
    Ok(())
}

fn reject_template_delimiters(value: &[u8], field_name: &str) -> ScriptResult<()> {
    if value.windows(2).any(|window| window == b"{{") {
        return Err(format!(
            "Script Error: {field_name} contains reserved template delimiter '{{}}'."
        ));
    }
    Ok(())
}

#[cfg(test)]
fn reject_windows_command_quotes(value: &str, field_name: &str) -> ScriptResult<()> {
    if value.contains('"') {
        return Err(format!(
            "Script Error: {field_name} contains a literal double quote, which cannot be safely embedded in a Windows command."
        ));
    }
    Ok(())
}

fn validate_filename_input(value: &[u8]) -> ScriptResult<()> {
    validate_script_input(value, "Archive filename")?;
    reject_template_delimiters(value, "Archive filename")
}

fn reject_windows_filename_quotes(value: &[u8]) -> ScriptResult<()> {
    reject_windows_command_quotes_bytes(value, "Archive filename")
}

fn reject_windows_command_quotes_bytes(value: &[u8], field_name: &str) -> ScriptResult<()> {
    if value.contains(&b'"') {
        return Err(format!(
            "Script Error: {field_name} contains a literal double quote, which cannot be safely embedded in a Windows command."
        ));
    }
    Ok(())
}

fn make_posix_command_path_bytes(path: &[u8]) -> ScriptResult<Vec<u8>> {
    if path.is_empty() {
        return Err("Script Error: Archive filename is empty.".to_string());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(path.len().saturating_add(2))
        .map_err(|_| "Script Error: Archive filename is too large.".to_string())?;
    output.extend_from_slice(b"./");
    output.extend_from_slice(path);
    Ok(output)
}

fn make_windows_command_path_bytes(path: &[u8]) -> ScriptResult<Vec<u8>> {
    if path.is_empty() {
        return Err("Script Error: Archive filename is empty.".to_string());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(path.len().saturating_add(2))
        .map_err(|_| "Script Error: Archive filename is too large.".to_string())?;
    output.extend_from_slice(b".\\");
    output.extend(
        path.iter()
            .map(|byte| if *byte == b'/' { b'\\' } else { *byte }),
    );
    Ok(output)
}

#[cfg(test)]
fn make_posix_command_path(path: &str) -> ScriptResult<String> {
    if path.is_empty() {
        return Err("Script Error: Archive filename is empty.".to_string());
    }
    Ok(format!("./{path}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    None,
    Single,
    Double,
}

fn split_posix_arguments(input: &[u8], field_name: &str) -> ScriptResult<Vec<Vec<u8>>> {
    let syntax_error =
        |reason: &str| -> String { format!("Arguments Error: {field_name} {reason}") };

    let mut args = Vec::<Vec<u8>>::new();
    let mut current = Vec::new();
    let mut state = QuoteState::None;
    let mut escaped = false;
    let mut token_started = false;

    for byte in input {
        if state == QuoteState::Single {
            if *byte == b'\'' {
                state = QuoteState::None;
            } else {
                current.push(*byte);
            }
            token_started = true;
            continue;
        }

        if escaped {
            current.push(*byte);
            escaped = false;
            token_started = true;
            continue;
        }

        if state == QuoteState::Double {
            if *byte == b'"' {
                state = QuoteState::None;
            } else if *byte == b'\\' {
                escaped = true;
            } else {
                current.push(*byte);
            }
            token_started = true;
            continue;
        }

        if byte.is_ascii_whitespace() {
            if token_started {
                args.push(std::mem::take(&mut current));
                token_started = false;
            }
            continue;
        }

        match *byte {
            b'\\' => {
                escaped = true;
                token_started = true;
            }
            b'\'' => {
                state = QuoteState::Single;
                token_started = true;
            }
            b'"' => {
                state = QuoteState::Double;
                token_started = true;
            }
            _ => {
                current.push(*byte);
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

fn split_windows_arguments(input: &[u8], field_name: &str) -> ScriptResult<Vec<Vec<u8>>> {
    let syntax_error =
        |reason: &str| -> String { format!("Arguments Error: {field_name} {reason}") };

    let bytes = input;
    let mut args = Vec::<Vec<u8>>::new();
    let mut i = 0usize;

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let mut current = Vec::<u8>::new();
        let mut in_quotes = false;
        let mut backslashes = 0usize;

        while i < bytes.len() {
            let ch = bytes[i];
            if ch == b'\\' {
                backslashes += 1;
                i += 1;
                continue;
            }

            if ch == b'"' {
                if backslashes % 2 == 0 {
                    current.extend(std::iter::repeat_n(b'\\', backslashes / 2));
                    backslashes = 0;

                    if in_quotes && (i + 1) < bytes.len() && bytes[i + 1] == b'"' {
                        current.push(b'"');
                        i += 2;
                        continue;
                    }

                    in_quotes = !in_quotes;
                    i += 1;
                    continue;
                }

                current.extend(std::iter::repeat_n(b'\\', backslashes / 2));
                current.push(b'"');
                backslashes = 0;
                i += 1;
                continue;
            }

            if backslashes > 0 {
                current.extend(std::iter::repeat_n(b'\\', backslashes));
                backslashes = 0;
            }

            if !in_quotes && ch.is_ascii_whitespace() {
                break;
            }

            current.push(ch);
            i += 1;
        }

        if backslashes > 0 {
            current.extend(std::iter::repeat_n(b'\\', backslashes));
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

#[cfg(test)]
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

fn quote_posix_argument_bytes(arg: &[u8]) -> ScriptResult<Vec<u8>> {
    let extra_quotes = arg.iter().filter(|byte| **byte == b'\'').count();
    let capacity = arg
        .len()
        .checked_add(extra_quotes.saturating_mul(3))
        .and_then(|size| size.checked_add(2))
        .ok_or_else(|| "Script Error: POSIX argument size overflow.".to_string())?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| "Script Error: POSIX argument is too large.".to_string())?;
    output.push(b'\'');
    for byte in arg {
        if *byte == b'\'' {
            output.extend_from_slice(b"'\\''");
        } else {
            output.push(*byte);
        }
    }
    output.push(b'\'');
    Ok(output)
}

#[cfg(test)]
fn quote_windows_argument_for_cmd(arg: &str) -> ScriptResult<String> {
    // A backslash does not escape a quote from cmd.exe's command parser. Keep
    // this encoder's contract deliberately narrow until CMD has a safe literal
    // quote representation for this context.
    reject_windows_command_quotes(arg, "Windows command value")?;

    let mut out = String::with_capacity(arg.len() * 2 + 2);
    out.push('"');

    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }

        if backslashes > 0 {
            out.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
        }

        // Prevent percent-expansion in CMD (including inside quoted args).
        if ch == '%' {
            out.push_str("%%");
        } else {
            out.push(ch);
        }
    }

    if backslashes > 0 {
        out.push_str(&"\\".repeat(backslashes * 2));
    }

    out.push('"');
    Ok(out)
}

fn quote_windows_argument_bytes_for_cmd(arg: &[u8], field_name: &str) -> ScriptResult<Vec<u8>> {
    reject_windows_command_quotes_bytes(arg, field_name)?;

    let capacity = arg
        .len()
        .checked_mul(2)
        .and_then(|size| size.checked_add(2))
        .ok_or_else(|| "Script Error: Windows argument size overflow.".to_string())?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| "Script Error: Windows argument is too large.".to_string())?;
    output.push(b'"');

    let mut backslashes = 0usize;
    for byte in arg {
        if *byte == b'\\' {
            backslashes += 1;
            continue;
        }
        output.extend(std::iter::repeat_n(b'\\', backslashes));
        backslashes = 0;
        if *byte == b'%' {
            output.extend_from_slice(b"%%");
        } else {
            output.push(*byte);
        }
    }
    output.extend(std::iter::repeat_n(b'\\', backslashes.saturating_mul(2)));
    output.push(b'"');
    Ok(output)
}

fn render_posix_arguments(raw_args: &[u8], field_name: &str) -> ScriptResult<Vec<u8>> {
    let args = split_posix_arguments(raw_args, field_name)?;
    if args.is_empty() {
        return Ok(Vec::new());
    }

    let capacity = raw_args
        .len()
        .checked_add(args.len())
        .ok_or_else(|| "Script Error: POSIX argument size overflow.".to_string())?;
    let mut rendered = Vec::new();
    rendered
        .try_reserve_exact(capacity)
        .map_err(|_| "Script Error: POSIX arguments are too large.".to_string())?;
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            rendered.push(b' ');
        }
        rendered.extend_from_slice(&quote_posix_argument_bytes(arg)?);
    }
    Ok(rendered)
}

fn render_windows_arguments(raw_args: &[u8], field_name: &str) -> ScriptResult<Vec<u8>> {
    let args = split_windows_arguments(raw_args, field_name)?;
    if args.is_empty() {
        return Ok(Vec::new());
    }

    let capacity = raw_args
        .len()
        .checked_mul(2)
        .and_then(|size| size.checked_add(args.len()))
        .ok_or_else(|| "Script Error: Windows argument size overflow.".to_string())?;
    let mut rendered = Vec::new();
    rendered
        .try_reserve_exact(capacity)
        .map_err(|_| "Script Error: Windows arguments are too large.".to_string())?;
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            rendered.push(b' ');
        }
        rendered.extend_from_slice(&quote_windows_argument_bytes_for_cmd(arg, field_name)?);
    }
    Ok(rendered)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn ensure_no_unresolved_placeholders(script_text: &[u8]) -> ScriptResult<()> {
    let tokens = [
        TOKEN_LINUX_FILENAME_ARG,
        TOKEN_WINDOWS_FILENAME_ARG,
        TOKEN_LINUX_ARGS,
        TOKEN_WINDOWS_ARGS,
        TOKEN_LINUX_ARGS_COMBINED,
        TOKEN_WINDOWS_ARGS_COMBINED,
    ];

    if tokens
        .iter()
        .any(|token| contains_bytes(script_text, token.as_bytes()))
    {
        return Err(
            "Script Error: Unresolved placeholder token in extraction script template.".to_string(),
        );
    }
    Ok(())
}

struct PlaceholderReplacement {
    token: &'static str,
    value: Vec<u8>,
}

/// Mirrors C++ `renderTemplate`: scans for `{{` markers, matches against the
/// known replacement tokens, and substitutes their resolved values. Any `{{`
/// marker that does not match a known token is an error.
fn render_template(
    template_text: &str,
    replacements: &[PlaceholderReplacement],
) -> ScriptResult<Vec<u8>> {
    let template_bytes = template_text.as_bytes();
    let mut rendered = Vec::new();
    rendered
        .try_reserve(template_text.len().saturating_add(256))
        .map_err(|_| "Script Error: Extraction script is too large.".to_string())?;
    let mut position = 0usize;

    while position < template_bytes.len() {
        match template_bytes[position..]
            .windows(2)
            .position(|window| window == b"{{")
        {
            None => {
                rendered.extend_from_slice(&template_bytes[position..]);
                break;
            }
            Some(rel_marker) => {
                let marker = position + rel_marker;
                rendered.extend_from_slice(&template_bytes[position..marker]);

                let mut matched = false;
                for replacement in replacements {
                    let token = replacement.token.as_bytes();
                    if template_bytes.len() - marker >= token.len()
                        && &template_bytes[marker..marker + token.len()] == token
                    {
                        rendered.extend_from_slice(&replacement.value);
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

fn validate_replacement_input(value: &[u8], field_name: &str) -> ScriptResult<()> {
    validate_script_input(value, field_name)?;
    reject_template_delimiters(value, field_name)?;
    Ok(())
}

fn combined_linux_arguments_raw(user_args: &UserArguments) -> &[u8] {
    if user_args.linux_args.is_empty() {
        &user_args.windows_args
    } else {
        &user_args.linux_args
    }
}

fn combined_windows_arguments_raw(user_args: &UserArguments) -> &[u8] {
    if user_args.windows_args.is_empty() {
        &user_args.linux_args
    } else {
        &user_args.windows_args
    }
}

fn make_placeholder_replacements(
    template_text: &str,
    first_filename: &[u8],
    user_args: &UserArguments,
) -> ScriptResult<Vec<PlaceholderReplacement>> {
    let mut replacements = Vec::with_capacity(6);

    if template_text.contains(TOKEN_LINUX_FILENAME_ARG) {
        validate_filename_input(first_filename)?;
        replacements.push(PlaceholderReplacement {
            token: TOKEN_LINUX_FILENAME_ARG,
            value: quote_posix_argument_bytes(&make_posix_command_path_bytes(first_filename)?)?,
        });
    }
    if template_text.contains(TOKEN_WINDOWS_FILENAME_ARG) {
        validate_filename_input(first_filename)?;
        reject_windows_filename_quotes(first_filename)?;
        replacements.push(PlaceholderReplacement {
            token: TOKEN_WINDOWS_FILENAME_ARG,
            value: quote_windows_argument_bytes_for_cmd(
                &make_windows_command_path_bytes(first_filename)?,
                "Archive filename",
            )?,
        });
    }
    if template_text.contains(TOKEN_LINUX_ARGS) {
        validate_replacement_input(&user_args.linux_args, "Linux arguments")?;
        replacements.push(PlaceholderReplacement {
            token: TOKEN_LINUX_ARGS,
            value: render_posix_arguments(&user_args.linux_args, "Linux arguments")?,
        });
    }
    if template_text.contains(TOKEN_WINDOWS_ARGS) {
        validate_replacement_input(&user_args.windows_args, "Windows arguments")?;
        replacements.push(PlaceholderReplacement {
            token: TOKEN_WINDOWS_ARGS,
            value: render_windows_arguments(&user_args.windows_args, "Windows arguments")?,
        });
    }
    if template_text.contains(TOKEN_LINUX_ARGS_COMBINED) {
        let raw_args = combined_linux_arguments_raw(user_args);
        validate_replacement_input(raw_args, "Combined Linux arguments")?;
        replacements.push(PlaceholderReplacement {
            token: TOKEN_LINUX_ARGS_COMBINED,
            value: render_posix_arguments(raw_args, "Combined Linux arguments")?,
        });
    }
    if template_text.contains(TOKEN_WINDOWS_ARGS_COMBINED) {
        let raw_args = combined_windows_arguments_raw(user_args);
        validate_replacement_input(raw_args, "Combined Windows arguments")?;
        replacements.push(PlaceholderReplacement {
            token: TOKEN_WINDOWS_ARGS_COMBINED,
            value: render_windows_arguments(raw_args, "Combined Windows arguments")?,
        });
    }

    Ok(replacements)
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
    first_filename: &[u8],
    user_args: &UserArguments,
) -> ScriptResult<Vec<u8>> {
    let script_template = get_script_template(file_type);
    let template_text = join_script_template(&script_template);
    let replacements = make_placeholder_replacements(&template_text, first_filename, user_args)?;
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
    first_filename: impl AsRef<[u8]>,
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

    let script_text = build_script_text(file_type, first_filename.as_ref(), user_args)?;
    script_vec.splice(SCRIPT_INDEX..SCRIPT_INDEX, script_text);

    let mut chunk_data_size = script_vec
        .len()
        .checked_sub(CHUNK_FIELDS_COMBINED_LENGTH)
        .ok_or_else(|| "Script Error: Invalid chunk size.".to_string())?;
    update_be_u32(&mut script_vec, 0, chunk_data_size)?;

    const PAD: &[u8] = b"........";
    const PAD_OFFSET: usize = 8;
    const MAX_PAD_ATTEMPTS: usize = 32;

    let mut pad_attempts = 0usize;
    while is_linux_problem_metacharacter(script_vec[LENGTH_FIRST_BYTE_INDEX]) {
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
    use super::{MAX_SCRIPT_SIZE, build_extraction_script, build_script_text};
    use super::{make_posix_command_path, quote_posix_argument, quote_windows_argument_for_cmd};
    use crate::types::{FileType, UserArguments};

    fn rendered_script(file_type: FileType, filename: &str, args: &UserArguments) -> String {
        String::from_utf8(
            build_script_text(file_type, filename.as_bytes(), args).expect("script text"),
        )
        .expect("ASCII test input renders UTF-8 script text")
    }

    #[test]
    fn posix_quote() {
        assert_eq!(quote_posix_argument("a'b"), "'a'\\''b'");
        assert_eq!(quote_posix_argument("x y"), "'x y'");
    }

    #[test]
    fn windows_quote_percent_and_bang() {
        assert_eq!(
            quote_windows_argument_for_cmd("a%b").expect("quote"),
            "\"a%%b\""
        );
        assert_eq!(
            quote_windows_argument_for_cmd("a!b").expect("quote"),
            "\"a!b\""
        );
        assert!(quote_windows_argument_for_cmd("safe\"&calc").is_err());
    }

    #[test]
    fn posix_path() {
        assert_eq!(make_posix_command_path("doc.pdf").unwrap(), "./doc.pdf");
    }

    #[test]
    fn rejects_control_characters() {
        let args = UserArguments {
            linux_args: b"--ok\n--bad".to_vec(),
            windows_args: Vec::new(),
        };
        assert!(build_extraction_script(FileType::Python, "tool.py", &args).is_err());
    }

    #[test]
    fn template_replacement() {
        let args = UserArguments {
            linux_args: b"--linux-flag".to_vec(),
            windows_args: b"--win-flag".to_vec(),
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
            linux_args: Vec::new(),
            windows_args: b"--combined".to_vec(),
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
            linux_args: br#"--alpha "two words" "O'Reilly""#.to_vec(),
            windows_args: br#"%USERPROFILE% "C:\Path With Spaces\tool.exe""#.to_vec(),
        };
        let script = build_extraction_script(FileType::Python, "tool.py", &args).expect("script");
        let text = String::from_utf8_lossy(&script);

        assert!(text.contains("'--alpha' 'two words' 'O'\\''Reilly'"));
        assert!(text.contains("\"%%USERPROFILE%%\" \"C:\\Path With Spaces\\tool.exe\""));

        let args = UserArguments {
            linux_args: Vec::new(),
            windows_args: br#"--run "%TEMP%\app.exe""#.to_vec(),
        };
        let script =
            build_extraction_script(FileType::WindowsExecutable, "app.exe", &args).expect("script");
        let text = String::from_utf8_lossy(&script);
        assert!(text.contains("\"--run\" \"%%TEMP%%\\app.exe\""));
    }

    #[test]
    fn invalid_argument_syntax() {
        let args = UserArguments {
            linux_args: b"'unterminated".to_vec(),
            windows_args: Vec::new(),
        };
        assert!(build_extraction_script(FileType::Python, "tool.py", &args).is_err());

        let args = UserArguments {
            linux_args: Vec::new(),
            windows_args: b"\"unterminated".to_vec(),
        };
        assert!(build_extraction_script(FileType::Python, "tool.py", &args).is_err());
    }

    #[test]
    fn only_parses_placeholders_used_by_selected_template() {
        let windows_only = UserArguments {
            linux_args: b"'unterminated".to_vec(),
            windows_args: b"C:\\tools\\".to_vec(),
        };
        assert!(
            build_extraction_script(FileType::WindowsExecutable, "tool.exe", &windows_only).is_ok()
        );

        let linux_only = UserArguments {
            linux_args: b"'linux\"choice'".to_vec(),
            windows_args: b"\"unterminated".to_vec(),
        };
        assert!(build_extraction_script(FileType::LinuxExecutable, "runner", &linux_only).is_ok());
    }

    #[test]
    fn windows_utf8_and_script_path_bangs_are_preserved() {
        let args = UserArguments {
            linux_args: Vec::new(),
            windows_args: "café !literal!".as_bytes().to_vec(),
        };
        let script = build_extraction_script(FileType::WindowsExecutable, "!NAME!.exe", &args)
            .expect("script");
        let text = String::from_utf8_lossy(&script);
        assert!(text.contains("setlocal EnableExtensions DisableDelayedExpansion"));
        assert!(text.contains("DisableDelayedExpansion"));
        assert!(!text.contains("EnableDelayedExpansion"));
        assert!(text.contains("café"));
        assert!(text.contains("!literal!"));
        assert!(text.contains("!NAME!.exe"));
    }

    #[test]
    fn raw_archive_filename_bytes_are_preserved() {
        let filename = b"caf\x82.py";
        let script = build_extraction_script(FileType::Python, filename, &UserArguments::default())
            .expect("raw ZIP filename");

        assert!(
            script
                .windows(filename.len())
                .any(|window| window == filename)
        );
    }

    #[test]
    fn raw_user_argument_bytes_are_preserved() {
        let args = UserArguments {
            linux_args: vec![b'-', b'-', b'x', b'=', 0xff],
            windows_args: Vec::new(),
        };
        let script = build_extraction_script(FileType::LinuxExecutable, "runner", &args)
            .expect("raw Linux argument");

        assert!(script.windows(5).any(|window| window == b"--x=\xff"));
    }

    #[test]
    fn templates_use_same_stem_and_report_missing_runtimes() {
        let args = UserArguments::default();
        let python = build_extraction_script(FileType::Python, "tool.py", &args).expect("python");
        let python_text = String::from_utf8_lossy(&python);
        assert!(python_text.contains("DIR=${SELF%.*}"));
        assert!(python_text.contains(r#"set "DIR=%~n0""#));
        assert!(python_text.contains("required runtime python3 was not found"));
        assert!(python_text.contains("exit 127"));
        assert!(python_text.contains(r#"set "STATUS=127"&goto :PDVZIP_RESTORE"#));
        assert!(python_text.contains("STATUS=$?"));
        assert!(python_text.contains(r#"set "STATUS=%ERRORLEVEL%""#));
        assert!(
            python_text
                .contains(r#"for %%I in (".\%~n0.png") do set "PDVZIP_RESTORE_TARGET=%%~fI""#)
        );
        assert!(python_text.contains(r#"move /-Y "%~f0" "%PDVZIP_RESTORE_TARGET%""#));

        let jar = build_extraction_script(FileType::Jar, "META-INF/", &args).expect("jar");
        let jar_text = String::from_utf8_lossy(&jar);
        assert!(jar_text.contains("required runtime java was not found"));
        assert!(jar_text.contains(r#""%ComSpec%" /d /c exit %STATUS%"#));
        assert!(jar_text.contains(r#"(goto) 2>nul&ren "%~f0" "%~n0.png""#));
    }

    #[test]
    fn all_windows_templates_are_quiet_and_restore_after_unwinding_cmd() {
        let cases: [(FileType, &str); 10] = [
            (FileType::VideoAudio, "media.mp4"),
            (FileType::Pdf, "document.pdf"),
            (FileType::Python, "script.py"),
            (FileType::Powershell, "script.ps1"),
            (FileType::BashShell, "script.sh"),
            (FileType::WindowsExecutable, "program.exe"),
            (FileType::Folder, "folder"),
            (FileType::LinuxExecutable, "program"),
            (FileType::Jar, "program.jar"),
            (FileType::UnknownFileType, "data.bin"),
        ];

        for (file_type, filename) in cases {
            let script = rendered_script(file_type, filename, &UserArguments::default());
            assert!(
                script.contains(
                    "#&cls&@echo off&setlocal EnableExtensions DisableDelayedExpansion\r\n"
                )
            );
            assert!(!script.contains("EnableDelayedExpansion"));
            assert!(script.contains("set \"ERRORLEVEL=\"\r\n"));
            assert!(script.contains("(goto) 2>nul&"));
            assert!(script.ends_with("\r\n"));
            assert!(script.len() < MAX_SCRIPT_SIZE);
        }
    }

    #[test]
    fn windows_runtime_restore_is_terminal() {
        for (file_type, filename) in [
            (FileType::Python, "script.py"),
            (FileType::Powershell, "script.ps1"),
        ] {
            let script = rendered_script(file_type, filename, &UserArguments::default());
            assert!(!script.contains(r#"move "%~dpnx0" ".\%DIR%""#));
            assert!(script.contains(r#"cls&tar -xf "%~dpnx0"||exit /b"#));
            assert!(script.contains(concat!(
                "cd \".\\%DIR%\"||exit /b\r\n",
                "for %%I in (\".\\%~n0.png\") do set ",
                "\"PDVZIP_RESTORE_TARGET=%%~fI\"\r\n",
            )));
            assert!(script.contains(concat!(
                "set \"STATUS=%ERRORLEVEL%\"\r\n",
                ":PDVZIP_RESTORE\r\n",
                r#"if exist "%PDVZIP_RESTORE_TARGET%" (>&2 echo pdvzip: PNG restore target already exists.&exit /b 1)"#,
                "\r\n",
                r#"(goto) 2>nul&move /-Y "%~f0" "%PDVZIP_RESTORE_TARGET%" <nul >nul&if errorlevel 1 ("%ComSpec%" /d /c exit 1) else ("%ComSpec%" /d /c exit %STATUS%)"#,
            )));
        }
    }

    #[test]
    fn jar_windows_restore_is_quiet_and_terminal() {
        let args = UserArguments {
            linux_args: Vec::new(),
            windows_args: br#"-u john_s -a 42 -f "John Smith""#.to_vec(),
        };
        let script = rendered_script(FileType::Jar, "program.jar", &args);

        assert!(script.contains(concat!(
            r#"java -jar "%~dpnx0" "-u" "john_s" "-a" "42" "-f" "John Smith""#,
            "\r\nset \"STATUS=%ERRORLEVEL%\"\r\n",
            ":PDVZIP_RESTORE\r\n",
            r#"if exist "%~dpn0.png" (>&2 echo pdvzip: PNG restore target already exists.&exit /b 1)"#,
            "\r\n",
            r#"(goto) 2>nul&ren "%~f0" "%~n0.png" >nul&if errorlevel 1 ("%ComSpec%" /d /c exit 1) else ("%ComSpec%" /d /c exit %STATUS%)"#,
        )));
        assert!(script.contains(
            r#"if errorlevel 1 (>&2 echo pdvzip: required runtime java was not found.&set "STATUS=127"&goto :PDVZIP_RESTORE)"#
        ));
        assert!(!script.contains(r#"ren "%~dpnx0" *.png"#));
        assert!(!script.contains(r#"ren "%~dpnx0" "%~n0.png""#));
        assert!(script.len() < MAX_SCRIPT_SIZE);
    }

    #[test]
    fn extraction_directory_matches_the_polyglot_stem() {
        for file_type in [
            FileType::Folder,
            FileType::Python,
            FileType::VideoAudio,
            FileType::WindowsExecutable,
            FileType::Powershell,
        ] {
            let script = rendered_script(file_type, "payload", &UserArguments::default());
            assert!(script.contains(r#"SELF=${0##*/};DIR=${SELF%.*};"#));
            assert!(script.contains(r#"set "DIR=%~n0""#));
            assert!(
                script
                    .contains(r#"for %%I in (".\%~n0.png") do set "PDVZIP_RESTORE_TARGET=%%~fI""#)
            );
            assert!(script.contains(r#"move /-Y "%~f0" "%PDVZIP_RESTORE_TARGET%""#));
            assert!(!script.contains("$$"));
            assert!(!script.contains("%RANDOM%"));
            assert!(script.len() < MAX_SCRIPT_SIZE);
        }
    }
}
