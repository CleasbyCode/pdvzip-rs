use std::io::{self, Write};
use std::path::PathBuf;

use pdvzip_rs::archive;
use pdvzip_rs::assembly;
use pdvzip_rs::binary_utils::{ByteOrder, update_value};
use pdvzip_rs::image;
use pdvzip_rs::io as file_io;
use pdvzip_rs::io::FileTypeCheck;
use pdvzip_rs::script;
use pdvzip_rs::types::{FileType, UserArguments};

#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildArgs {
    image_file_path: PathBuf,
    archive_file_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Info,
    Build(BuildArgs),
}

fn usage(program_name: &str) -> String {
    format!("\nUsage: {program_name} <cover_image> <zip/jar>\n       {program_name} --info\n")
}

fn parse_cli(args: &[String], program_name: &str) -> Result<Command, String> {
    if args.is_empty() {
        return Err("Invalid program invocation: missing program name".to_string());
    }

    if args.len() == 2 {
        if args[1] == "--info" {
            return Ok(Command::Info);
        }
        return Err(usage(program_name));
    }

    if args.len() != 3 {
        return Err(usage(program_name));
    }

    Ok(Command::Build(BuildArgs {
        image_file_path: PathBuf::from(&args[1]),
        archive_file_path: PathBuf::from(&args[2]),
    }))
}

fn needs_user_arguments(file_type: FileType) -> bool {
    matches!(
        file_type,
        FileType::Python
            | FileType::Powershell
            | FileType::BashShell
            | FileType::WindowsExecutable
            | FileType::LinuxExecutable
            | FileType::Jar
    )
}

fn prompt_line(label: &str) -> Result<String, String> {
    print!("{label}");
    io::stdout()
        .flush()
        .map_err(|err| format!("I/O Error: Failed writing prompt: {err}"))?;

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|err| format!("I/O Error: Failed reading stdin: {err}"))?;

    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }

    Ok(line)
}

fn collect_user_arguments(file_type: FileType) -> Result<UserArguments, String> {
    const MAX_ARG_LENGTH: usize = 1024;

    let mut args = UserArguments::default();

    if !needs_user_arguments(file_type) {
        return Ok(args);
    }

    println!("\nFor this file type, if required, you can provide command-line arguments here.");

    if file_type != FileType::WindowsExecutable {
        args.linux_args = prompt_line("\nLinux: ")?;
        if args.linux_args.len() > MAX_ARG_LENGTH {
            return Err("Input Error: Linux arguments exceed maximum length.".to_string());
        }
    }
    if file_type != FileType::LinuxExecutable {
        args.windows_args = prompt_line("\nWindows: ")?;
        if args.windows_args.len() > MAX_ARG_LENGTH {
            return Err("Input Error: Windows arguments exceed maximum length.".to_string());
        }
    }

    Ok(args)
}

fn print_info() {
    print!(
        r#"
PNG Data Vehicle ZIP/JAR Edition (PDVZIP v4.7).
Created by Nicholas Cleasby (@CleasbyCode) 6/08/2022.

Use PDVZIP to embed a ZIP/JAR file within a PNG image,
to create a tweetable and "executable" PNG-ZIP/JAR polyglot file.

The supported hosting sites will retain the embedded archive within the PNG image.

PNG image size limits are platform dependant:

X/Twitter (5MB), Flickr (200MB), Imgbb (32MB), PostImage (32MB), ImgPile (8MB).

Once the ZIP file has been embedded within a PNG image, it can be shared on your chosen
hosting site or 'executed' whenever you want to access the embedded file(s).

pdvzip (Linux) will attempt to automatically set executable permissions on newly created polyglot image files.
You will need to manually set executable permissions using chmod on these polyglot images downloaded from hosting sites.

From a Linux terminal: ./pzip_image.png (chmod +x pzip_image.png, if required).
From a Windows terminal: First, rename the '.png' file extension to '.cmd', then .\pzip_image.cmd

For common video/audio files, Linux uses the media player vlc or mpv. Windows uses the set default media player.
PDF, Linux uses either evince or firefox. Windows uses the set default PDF viewer.
Python, Linux & Windows use python3 to run these programs.
PowerShell, Linux uses pwsh command (if PowerShell is installed).
Depending on the installed version of PowerShell, Windows uses either pwsh.exe or powershell.exe, to run these scripts.
Folder, Linux uses xdg-open, Windows uses the default shell file association to open zipped folders.

For any other media type/file extension, Linux & Windows will rely on the operating system's method or set default application for those files.

PNG Image Requirements for Arbitrary Data Preservation

PNG file size (image + embedded content) must not exceed the hosting site's size limits.
The site will either refuse to upload your image or it will convert your image to jpg, such as X/Twitter.

Dimensions:

The following dimension size limits are specific to pdvzip and not necessarily the exact hosting site's size limits.

PNG-32/24 (Truecolor)

Image dimensions can be set between a minimum of 68x68 and a maximum of 900x900.
These dimension size limits are for compatibility reasons, allowing it to work with all the above listed platforms.

Note: Images that are created & saved within your image editor as PNG-32/24 that are either
black & white/grayscale, images with 256 colours or less, will be converted by X/Twitter to
PNG-8 and you will lose the embedded content. If you want to use a simple "single" colour PNG-32/24 image,
then fill an area with a gradient colour instead of a single solid colour.
X/Twitter should then keep the image as PNG-32/24.

PNG-8 (Indexed-colour)

Image dimensions can be set between a minimum of 68x68 and a maximum of 4096x4096.

PNG Chunks:

For example, with X/Twitter, you can overfill the following PNG chunks with arbitrary data,
in which the platform will preserve as long as you keep within the image dimension & file size limits.

Other platforms may differ in what chunks they preserve and which you can overfill.

bKGD, cHRM, gAMA, hIST,
iCCP, (Only 10KB max. with X/Twitter).
IDAT, (Use as last IDAT chunk, after the final image IDAT chunk).
PLTE, (Use only with PNG-32 & PNG-24 for arbitrary data).
pHYs, sBIT, sPLT, sRGB,
tRNS. (PNG-32 only).

This program uses the iCCP (extraction script) and IDAT (zip file) chunk names for storing arbitrary data.

ZIP File Size & Other Information

To work out the maximum ZIP file size, start with the hosting site's size limit,
minus your PNG image size, minus 1500 bytes (extraction script size).

X/Twitter example: (5MB Image Limit) 5,242,880 - (image size 307,200 + extraction script size 1500) = 4,934,180 bytes available for your ZIP file.

Make sure ZIP file is a standard ZIP archive, compatible with Linux unzip & Windows Explorer.
Do not include other .zip files within the main ZIP archive. (.rar files are ok).
Do not include other pdvzip created PNG image files within the main ZIP archive, as they are essentially .zip files.
Use file extensions for your media file within the ZIP archive: my_doc.pdf, my_video.mp4, my_program.py, etc.
A file without an extension will be treated as a Linux executable.
Paint.net application is recommended for easily creating compatible PNG image files.

"#
    );
}

fn run_build(build_args: &BuildArgs) -> Result<(), String> {
    let mut image_vec = file_io::read_file(&build_args.image_file_path, FileTypeCheck::CoverImage)?;
    let mut archive_vec =
        file_io::read_file(&build_args.archive_file_path, FileTypeCheck::ArchiveFile)?;

    image::optimize_image(&mut image_vec)?;
    let original_image_size = image_vec.len();

    let is_zip_file = file_io::has_file_extension(&build_args.archive_file_path, &[".zip"]);
    if archive_vec.len() < 12 {
        return Err("Archive File Error: Invalid file size.".to_string());
    }
    let archive_data_length = archive_vec.len() - 12;

    update_value(&mut archive_vec, 0, archive_data_length, 4, ByteOrder::Big)
        .map_err(|err| format!("Archive File Error: {err}"))?;

    archive::validate_archive_entry_paths(&archive_vec)?;
    let file_type = archive::determine_file_type(&archive_vec, is_zip_file)?;
    let first_filename = archive::get_archive_first_filename(&archive_vec)?;
    let user_args = collect_user_arguments(file_type)?;

    let script_vec = script::build_extraction_script(file_type, &first_filename, &user_args)?;

    assembly::embed_chunks(&mut image_vec, script_vec, archive_vec, original_image_size)?;

    let output_path = file_io::write_polyglot_file(&image_vec, is_zip_file, None, false)?;

    println!(
        "\nCreated {} polyglot image file: {} ({} bytes).\n\nComplete!\n",
        if is_zip_file { "PNG-ZIP" } else { "PNG-JAR" },
        output_path.display(),
        image_vec.len()
    );

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program_name = args
        .first()
        .map_or_else(|| "pdvzip-rs".to_string(), Clone::clone);

    let command = match parse_cli(&args, &program_name) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let result = match command {
        Command::Info => {
            print_info();
            Ok(())
        }
        Command::Build(build_args) => run_build(&build_args),
    };

    if let Err(err) = result {
        eprintln!("\n{err}\n");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{BuildArgs, Command, parse_cli, usage};

    fn vec_args(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn parse_info_and_build() {
        let cmd = parse_cli(&vec_args(&["pdvzip-rs", "--info"]), "pdvzip-rs").expect("parse");
        assert!(matches!(cmd, Command::Info));

        let cmd = parse_cli(
            &vec_args(&["pdvzip-rs", "face.png", "data.zip"]),
            "pdvzip-rs",
        )
        .expect("parse");
        assert_eq!(
            cmd,
            Command::Build(BuildArgs {
                image_file_path: "face.png".into(),
                archive_file_path: "data.zip".into(),
            })
        );
    }

    #[test]
    fn parse_rejects_extra_options() {
        let err = parse_cli(
            &vec_args(&["pdvzip-rs", "face.png", "data.zip", "--no-prompt"]),
            "pdvzip-rs",
        )
        .expect_err("should fail");
        assert_eq!(err, usage("pdvzip-rs"));
    }
}
