#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum FileType {
    VideoAudio = 29,
    Pdf,
    Python,
    Powershell,
    BashShell,
    WindowsExecutable,
    UnknownFileType,
    Folder,
    LinuxExecutable,
    Jar,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserArguments {
    pub linux_args: String,
    pub windows_args: String,
}

pub const EXTENSION_LIST: &[&str] = &[
    "mp4", "mp3", "wav", "mpg", "webm", "flac", "3gp", "aac", "aiff", "aif", "alac", "ape",
    "avchd", "avi", "dsd", "divx", "f4v", "flv", "m4a", "m4v", "mkv", "mov", "midi", "mpeg", "ogg",
    "pcm", "swf", "wma", "wmv", "xvid", "pdf", "py", "ps1", "sh", "exe",
];
