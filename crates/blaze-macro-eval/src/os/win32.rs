//! What std asks of Windows, answered as [`super::env`] and [`super::files`] answer it of Unix:
//! the same descriptors and walks, each read noted the same way, so that an expansion is keyed
//! by what it read here too. A path crosses here: the daemon names `/C:/a` what a macro holds as
//! `C:\a`, so each is made the other's on its way through. A failed call says why through the
//! thread's last error ([`Os::last_error`]), which std clears and reads around each call.
//!
//! A handle is a descriptor of [`Os::fds`], so it is never 0 or `INVALID_HANDLE_VALUE`; the
//! standard handles are 1 and 2, below every descriptor.
//!
//! A macro may write below `OUT_DIR` alone, as `tauri::generate_context!` does, leaving there
//! what it compressed for the `include_bytes!` it expands to. A key has no outputs, so such an
//! expansion is not kept, and runs again each time.

use std::{fs, io};

use blaze_usercode::trace::{ALL_ENV, Seen};

use super::{
    Answer, Done, Noted, Os, clock,
    files::{self, FIRST_FD, MANIFEST_DIR, Open, daemon_path, host},
    ok,
    target::{Arch, DEV, Errno, Kind, System, Target},
};
use crate::guest::{Guest, Stop, put_word, word};

/// What a walk is told of the target. It reads only the directory the `*at` calls name as the
/// working one; an [`Errno`] goes no further than [`error_of`].
const WALK: Target = Target { system: System::Linux, arch: Arch::X86_64 };

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_GEN_FAILURE: u32 = 31;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NEGATIVE_SEEK: u32 = 131;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_ENVVAR_NOT_FOUND: u32 = 203;
const ERROR_DIRECTORY: u32 = 267;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;

const INVALID_HANDLE_VALUE: u64 = u64::MAX;

const CREATE_NEW: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_READ_DATA: u32 = 0x1;
/// `GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE`.
const WRITES: u32 = 0x4000_0000 | 0x1000_0000 | 0x2 | 0x4 | 0x1_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

const FILE_BEGIN: u32 = 0;
const FILE_CURRENT: u32 = 1;
const FILE_END: u32 = 2;

/// `STD_OUTPUT_HANDLE` and `STD_ERROR_HANDLE`, the `DWORD`s of -11 and -12.
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4;

/// Ticks of [`Os::performance_counter`] a second.
const TICKS: u64 = 1_000_000_000;

/// 100-nanosecond intervals from 1601, where a `FILETIME` starts, to the Unix epoch.
const FILETIME_LEAD: u64 = 116_444_736_000_000_000;

/// The longest string read: Windows' longest path.
const WIDE_MAX: u64 = 32 << 10;

/// `BY_HANDLE_FILE_INFORMATION`.
const FILE_INFORMATION_SIZE: usize = 52;

/// `WIN32_FIND_DATAW`.
const FIND_DATA_SIZE: usize = 592;
const FIND_DATA_NAME: usize = 44;
/// The units of `cFileName`, its NUL included.
const FIND_DATA_NAME_LEN: usize = 260;

/// Each function of Windows that is answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Win32 {
    GetLastError,
    SetLastError,
    GetEnvironmentVariable,
    GetEnvironmentStrings,
    FreeEnvironmentStrings,
    GetCurrentDirectory,
    SetCurrentDirectory,
    GetFullPathName,
    CreateDirectory,
    CreateFile,
    CloseHandle,
    GetFileInformationByHandle,
    GetFinalPathNameByHandle,
    SetFilePointerEx,
    NtReadFile,
    NtWriteFile,
    RtlNtStatusToDosError,
    FindFirstFileEx,
    FindNextFile,
    FindClose,
    /// What a search for a program to start asks: a macro starts none, so it finds none, and
    /// `Command::output` is the error `NotFound`, which `tauri::command` lives with.
    NoProgramFound,
    GetStdHandle,
    GetConsoleMode,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    GetSystemTimePreciseAsFileTime,
}

impl Win32 {
    /// The function an extern function of the symbol `name` is.
    pub(super) fn of_name(name: &str) -> Option<Win32> {
        Some(match name {
            "GetLastError" => Win32::GetLastError,
            "SetLastError" => Win32::SetLastError,
            "GetEnvironmentVariableW" => Win32::GetEnvironmentVariable,
            "GetEnvironmentStringsW" => Win32::GetEnvironmentStrings,
            "FreeEnvironmentStringsW" => Win32::FreeEnvironmentStrings,
            "GetCurrentDirectoryW" => Win32::GetCurrentDirectory,
            "SetCurrentDirectoryW" => Win32::SetCurrentDirectory,
            "GetFullPathNameW" => Win32::GetFullPathName,
            "CreateDirectoryW" => Win32::CreateDirectory,
            "CreateFileW" => Win32::CreateFile,
            "CloseHandle" => Win32::CloseHandle,
            "GetFileInformationByHandle" => Win32::GetFileInformationByHandle,
            "GetFinalPathNameByHandleW" => Win32::GetFinalPathNameByHandle,
            "SetFilePointerEx" => Win32::SetFilePointerEx,
            "NtReadFile" => Win32::NtReadFile,
            "NtWriteFile" => Win32::NtWriteFile,
            "RtlNtStatusToDosError" => Win32::RtlNtStatusToDosError,
            "FindFirstFileExW" => Win32::FindFirstFileEx,
            "FindNextFileW" => Win32::FindNextFile,
            "FindClose" => Win32::FindClose,
            "GetModuleFileNameW" | "GetSystemDirectoryW" | "GetWindowsDirectoryW" | "GetFileAttributesW" => {
                Win32::NoProgramFound
            }
            "GetStdHandle" => Win32::GetStdHandle,
            "GetConsoleMode" => Win32::GetConsoleMode,
            "QueryPerformanceCounter" => Win32::QueryPerformanceCounter,
            "QueryPerformanceFrequency" => Win32::QueryPerformanceFrequency,
            "GetSystemTimePreciseAsFileTime" => Win32::GetSystemTimePreciseAsFileTime,
            _ => return None,
        })
    }
}

/// The Win32 error of what a walk said.
fn error_of(errno: Errno) -> u32 {
    match errno {
        Errno::Noent => ERROR_FILE_NOT_FOUND,
        Errno::Notdir => ERROR_PATH_NOT_FOUND,
        Errno::Acces => ERROR_ACCESS_DENIED,
        Errno::Badf => ERROR_INVALID_HANDLE,
        _ => ERROR_GEN_FAILURE,
    }
}

/// The NUL-terminated UTF-16 string at `addr`.
fn wide(g: &impl Guest, addr: u64) -> Result<String, Stop> {
    // alloc: per call that names a string, its units
    let mut units = Vec::new();
    for at in 0..WIDE_MAX {
        let unit = g.read(addr + 2 * at, 2)?;
        match u16::from_le_bytes([unit[0], unit[1]]) {
            0 => {
                return String::from_utf16(&units).map_err(|_| {
                    // alloc: error path
                    Stop(format!(
                        "names {:?}, which is not UTF-16, and blaze traces what a proc macro \
                         reads by UTF-8 paths",
                        String::from_utf16_lossy(&units)
                    ))
                });
            }
            unit => units.push(unit),
        }
    }
    // alloc: error path
    Err(Stop(format!("passed a string longer than {WIDE_MAX} units, or one with no end")))
}

/// What the daemon named as a macro is given it: a path as this system has it, anything else
/// as it is.
fn host_value(text: &str) -> String {
    let bytes = text.as_bytes();
    match bytes.len() >= 4 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' && bytes[3] == b'/' {
        true => text[1..].replace('/', "\\"),
        false => text.to_owned(),
    }
}

impl<'a> Os<'a> {
    pub(super) fn win32(&mut self, call: Win32, g: &mut impl Guest, args: &[&[u8]], ret: &mut [u8]) -> Done {
        let handle = |n| word(args, n).map(|it| it as i64);
        match call {
            Win32::GetLastError => ok(ret, u64::from(self.last_error)),
            Win32::SetLastError => {
                self.last_error = word(args, 0)? as u32;
                Ok(Answer::Answered)
            }
            Win32::GetEnvironmentVariable => {
                self.get_environment_variable(g, ret, word(args, 0)?, (word(args, 1)?, word(args, 2)?))
            }
            Win32::GetEnvironmentStrings => self.get_environment_strings(g, ret),
            Win32::FreeEnvironmentStrings => ok(ret, 1),
            Win32::GetCurrentDirectory => {
                let cwd = self.working_dir()?;
                self.give(g, ret, &host_value(&cwd), (word(args, 1)?, word(args, 0)?))
            }
            Win32::SetCurrentDirectory => self.set_current_directory(g, ret, word(args, 0)?),
            Win32::GetFullPathName => {
                self.get_full_path_name(g, ret, word(args, 0)?, (word(args, 2)?, word(args, 1)?))
            }
            Win32::CreateDirectory => self.create_directory(g, ret, word(args, 0)?),
            Win32::CreateFile => {
                let (access, creation, flags) = (word(args, 1)? as u32, word(args, 4)? as u32, word(args, 5)? as u32);
                self.create_file(g, ret, word(args, 0)?, (access, creation, flags))
            }
            Win32::CloseHandle | Win32::FindClose => self.close_handle(ret, handle(0)?),
            Win32::GetFileInformationByHandle => self.get_file_information(g, ret, handle(0)?, word(args, 1)?),
            Win32::GetFinalPathNameByHandle => {
                let Some(slot) = files::slot(&self.fds, handle(0)?) else {
                    return self.failed(ret, ERROR_INVALID_HANDLE);
                };
                // alloc: per call, the path as the system says it
                let path = format!(r"\\?\{}", host_value(&slot.path));
                self.give(g, ret, &path, (word(args, 1)?, word(args, 2)?))
            }
            Win32::SetFilePointerEx => {
                let at = (handle(0)?, word(args, 1)? as i64);
                self.set_file_pointer(g, ret, at, word(args, 2)?, word(args, 3)? as u32)
            }
            Win32::NtReadFile => {
                let into = (word(args, 5)?, word(args, 6)? as u32);
                self.nt_read_file(g, ret, handle(0)?, word(args, 4)?, into, word(args, 7)?)
            }
            Win32::NtWriteFile => {
                let from = (word(args, 5)?, word(args, 6)? as u32);
                self.nt_write_file(g, ret, handle(0)?, word(args, 4)?, from)
            }
            Win32::RtlNtStatusToDosError => ok(ret, u64::from(ERROR_GEN_FAILURE)),
            Win32::FindFirstFileEx => self.find_first_file(g, ret, word(args, 0)?, word(args, 2)?),
            Win32::FindNextFile => self.find_next_file(g, ret, handle(0)?, word(args, 1)?),
            // Zero is a failure of the three that fill a path; `GetFileAttributesW` fails with
            // `INVALID_FILE_ATTRIBUTES`, its return all ones.
            Win32::NoProgramFound => {
                self.last_error = ERROR_FILE_NOT_FOUND;
                ok(ret, if ret.len() == 4 && args.len() == 1 { u64::MAX } else { 0 })
            }
            Win32::GetStdHandle => ok(ret, match word(args, 0)? as u32 {
                STD_OUTPUT_HANDLE => 1,
                STD_ERROR_HANDLE => 2,
                _ => 0,
            }),
            // Neither standard handle is a console: what is written to it is `NtWriteFile`'s.
            Win32::GetConsoleMode => self.failed(ret, ERROR_INVALID_HANDLE),
            Win32::QueryPerformanceCounter => self.performance_counter(g, ret, word(args, 0)?),
            // A constant, so not a read.
            Win32::QueryPerformanceFrequency => {
                g.write_u64(word(args, 0)?, TICKS)?;
                ok(ret, 1)
            }
            Win32::GetSystemTimePreciseAsFileTime => {
                self.note_clock();
                g.write_u64(word(args, 0)?, clock::now_ns() / 100 + FILETIME_LEAD)?;
                Ok(Answer::Answered)
            }
        }
    }

    /// The call failed with `error`: zero returned, which is `FALSE` and no length.
    fn failed(&mut self, ret: &mut [u8], error: u32) -> Done {
        self.last_error = error;
        ok(ret, 0)
    }

    /// `text` as a Win32 call fills the caller's `(buffer, units)`: its length without its NUL
    /// when it fits, else the units it needs, its NUL included.
    fn give(&mut self, g: &mut impl Guest, ret: &mut [u8], text: &str, (buf, size): (u64, u64)) -> Done {
        self.bytes.clear();
        self.bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let units = self.bytes.len() as u64 / 2;
        if units + 1 > size {
            return ok(ret, units + 1);
        }
        self.bytes.extend_from_slice(&[0, 0]);
        g.write(buf, &self.bytes)?;
        ok(ret, units)
    }

    /// `GetEnvironmentVariableW`: a name is of any case on Windows.
    fn get_environment_variable(&mut self, g: &mut impl Guest, ret: &mut [u8], name: u64, into: (u64, u64)) -> Done {
        let name = wide(g, name)?;
        self.trace.note(Noted::Seen(Seen::Env), &name);
        let env = self.env;
        let Some((_, value)) = env.iter().find(|it| it.0.eq_ignore_ascii_case(&name)) else {
            return self.failed(ret, ERROR_ENVVAR_NOT_FOUND);
        };
        self.give(g, ret, &host_value(value), into)
    }

    /// `GetEnvironmentStringsW`: the block of `NAME=value` strings, sorted by name.
    fn get_environment_strings(&mut self, g: &mut impl Guest, ret: &mut [u8]) -> Done {
        if !self.trace.all_env {
            self.trace.all_env = true;
            self.trace.note(Noted::Seen(Seen::Env), ALL_ENV);
        }
        // alloc: once per expansion that walks the whole environment
        let mut vars: Vec<(&str, &str)> = self.env.iter().collect();
        vars.sort_unstable();
        self.bytes.clear();
        for (name, value) in vars {
            let var = format!("{name}={}", host_value(value));
            self.bytes.extend(var.encode_utf16().flat_map(u16::to_le_bytes));
            self.bytes.extend_from_slice(&[0, 0]);
        }
        self.bytes.extend_from_slice(&[0, 0]);
        let block = g.alloc(&self.bytes, 2)?;
        ok(ret, block)
    }

    /// The directory a relative path starts at, as the daemon names it.
    fn working_dir(&mut self) -> Result<String, Stop> {
        self.ready();
        let cwd = self.cwd.as_deref().or(self.roots.as_ref().and_then(files::Roots::cwd));
        // alloc: per call, and an error
        cwd.map(str::to_owned).ok_or_else(|| {
            Stop(format!("asks for its working directory, and the calling crate has no `{MANIFEST_DIR}`"))
        })
    }

    /// `SetCurrentDirectoryW`: this expansion's own working directory moves.
    fn set_current_directory(&mut self, g: &mut impl Guest, ret: &mut [u8], addr: u64) -> Done {
        let path = wide(g, addr)?;
        match self.locate(WALK, (WALK.at_flags().fdcwd, &daemon_path(&path)), true, Seen::Looked)? {
            Ok((Kind::Dir, _)) => {
                self.cwd = Some(self.real.clone());
                ok(ret, 1)
            }
            Ok(_) => self.failed(ret, ERROR_DIRECTORY),
            Err(errno) => self.failed(ret, error_of(errno)),
        }
    }

    /// `path`, a macro's, absolute as the daemon names it: from its text alone, as the system
    /// makes it.
    fn full_path(&mut self, path: &str) -> Result<String, Stop> {
        let path = daemon_path(path);
        let mut full = match path.starts_with('/') {
            true => String::new(),
            false => self.working_dir()?,
        };
        for part in path.split('/').filter(|it| !it.is_empty()) {
            match part {
                "." => {}
                ".." => full.truncate(full.rfind('/').unwrap_or(0)),
                part => {
                    full.push('/');
                    full.push_str(part);
                }
            }
        }
        Ok(full)
    }

    fn get_full_path_name(&mut self, g: &mut impl Guest, ret: &mut [u8], addr: u64, into: (u64, u64)) -> Done {
        let path = wide(g, addr)?;
        let full = self.full_path(&path)?;
        self.give(g, ret, &host_value(&full), into)
    }

    /// `path`, a macro's, absolute, when it is below `OUT_DIR`, and the expansion noted as one
    /// that can't be kept; the only way a macro writes.
    fn output(&mut self, path: &str) -> Result<String, Stop> {
        let full = self.full_path(path)?;
        self.ready();
        if !self.roots.as_ref().is_some_and(|roots| roots.in_out_dir(&full)) {
            // alloc: error path
            return Err(Stop(format!("writes `{path}`, outside `OUT_DIR`, which a proc macro may not")));
        }
        // alloc: per expansion that writes, once
        self.unkeyable.get_or_insert_with(|| format!("{full}: written by the macro"));
        Ok(full)
    }

    fn create_directory(&mut self, g: &mut impl Guest, ret: &mut [u8], addr: u64) -> Done {
        let path = wide(g, addr)?;
        let full = self.output(&path)?;
        match fs::create_dir(host(&full)) {
            Ok(()) => ok(ret, 1),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => self.failed(ret, ERROR_ALREADY_EXISTS),
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.failed(ret, ERROR_PATH_NOT_FOUND),
            Err(error) => {
                self.cant(&full, &error);
                self.failed(ret, ERROR_GEN_FAILURE)
            }
        }
    }

    /// `CreateFileW` of a file to write: nothing reaches the disk until it is closed.
    fn create_output(&mut self, ret: &mut [u8], path: &str, creation: u32) -> Done {
        let full = self.output(path)?;
        if creation == CREATE_NEW && fs::exists(host(&full)).unwrap_or(false) {
            self.last_error = ERROR_ALREADY_EXISTS;
            return ok(ret, INVALID_HANDLE_VALUE);
        }
        self.real.clear();
        self.real.push_str(&full);
        let fd = match self.opened(Kind::File, 0, false) {
            Ok(fd) => fd,
            Err(errno) => {
                self.last_error = error_of(errno);
                return ok(ret, INVALID_HANDLE_VALUE);
            }
        };
        if let Some(slot) = files::slot_mut(&mut self.fds, fd) {
            slot.writing = true;
        }
        // Not `ERROR_ALREADY_EXISTS`, which would have std cut what `bytes` replaces anyway.
        self.last_error = 0;
        ok(ret, fd as u64)
    }

    /// `CloseHandle`, of anything: what is not a descriptor has nothing to close.
    fn close_handle(&mut self, ret: &mut [u8], handle: i64) -> Done {
        let Some(slot) = files::slot_mut(&mut self.fds, handle) else { return ok(ret, 1) };
        slot.open = Open::Closed;
        if !slot.writing {
            return ok(ret, 1);
        }
        slot.writing = false;
        if let Err(error) = fs::write(host(&slot.path), &slot.bytes) {
            // alloc: error path
            let path = slot.path.clone();
            self.cant(&path, &error);
            return self.failed(ret, ERROR_GEN_FAILURE);
        }
        ok(ret, 1)
    }

    /// `CreateFileW` of what is there: read whole when it is opened to read, only looked at
    /// otherwise, as std opens a file to ask of it.
    fn create_file(&mut self, g: &mut impl Guest, ret: &mut [u8], addr: u64, (access, creation, flags): (u32, u32, u32)) -> Done {
        let path = wide(g, addr)?;
        if access & WRITES != 0 || creation != OPEN_EXISTING {
            return self.create_output(ret, &path, creation);
        }
        let read = access & (GENERIC_READ | FILE_READ_DATA) != 0;
        let follow = flags & FILE_FLAG_OPEN_REPARSE_POINT == 0;
        let seen = if read { Seen::Read } else { Seen::Looked };
        let (kind, size) = match self.locate(WALK, (WALK.at_flags().fdcwd, &daemon_path(&path)), follow, seen)? {
            Ok(found) => found,
            Err(errno) => {
                self.last_error = error_of(errno);
                return ok(ret, INVALID_HANDLE_VALUE);
            }
        };
        match kind {
            Kind::Dir if flags & FILE_FLAG_BACKUP_SEMANTICS == 0 => {
                self.last_error = ERROR_ACCESS_DENIED;
                ok(ret, INVALID_HANDLE_VALUE)
            }
            // alloc: error path
            Kind::Link => Err(Stop(format!("opens the link `{}` itself, which blaze's evaluator doesn't model", self.real))),
            // alloc: error path
            Kind::Other => Err(Stop(format!("opens `{}`, which is neither a file nor a directory", self.real))),
            Kind::File | Kind::Dir => match self.opened(kind, size, read && kind == Kind::File) {
                Ok(fd) => ok(ret, fd as u64),
                Err(errno) => {
                    self.last_error = error_of(errno);
                    ok(ret, INVALID_HANDLE_VALUE)
                }
            },
        }
    }

    /// `GetFileInformationByHandle`: as a `stat` says it, its kind, size and an inode.
    fn get_file_information(&mut self, g: &mut impl Guest, ret: &mut [u8], handle: i64, info: u64) -> Done {
        let Some(slot) = files::slot(&self.fds, handle) else { return self.failed(ret, ERROR_INVALID_HANDLE) };
        let attributes = if slot.open == Open::Dir { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL };
        let mut out = [0; FILE_INFORMATION_SIZE];
        out[..4].copy_from_slice(&attributes.to_le_bytes());
        out[28..32].copy_from_slice(&(DEV as u32).to_le_bytes());
        out[32..36].copy_from_slice(&((slot.size >> 32) as u32).to_le_bytes());
        out[36..40].copy_from_slice(&(slot.size as u32).to_le_bytes());
        out[40..44].copy_from_slice(&1u32.to_le_bytes());
        out[44..48].copy_from_slice(&((slot.ino >> 32) as u32).to_le_bytes());
        out[48..52].copy_from_slice(&(slot.ino as u32).to_le_bytes());
        g.write(info, &out)?;
        ok(ret, 1)
    }

    fn set_file_pointer(&mut self, g: &mut impl Guest, ret: &mut [u8], (handle, by): (i64, i64), new: u64, method: u32) -> Done {
        let Some(slot) = files::slot_mut(&mut self.fds, handle) else {
            return self.failed(ret, ERROR_INVALID_HANDLE);
        };
        let from = match method {
            FILE_BEGIN => 0,
            FILE_CURRENT => slot.at as i64,
            FILE_END => slot.size as i64,
            _ => return self.failed(ret, ERROR_INVALID_PARAMETER),
        };
        match from.checked_add(by) {
            Some(at) if at >= 0 => {
                slot.at = at as u64;
                if new != 0 {
                    g.write_u64(new, at as u64)?;
                }
                ok(ret, 1)
            }
            _ => self.failed(ret, ERROR_NEGATIVE_SEEK),
        }
    }

    /// `NtReadFile`, how std reads a file: from `*offset` when it is given.
    fn nt_read_file(
        &mut self,
        g: &mut impl Guest,
        ret: &mut [u8],
        handle: i64,
        status: u64,
        (buf, len): (u64, u32),
        offset: u64,
    ) -> Done {
        let Some(slot) = files::slot_mut(&mut self.fds, handle) else {
            return ok(ret, u64::from(STATUS_INVALID_HANDLE));
        };
        if slot.open == Open::Dir {
            return ok(ret, u64::from(STATUS_INVALID_DEVICE_REQUEST));
        }
        let from = match offset {
            0 => slot.at,
            at => g.read_u64(at)?,
        };
        let start = from.min(slot.bytes.len() as u64) as usize;
        let end = start + (len as usize).min(slot.bytes.len() - start);
        if end > start {
            g.write(buf, &slot.bytes[start..end])?;
        }
        if offset == 0 {
            slot.at = from + (end - start) as u64;
        }
        g.write_u64(status, 0)?;
        g.write_u64(status + 8, (end - start) as u64)?;
        ok(ret, if end == start && len != 0 { u64::from(STATUS_END_OF_FILE) } else { 0 })
    }

    /// `NtWriteFile`: to a file being made, or to a standard handle, which nothing reads.
    fn nt_write_file(&mut self, g: &mut impl Guest, ret: &mut [u8], handle: i64, status: u64, (buf, len): (u64, u32)) -> Done {
        if handle >= FIRST_FD {
            let Some(slot) = files::slot_mut(&mut self.fds, handle) else {
                return ok(ret, u64::from(STATUS_INVALID_HANDLE));
            };
            if !slot.writing {
                return Err(Stop(format!("writes to `{}`, opened to read", slot.path))); // alloc: error path
            }
            slot.bytes.extend_from_slice(g.read(buf, len as usize)?);
            slot.size = slot.bytes.len() as u64;
        }
        g.write_u64(status, 0)?;
        g.write_u64(status + 8, u64::from(len))?;
        ok(ret, 0)
    }

    /// `FindFirstFileExW` of `dir\*`, how std lists a directory.
    fn find_first_file(&mut self, g: &mut impl Guest, ret: &mut [u8], addr: u64, data: u64) -> Done {
        let path = wide(g, addr)?;
        let Some(dir) = path.strip_suffix('*') else {
            // alloc: error path
            return Err(Stop(format!("looks for the pattern `{path}`, which blaze's evaluator doesn't model")));
        };
        let found = self.locate(WALK, (WALK.at_flags().fdcwd, &daemon_path(dir)), true, Seen::Looked)?;
        let opened = match found {
            Ok((Kind::Dir, size)) => self.opened(Kind::Dir, size, false),
            Ok(_) => Err(Errno::Notdir),
            Err(errno) => Err(errno),
        };
        let fd = match opened {
            Ok(fd) => fd,
            Err(errno) => {
                self.last_error = error_of(errno);
                return ok(ret, INVALID_HANDLE_VALUE);
            }
        };
        let index = files::slot_index(&self.fds, fd).expect("a descriptor just opened");
        if let Err(error) = self.list(index) {
            let path = std::mem::take(&mut self.fds[index].path);
            self.cant(&path, &error);
            self.fds[index].path = path;
            self.last_error = ERROR_GEN_FAILURE;
            return ok(ret, INVALID_HANDLE_VALUE);
        }
        self.next_found(g, index, data)?;
        ok(ret, fd as u64)
    }

    fn find_next_file(&mut self, g: &mut impl Guest, ret: &mut [u8], handle: i64, data: u64) -> Done {
        let Some(index) = files::slot_index(&self.fds, handle) else {
            return self.failed(ret, ERROR_INVALID_HANDLE);
        };
        match self.next_found(g, index, data)? {
            true => ok(ret, 1),
            false => self.failed(ret, ERROR_NO_MORE_FILES),
        }
    }

    /// The next entry of the directory of the slot `index` as a `WIN32_FIND_DATAW`, of `Kind`
    /// and name alone. `false` once there are no more.
    fn next_found(&mut self, g: &mut impl Guest, index: usize, data: u64) -> Result<bool, Stop> {
        let slot = &mut self.fds[index];
        let Some(entry) = slot.entries.get(slot.at as usize) else { return Ok(false) };
        slot.at += 1;
        let (attributes, tag) = match entry.kind {
            Kind::Dir => (FILE_ATTRIBUTE_DIRECTORY, 0),
            Kind::Link => (FILE_ATTRIBUTE_REPARSE_POINT, IO_REPARSE_TAG_SYMLINK),
            Kind::File | Kind::Other => (FILE_ATTRIBUTE_NORMAL, 0),
        };
        let mut out = [0; FIND_DATA_SIZE];
        out[..4].copy_from_slice(&attributes.to_le_bytes());
        out[36..40].copy_from_slice(&tag.to_le_bytes());
        let name = String::from_utf8_lossy(&slot.names[entry.start as usize..entry.end as usize]);
        for (at, unit) in name.encode_utf16().take(FIND_DATA_NAME_LEN - 1).enumerate() {
            out[FIND_DATA_NAME + 2 * at..][..2].copy_from_slice(&unit.to_le_bytes());
        }
        g.write(data, &out)?;
        Ok(true)
    }

    /// `QueryPerformanceCounter`: nanoseconds of the real clock, [`TICKS`] of them a second.
    fn performance_counter(&mut self, g: &mut impl Guest, ret: &mut [u8], out: u64) -> Done {
        let mut ticks = [0; 8];
        self.mach_absolute_time(&mut ticks)?;
        g.write(out, &ticks)?;
        put_word(ret, 1);
        Ok(Answer::Answered)
    }
}
