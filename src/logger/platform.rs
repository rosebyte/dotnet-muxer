#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod linux;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod macos;

#[cfg(windows)]
#[path = "windows.rs"]
mod windows;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("Unsupported target OS. dotnet-muxer currently supports only linux, macos, and windows.");

#[cfg(target_os = "linux")]
pub(crate) use linux::write_parent_fields;

#[cfg(target_os = "macos")]
pub(crate) use macos::write_parent_fields;

#[cfg(windows)]
pub(crate) use windows::write_parent_fields;
