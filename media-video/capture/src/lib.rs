#[cfg(target_family = "windows")]
pub mod dxgi_desktop_duplication;
#[cfg(target_family = "unix")]
pub mod wayland;


mod utils;