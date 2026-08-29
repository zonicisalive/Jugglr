use std::io;
use std::path::Path;

/// Safely move a file to the Linux FreeDesktop trash directory.
pub fn move_to_trash(path: &Path) -> io::Result<()> {
    trash::delete(path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to move '{}' to trash: {}", path.display(), e),
        )
    })
}
