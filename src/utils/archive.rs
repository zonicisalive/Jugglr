use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use flate2::read::GzDecoder;
use tar::Archive as TarArchive;
use zip::ZipArchive;

/// Hard ceilings on what a single archive is allowed to unpack.
///
/// Auto-extraction runs unattended on files that just landed in a watched folder, so a
/// decompression bomb would otherwise fill the disk before anyone noticed. The
/// `zipbomb_detector` condition can flag such archives up front, but extraction must be safe
/// on its own even when no rule enabled that check.
const MAX_EXTRACTED_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const MAX_EXTRACTED_ENTRIES: usize = 100_000;

fn limit_exceeded(archive_path: &Path, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "Refusing to extract {}: {} (possible decompression bomb)",
            archive_path.display(),
            what
        ),
    )
}

/// Safely extract an archive (.zip, .tar.gz, .tar) into a destination directory.
pub fn extract_archive(archive_path: &Path, destination_dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(destination_dir)?;

    let ext = archive_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    let filename = archive_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

    if ext == "zip" {
        extract_zip(archive_path, destination_dir)?;
    } else if filename.ends_with(".tar.gz") || ext == "tgz" {
        extract_tar_gz(archive_path, destination_dir)?;
    } else if ext == "tar" {
        extract_tar(archive_path, destination_dir)?;
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported archive format: {}", archive_path.display()),
        ));
    }

    Ok(destination_dir.to_path_buf())
}

fn extract_zip(archive_path: &Path, dest_dir: &Path) -> io::Result<()> {
    let file = File::open(archive_path)?;
    let mut zip = ZipArchive::new(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if zip.len() > MAX_EXTRACTED_ENTRIES {
        return Err(limit_exceeded(archive_path, &format!("{} entries", zip.len())));
    }

    let mut written_total: u64 = 0;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Zip-Slip protection: ensure safe enclosed path
        let enclosed_name = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => continue,
        };

        let out_path = dest_dir.join(enclosed_name);

        if file.name().ends_with('/') {
            fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            let mut outfile = File::create(&out_path)?;

            // Copy through a cap rather than trusting the header's declared size, which a
            // crafted archive is free to understate.
            let remaining = MAX_EXTRACTED_BYTES - written_total;
            let written = io::copy(&mut (&mut file).take(remaining + 1), &mut outfile)?;
            if written > remaining {
                drop(outfile);
                let _ = fs::remove_file(&out_path);
                return Err(limit_exceeded(
                    archive_path,
                    &format!("expands past the {} GiB limit", MAX_EXTRACTED_BYTES / (1024 * 1024 * 1024)),
                ));
            }
            written_total += written;
        }
    }

    Ok(())
}

fn extract_tar_gz(archive_path: &Path, dest_dir: &Path) -> io::Result<()> {
    let file = File::open(archive_path)?;
    let gz_decoder = GzDecoder::new(BufReader::new(file));
    unpack_tar(TarArchive::new(gz_decoder), archive_path, dest_dir)
}

fn extract_tar(archive_path: &Path, dest_dir: &Path) -> io::Result<()> {
    let file = File::open(archive_path)?;
    unpack_tar(TarArchive::new(BufReader::new(file)), archive_path, dest_dir)
}

/// Unpack tar entries one at a time so the totals can be capped.
///
/// `Entry::unpack_in` keeps the same traversal protection as `Archive::unpack`: entries with
/// absolute paths or `..` components are refused rather than written outside `dest_dir`.
fn unpack_tar<R: Read>(mut tar: TarArchive<R>, archive_path: &Path, dest_dir: &Path) -> io::Result<()> {
    let mut written_total: u64 = 0;
    let mut entry_count: usize = 0;

    for entry in tar.entries()? {
        let mut entry = entry?;

        entry_count += 1;
        if entry_count > MAX_EXTRACTED_ENTRIES {
            return Err(limit_exceeded(archive_path, &format!("more than {} entries", MAX_EXTRACTED_ENTRIES)));
        }

        written_total = written_total.saturating_add(entry.size());
        if written_total > MAX_EXTRACTED_BYTES {
            return Err(limit_exceeded(
                archive_path,
                &format!("expands past the {} GiB limit", MAX_EXTRACTED_BYTES / (1024 * 1024 * 1024)),
            ));
        }

        entry.unpack_in(dest_dir)?;
    }

    Ok(())
}
