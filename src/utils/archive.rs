use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use flate2::read::GzDecoder;
use tar::Archive as TarArchive;
use zip::ZipArchive;

/// Safely extract an archive (.zip, .tar.gz, .tar) into a destination directory.
pub fn extract_archive(archive_path: &Path, destination_dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(destination_dir)?;

    let ext = archive_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    let filename = archive_path.file_name().and_then(|s| s.to_str()).unwrap_or("");

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
            io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

fn extract_tar_gz(archive_path: &Path, dest_dir: &Path) -> io::Result<()> {
    let file = File::open(archive_path)?;
    let gz_decoder = GzDecoder::new(BufReader::new(file));
    let mut tar = TarArchive::new(gz_decoder);
    tar.unpack(dest_dir)?;
    Ok(())
}

fn extract_tar(archive_path: &Path, dest_dir: &Path) -> io::Result<()> {
    let file = File::open(archive_path)?;
    let mut tar = TarArchive::new(BufReader::new(file));
    tar.unpack(dest_dir)?;
    Ok(())
}
