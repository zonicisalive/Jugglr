use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use exif::{Reader, Tag};

#[derive(Debug, Clone, Default)]
pub struct ExifMetadata {
    pub year: Option<String>,
    pub month: Option<String>,
    pub day: Option<String>,
    pub camera_make: Option<String>,
    pub camera_model: Option<String>,
}

/// Extract EXIF metadata from an image file if available.
pub fn extract_exif(path: &Path) -> Option<ExifMetadata> {
    let file = File::open(path).ok()?;
    let mut bufreader = BufReader::new(file);
    let exif_reader = Reader::new().read_from_container(&mut bufreader).ok()?;

    let mut meta = ExifMetadata::default();

    for field in exif_reader.fields() {
        match field.tag {
            Tag::DateTimeOriginal | Tag::DateTime => {
                if meta.year.is_none() {
                    let date_str = field.display_value().to_string();
                    if let Some(first_part) = date_str.split_whitespace().next() {
                        let parts: Vec<&str> = first_part.split(&['-', ':'][..]).collect();
                        if parts.len() >= 3 {
                            meta.year = Some(parts[0].to_string());
                            meta.month = Some(parts[1].to_string());
                            meta.day = Some(parts[2].to_string());
                        }
                    }
                }
            }
            Tag::Make => {
                let make = field.display_value().to_string().trim_matches('"').trim().to_string();
                if !make.is_empty() && meta.camera_make.is_none() {
                    meta.camera_make = Some(make);
                }
            }
            Tag::Model => {
                let model = field.display_value().to_string().trim_matches('"').trim().to_string();
                if !model.is_empty() && meta.camera_model.is_none() {
                    meta.camera_model = Some(model);
                }
            }
            _ => {}
        }
    }

    Some(meta)
}
