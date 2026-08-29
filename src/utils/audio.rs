use std::path::Path;
use id3::{Tag, TagLike};

#[derive(Debug, Clone, Default)]
pub struct AudioMetadata {
    pub artist: Option<String>,
    pub album: Option<String>,
    pub title: Option<String>,
    pub track: Option<String>,
}

/// Extract ID3 audio metadata from an audio file if available.
pub fn extract_audio_tags(path: &Path) -> Option<AudioMetadata> {
    let tag = Tag::read_from_path(path).ok()?;

    let mut meta = AudioMetadata::default();

    if let Some(artist) = tag.artist() {
        if !artist.trim().is_empty() {
            meta.artist = Some(artist.trim().to_string());
        }
    }

    if let Some(album) = tag.album() {
        if !album.trim().is_empty() {
            meta.album = Some(album.trim().to_string());
        }
    }

    if let Some(title) = tag.title() {
        if !title.trim().is_empty() {
            meta.title = Some(title.trim().to_string());
        }
    }

    if let Some(track) = tag.track() {
        meta.track = Some(format!("{:02}", track));
    }

    Some(meta)
}
