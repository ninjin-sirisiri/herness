//! Shared still-image header validation for assessment evidence.
//!
//! Only PNG and JPEG caller-provided bytes are accepted. The parser reads the
//! dimensions from the header without decoding pixel data; providers still
//! validate the actual image content. Rejecting malformed or animated inputs
//! before send prevents a damaged image from being mistaken for evidence.

/// Still-image format accepted by an assessment adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StillImageFormat {
    /// Portable Network Graphics.
    Png,
    /// Joint Photographic Experts Group.
    Jpeg,
}

impl StillImageFormat {
    /// Maps an image media type to a supported still-image format.
    pub(crate) fn from_media_type(media_type: &str) -> Option<Self> {
        match media_type {
            "image/png" => Some(Self::Png),
            "image/jpeg" => Some(Self::Jpeg),
            _ => None,
        }
    }

    /// Reads the image dimensions without decoding pixel data.
    pub(crate) fn dimensions(self, bytes: &[u8]) -> Option<(u32, u32)> {
        match self {
            Self::Png => png_dimensions(bytes),
            Self::Jpeg => jpeg_dimensions(bytes),
        }
    }
}

/// Reads PNG dimensions and rejects animated PNGs, truncated files, and files
/// that do not contain both image data and an end marker.
fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if bytes.get(..8)? != SIGNATURE.as_slice() {
        return None;
    }
    if bytes.get(8..12)? != 13_u32.to_be_bytes().as_slice() {
        return None;
    }
    if bytes.get(12..16)? != b"IHDR".as_slice() {
        return None;
    }
    let width = u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?);
    let height = u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?);

    let mut offset = 8_usize;
    let mut saw_image_data = false;
    let mut saw_end = false;
    while offset.saturating_add(12) <= bytes.len() {
        let length = u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize;
        let kind = bytes.get(offset + 4..offset + 8)?;
        if kind == b"acTL".as_slice() {
            // Animated PNGs are not still images.
            return None;
        }
        if kind == b"IDAT".as_slice() {
            saw_image_data = true;
        }
        if kind == b"IEND".as_slice() {
            saw_end = true;
            break;
        }
        offset = offset.checked_add(12)?.checked_add(length)?;
        if offset > bytes.len() {
            return None;
        }
    }
    if !saw_image_data || !saw_end {
        return None;
    }
    Some((width, height))
}

/// Reads JPEG dimensions from the first start-of-frame marker.
fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return None;
    }
    let mut offset = 2_usize;
    while offset.saturating_add(4) <= bytes.len() {
        if bytes[offset] != 0xFF {
            return None;
        }
        let mut marker = bytes[offset + 1];
        offset += 2;
        while marker == 0xFF {
            marker = *bytes.get(offset)?;
            offset += 1;
        }
        if marker == 0xD8 || marker == 0xD9 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            continue;
        }
        if marker == 0xDA {
            break;
        }
        let length = u16::from_be_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]) as usize;
        if length < 2 || offset.saturating_add(length) > bytes.len() {
            return None;
        }
        if matches!(
            marker,
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
        ) {
            if length < 7 {
                return None;
            }
            let height =
                u16::from_be_bytes([*bytes.get(offset + 3)?, *bytes.get(offset + 4)?]) as u32;
            let width =
                u16::from_be_bytes([*bytes.get(offset + 5)?, *bytes.get(offset + 6)?]) as u32;
            return Some((width, height));
        }
        offset = offset.saturating_add(length);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_fixture(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let mut chunk = |kind: &[u8; 4], data: &[u8]| {
            bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
            bytes.extend_from_slice(kind);
            bytes.extend_from_slice(data);
            bytes.extend_from_slice(&[0, 0, 0, 0]);
        };
        let mut header = Vec::new();
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&[8, 2, 0, 0, 0]);
        chunk(b"IHDR", &header);
        chunk(b"IDAT", &[0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
        chunk(b"IEND", &[]);
        bytes
    }

    fn jpeg_fixture(width: u16, height: u16) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xD8];
        bytes.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        bytes.extend_from_slice(b"JFIF\0");
        bytes.extend_from_slice(&[1, 1, 0, 0, 1, 0, 1, 0, 0]);
        bytes.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01]);
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        bytes
    }

    #[test]
    fn still_image_dimensions_are_read_from_png_and_jpeg_headers() {
        assert_eq!(
            StillImageFormat::Png.dimensions(&png_fixture(640, 480)),
            Some((640, 480))
        );
        assert_eq!(
            StillImageFormat::Jpeg.dimensions(&jpeg_fixture(320, 200)),
            Some((320, 200))
        );
        assert_eq!(StillImageFormat::from_media_type("image/webp"), None);
    }

    #[test]
    fn animated_and_truncated_pngs_are_rejected() {
        let mut animated = png_fixture(280, 280);
        // Insert an acTL chunk immediately after IHDR.
        let mut rebuilt = animated.drain(..33).collect::<Vec<_>>();
        rebuilt.extend_from_slice(&[0, 0, 0, 8]);
        rebuilt.extend_from_slice(b"acTL");
        rebuilt.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
        rebuilt.extend_from_slice(&[0, 0, 0, 0]);
        rebuilt.extend_from_slice(&animated);
        assert_eq!(StillImageFormat::Png.dimensions(&rebuilt), None);

        let truncated = png_fixture(280, 280);
        assert_eq!(StillImageFormat::Png.dimensions(&truncated[..24]), None);
    }
}
