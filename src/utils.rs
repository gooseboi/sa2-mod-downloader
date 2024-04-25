use sha2::{Digest as _, Sha256};

#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn size_str(size: u64) -> String {
    const BYTE_SIZE: u64 = 1024;

    if size < BYTE_SIZE {
        format!("{size} B")
    } else if size < BYTE_SIZE.pow(2) {
        let size = (size as f64) / (BYTE_SIZE as f64).powi(1);
        format!("{size:.1} KiB")
    } else if size < BYTE_SIZE.pow(3) {
        let size = (size as f64) / (BYTE_SIZE as f64).powi(2);
        format!("{size:.1} MiB")
    } else if size < BYTE_SIZE.pow(4) {
        let size = (size as f64) / (BYTE_SIZE as f64).powi(3);
        format!("{size:.1} GiB")
    } else {
        "You really shouldn't be serving files that big with this tool...".to_owned()
    }
}

#[must_use]
pub fn sha256_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let computed_hash = hasher.finalize();
    format!("{computed_hash:016x}")
}
