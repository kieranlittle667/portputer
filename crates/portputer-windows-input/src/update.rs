//! Secure package updating is added with the separate installer.
pub fn stage(_: &str, _: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("Install the separate secure-input package to update this helper.".into())
}
pub fn apply_staged() -> Result<(), Box<dyn std::error::Error>> {
    Err("Secure-input package update unavailable.".into())
}
