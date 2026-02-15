use crate::config::{InterfaceClass, TimeoutProfile};

pub fn classify_path(path: &str) -> InterfaceClass {
    if path.starts_with("/v2/admin") {
        InterfaceClass::Control
    } else if path.starts_with("/dav") {
        InterfaceClass::Metadata
    } else if path.starts_with("/d") || path.starts_with("/p") {
        InterfaceClass::LargeStream
    } else {
        InterfaceClass::SmallTransfer
    }
}

pub fn default_profile(path: &str) -> TimeoutProfile {
    classify_path(path).profile()
}

#[cfg(test)]
mod tests {
    use crate::config::InterfaceClass;

    use super::{classify_path, default_profile};

    #[test]
    fn classify_known_paths() {
        assert!(matches!(
            classify_path("/v2/admin/ping"),
            InterfaceClass::Control
        ));
        assert!(matches!(
            classify_path("/dav/abc"),
            InterfaceClass::Metadata
        ));
        assert!(matches!(
            classify_path("/d/file"),
            InterfaceClass::LargeStream
        ));
        assert!(matches!(
            classify_path("/p/file"),
            InterfaceClass::LargeStream
        ));
        assert!(matches!(
            classify_path("/misc"),
            InterfaceClass::SmallTransfer
        ));
    }

    #[test]
    fn total_timeout_for_large_stream_is_disabled() {
        let p = default_profile("/d/x");
        assert_eq!(p.total_ms, 0);
    }
}
