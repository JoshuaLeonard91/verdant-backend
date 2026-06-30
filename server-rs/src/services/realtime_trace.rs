pub fn enabled() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }

    std::env::var("VERDANT_REALTIME_TRACE")
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

#[macro_export]
macro_rules! realtime_trace {
    ($($arg:tt)+) => {
        if $crate::services::realtime_trace::enabled() {
            tracing::info!($($arg)+);
        }
    };
}
