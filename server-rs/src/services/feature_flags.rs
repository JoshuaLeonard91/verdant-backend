use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory feature flag service.
/// Flags can be set at runtime via admin endpoints.
pub struct FeatureFlagService {
    flags: RwLock<HashMap<String, bool>>,
}

impl FeatureFlagService {
    pub fn new() -> Self {
        let mut defaults = HashMap::new();
        // Default feature flags — keep in sync with TS server
        defaults.insert("file_sharing".to_string(), true);
        defaults.insert("image_uploads".to_string(), true);
        defaults.insert("voice_chat".to_string(), true);
        defaults.insert("custom_emoji".to_string(), true);
        defaults.insert("lazy_emoji_loading".to_string(), true);
        defaults.insert("invite_codes".to_string(), false);

        Self {
            flags: RwLock::new(defaults),
        }
    }

    /// Get all flags as a HashMap (for READY payload).
    pub fn get_all(&self) -> HashMap<String, bool> {
        self.flags.read().unwrap().clone()
    }

    /// Resolve a single flag for a user. Currently user-agnostic.
    pub fn resolve(&self, key: &str, _user_id: i64) -> bool {
        self.flags
            .read()
            .unwrap()
            .get(key)
            .copied()
            .unwrap_or(false)
    }

    /// Set a flag value at runtime.
    pub fn set(&self, key: String, value: bool) {
        self.flags.write().unwrap().insert(key, value);
    }
}
