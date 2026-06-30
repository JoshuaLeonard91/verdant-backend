use verdant_server::federation::storage::{INBOUND_EVENT_ACCEPT_SQL, INBOUND_EVENT_INSERT_SQL};

#[test]
fn inbound_event_storage_reserves_then_accepts_after_runtime_application() {
    assert!(INBOUND_EVENT_INSERT_SQL.contains("'received'"));
    assert!(!INBOUND_EVENT_INSERT_SQL.contains("'accepted'"));
    assert!(INBOUND_EVENT_ACCEPT_SQL.contains("status = 'accepted'"));
    assert!(INBOUND_EVENT_ACCEPT_SQL.contains("accepted_at_ms = $3"));
}
