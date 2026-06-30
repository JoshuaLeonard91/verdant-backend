use dashmap::DashMap;
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct BotGatewaySession {
    pub bot_id: i64,
    pub server_id: i64,
    pub connected_at_ms: i64,
}

#[derive(Debug, Default)]
pub struct BotGatewayManager {
    sessions: DashMap<u64, BotGatewaySession>,
}

impl BotGatewayManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn add_session(&self, conn_id: u64, bot_id: i64, server_id: i64) {
        self.sessions.insert(
            conn_id,
            BotGatewaySession {
                bot_id,
                server_id,
                connected_at_ms: chrono::Utc::now().timestamp_millis(),
            },
        );
    }

    pub fn remove_session(&self, conn_id: u64) -> Option<BotGatewaySession> {
        self.sessions.remove(&conn_id).map(|(_, session)| session)
    }

    pub fn is_bot_online(&self, bot_id: i64) -> bool {
        self.sessions.iter().any(|entry| entry.bot_id == bot_id)
    }

    pub fn online_bots_for_server(&self, server_id: i64) -> Vec<i64> {
        let mut bot_ids: Vec<i64> = self
            .sessions
            .iter()
            .filter(|entry| entry.server_id == server_id)
            .map(|entry| entry.bot_id)
            .collect();
        bot_ids.sort_unstable();
        bot_ids.dedup();
        bot_ids
    }

    pub fn presence_payload(&self, bot_id: i64, server_id: i64, status: &str) -> Value {
        json!({
            "botId": bot_id.to_string(),
            "serverId": server_id.to_string(),
            "status": status,
        })
    }
}
