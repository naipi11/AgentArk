use serde_json::{Value, json};

use crate::CodexError;

pub const MAX_JSON_LINE: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RawJsonRpc {
    pub bytes: Vec<u8>,
    pub value: Value,
}

pub trait JsonRpcTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError>;
    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError>;
}

pub struct ReadOnlyAppServerClient<'a, T: JsonRpcTransport> {
    transport: &'a mut T,
    next_id: u64,
}

impl<'a, T: JsonRpcTransport> ReadOnlyAppServerClient<'a, T> {
    pub fn new(transport: &'a mut T) -> Self {
        Self {
            transport,
            next_id: 1,
        }
    }

    pub fn initialize(&mut self) -> Result<RawJsonRpc, CodexError> {
        let response = self.request(
            "initialize",
            json!({
                "clientInfo": {
                    "name": "agentark",
                    "title": "AgentArk",
                    "version": "0.1.0"
                }
            }),
        )?;
        self.transport
            .send_value(&json!({"method":"initialized","params":{}}))?;
        Ok(response)
    }

    pub fn list_threads(&mut self, archived: bool) -> Result<Vec<RawJsonRpc>, CodexError> {
        let mut cursor = None;
        let mut responses = Vec::new();
        loop {
            let mut params = json!({
                "archived": archived,
                "sourceKinds": [
                    "cli", "vscode", "exec", "appServer", "subAgent", "subAgentReview",
                    "subAgentCompact", "subAgentThreadSpawn", "subAgentOther", "unknown"
                ],
                "useStateDbOnly": true,
                "limit": 100,
                "sortKey": "created_at",
                "sortDirection": "asc"
            });
            if let Some(cursor) = cursor.clone() {
                params["cursor"] = cursor;
            }
            let response = self.request("thread/list", params)?;
            let next_cursor = response
                .value
                .get("result")
                .and_then(|result| result.get("nextCursor"))
                .cloned()
                .filter(|value| !value.is_null());
            responses.push(response);
            match next_cursor {
                Some(value) => cursor = Some(value),
                None => break,
            }
        }
        Ok(responses)
    }

    pub fn read_thread(&mut self, thread_id: &str) -> Result<RawJsonRpc, CodexError> {
        self.request(
            "thread/read",
            json!({"threadId": thread_id, "includeTurns": true}),
        )
    }

    fn request(&mut self, method: &str, params: Value) -> Result<RawJsonRpc, CodexError> {
        let id = self.next_id;
        self.next_id += 1;
        self.transport.send_value(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))?;
        loop {
            let response = self.transport.receive_value()?;
            if response.value.get("id") == Some(&Value::from(id)) {
                if response.value.get("error").is_some() {
                    return Err(CodexError::Protocol);
                }
                return Ok(response);
            }
        }
    }
}
