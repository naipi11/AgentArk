use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::CodexError;

pub const MAX_JSON_LINE: usize = 16 * 1024 * 1024;
pub const AGENTARK_APP_SERVER_CLIENT_VERSION: &str = "0.6.0";
pub(crate) const APP_SERVER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct RawJsonRpc {
    pub bytes: Vec<u8>,
    pub value: Value,
}

pub trait JsonRpcTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError>;
    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError>;

    fn send_value_until(&mut self, value: &Value, deadline: Instant) -> Result<(), CodexError> {
        if Instant::now() >= deadline {
            return Err(CodexError::AppServerRequestTimeout);
        }
        self.send_value(value)
    }

    fn receive_value_until(&mut self, deadline: Instant) -> Result<RawJsonRpc, CodexError> {
        if Instant::now() >= deadline {
            return Err(CodexError::AppServerRequestTimeout);
        }
        self.receive_value()
    }
}

pub struct ReadOnlyAppServerClient<'a, T: JsonRpcTransport> {
    transport: &'a mut T,
    next_id: u64,
    request_timeout: Duration,
}

impl<'a, T: JsonRpcTransport> ReadOnlyAppServerClient<'a, T> {
    pub fn new(transport: &'a mut T) -> Self {
        Self {
            transport,
            next_id: 1,
            request_timeout: APP_SERVER_REQUEST_TIMEOUT,
        }
    }

    #[doc(hidden)]
    pub fn with_request_timeout(transport: &'a mut T, request_timeout: Duration) -> Self {
        Self {
            transport,
            next_id: 1,
            request_timeout,
        }
    }

    pub fn initialize(&mut self) -> Result<RawJsonRpc, CodexError> {
        let deadline = Instant::now() + self.request_timeout;
        let response = self.request(
            "initialize",
            json!({
                "clientInfo": {
                    "name": "agentark",
                    "title": "AgentArk",
                    "version": AGENTARK_APP_SERVER_CLIENT_VERSION
                }
            }),
            deadline,
        )?;
        self.transport
            .send_value_until(&json!({"method":"initialized","params":{}}), deadline)?;
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
            let deadline = Instant::now() + self.request_timeout;
            let response = self.request("thread/list", params, deadline)?;
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
        let deadline = Instant::now() + self.request_timeout;
        self.request(
            "thread/read",
            json!({"threadId": thread_id, "includeTurns": true}),
            deadline,
        )
    }

    fn request(
        &mut self,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Result<RawJsonRpc, CodexError> {
        let id = self.next_id;
        self.next_id += 1;
        self.transport.send_value_until(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params
            }),
            deadline,
        )?;
        let response = receive_response_until(self.transport, id, deadline)?;
        if response.value.get("error").is_some() {
            return Err(CodexError::Protocol);
        }
        Ok(response)
    }
}

pub(crate) fn receive_response_until<T: JsonRpcTransport>(
    transport: &mut T,
    id: u64,
    deadline: Instant,
) -> Result<RawJsonRpc, CodexError> {
    loop {
        let response = transport.receive_value_until(deadline)?;
        if response.value.get("id") == Some(&Value::from(id)) {
            return Ok(response);
        }
    }
}
