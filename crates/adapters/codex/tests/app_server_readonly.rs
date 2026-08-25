use std::collections::VecDeque;
use std::time::{Duration, Instant};

use agentark_adapter_codex::{
    AGENTARK_APP_SERVER_CLIENT_VERSION, CodexError, JsonRpcTransport, RawJsonRpc,
    ReadOnlyAppServerClient,
};
use serde_json::{Value, json};

struct ScriptedTransport {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Value>,
}

impl ScriptedTransport {
    fn new(lines: &[&str]) -> Self {
        Self {
            incoming: lines.iter().map(|line| line.as_bytes().to_vec()).collect(),
            sent: Vec::new(),
        }
    }
}

impl JsonRpcTransport for ScriptedTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError> {
        self.sent.push(value.clone());
        Ok(())
    }

    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError> {
        let bytes = self.incoming.pop_front().ok_or(CodexError::EndOfStream)?;
        let value = serde_json::from_slice(&bytes).map_err(|_| CodexError::MalformedJson)?;
        Ok(RawJsonRpc { bytes, value })
    }
}

struct NotificationTransport {
    sent: Vec<Value>,
    notifications: usize,
}

impl JsonRpcTransport for NotificationTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError> {
        self.sent.push(value.clone());
        Ok(())
    }

    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError> {
        self.notifications += 1;
        let value = json!({
            "jsonrpc": "2.0",
            "method": "thread/status/changed",
            "params": {"sequence": self.notifications}
        });
        Ok(RawJsonRpc {
            bytes: serde_json::to_vec(&value).unwrap(),
            value,
        })
    }
}

#[test]
fn client_uses_only_read_methods_and_preserves_raw_responses() {
    let mut transport = ScriptedTransport::new(&[
        r#"{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"version":"0.146.0"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"data":[{"id":"thr_active"}],"nextCursor":null}}"#,
        r#"{"jsonrpc":"2.0","id":3,"result":{"data":[{"id":"thr_archived"}],"nextCursor":null}}"#,
        r#"{"jsonrpc":"2.0","id":4,"result":{"thread":{"id":"thr_active","turns":[]}}}"#,
    ]);
    let mut client = ReadOnlyAppServerClient::new(&mut transport);
    client.initialize().unwrap();
    let active = client.list_threads(false).unwrap();
    let archived = client.list_threads(true).unwrap();
    let read = client.read_thread("thr_active").unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(archived.len(), 1);
    assert_eq!(
        read.bytes,
        br#"{"jsonrpc":"2.0","id":4,"result":{"thread":{"id":"thr_active","turns":[]}}}"#
    );

    let methods = transport
        .sent
        .iter()
        .filter_map(|value| value.get("method").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        [
            "initialize",
            "initialized",
            "thread/list",
            "thread/list",
            "thread/read"
        ]
    );
    let sent_json = transport
        .sent
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>();
    assert!(
        sent_json
            .iter()
            .all(|json| !json.contains("experimentalApi"))
    );
    assert!(sent_json.iter().all(|json| {
        ![
            "thread/start",
            "thread/resume",
            "thread/archive",
            "thread/delete",
            "thread/metadata/update",
            "turn/start",
            "command/exec",
        ]
        .iter()
        .any(|method| json.contains(method))
    }));
    let list_params = &transport.sent[2]["params"];
    assert_eq!(list_params["useStateDbOnly"], json!(true));
    assert_eq!(list_params["limit"], json!(100));
    assert_eq!(list_params["sortKey"], json!("created_at"));
    assert_eq!(list_params["sortDirection"], json!("asc"));
    assert_eq!(AGENTARK_APP_SERVER_CLIENT_VERSION, "0.6.2");
    assert_eq!(
        transport.sent[0]["params"]["clientInfo"]["version"],
        "0.6.2"
    );
}

#[test]
fn notifications_cannot_extend_the_original_request_deadline() {
    let mut transport = NotificationTransport {
        sent: Vec::new(),
        notifications: 0,
    };
    let started = Instant::now();
    let mut client =
        ReadOnlyAppServerClient::with_request_timeout(&mut transport, Duration::from_millis(25));

    let error = client.initialize().unwrap_err();

    assert!(matches!(error, CodexError::AppServerRequestTimeout));
    assert!(started.elapsed() >= Duration::from_millis(10));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(transport.notifications > 1);
    assert_eq!(transport.sent.len(), 1);
    assert_eq!(transport.sent[0]["method"], "initialize");
}
