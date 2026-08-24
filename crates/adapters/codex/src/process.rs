use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender as MpscSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::{CodexError, JsonRpcTransport, MAX_JSON_LINE, RawJsonRpc};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(windows)]
const OWNED_TREE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(1);
const READER_JOIN_TIMEOUT: Duration = Duration::from_secs(1);
const WRITER_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

pub struct ProcessTransport {
    child: Option<Child>,
    writer_tx: Option<MpscSender<WriterMessage>>,
    incoming: Receiver<Result<RawJsonRpc, CodexError>>,
    reader: Option<JoinHandle<()>>,
    reader_done: Receiver<()>,
    writer: Option<JoinHandle<()>>,
    shutdown_error: Option<String>,
}

struct WriterMessage {
    bytes: Vec<u8>,
    reply: MpscSender<Result<(), CodexError>>,
}

impl ProcessTransport {
    pub(crate) fn process_id(&self) -> u32 {
        self.child.as_ref().map(Child::id).unwrap_or_default()
    }

    pub fn spawn(executable: &Path) -> Result<Self, CodexError> {
        Self::spawn_with_codex_home(executable, None)
    }

    pub fn spawn_with_codex_home(
        executable: &Path,
        codex_home: Option<&Path>,
    ) -> Result<Self, CodexError> {
        let mut command = Command::new(executable);
        command
            .args([
                "app-server",
                "-c",
                "analytics.enabled=false",
                "--listen",
                "stdio://",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        configure_hidden_window(&mut command);
        if let Some(codex_home) = codex_home {
            command.env("CODEX_HOME", codex_home);
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().ok_or(CodexError::InvalidOutput)?;
        let stdout = child.stdout.take().ok_or(CodexError::InvalidOutput)?;
        let (writer_tx, writer_rx) = mpsc::channel::<WriterMessage>();
        let writer = thread::spawn(move || {
            let mut stdin = stdin;
            while let Ok(message) = writer_rx.recv() {
                let result = stdin
                    .write_all(&message.bytes)
                    .and_then(|_| stdin.flush())
                    .map_err(CodexError::from);
                let _ = message.reply.send(result);
            }
        });
        let (incoming_tx, incoming) = mpsc::channel();
        let (reader_done_tx, reader_done) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let response = read_json_rpc(&mut stdout);
                let terminal = response.is_err();
                if incoming_tx.send(response).is_err() || terminal {
                    break;
                }
            }
            let _ = reader_done_tx.send(());
        });
        Ok(Self {
            child: Some(child),
            writer_tx: Some(writer_tx),
            incoming,
            reader: Some(reader),
            reader_done,
            writer: Some(writer),
            shutdown_error: None,
        })
    }

    fn shutdown(&mut self) {
        self.writer_tx.take();
        let mut reader_finished = matches!(
            self.reader_done.try_recv(),
            Ok(()) | Err(TryRecvError::Disconnected)
        );
        if let Some(mut child) = self.child.take() {
            let process_id = child.id();
            let mut child_exited = wait_for_child(&mut child, GRACEFUL_SHUTDOWN_TIMEOUT);
            reader_finished |= matches!(
                self.reader_done.try_recv(),
                Ok(()) | Err(TryRecvError::Disconnected)
            );
            if !child_exited {
                if terminate_owned_process_tree(process_id).is_err() {
                    self.record_shutdown_error(CodexError::Io(std::io::Error::other(
                        "failed to terminate owned Codex process tree",
                    )));
                }
                let _ = child.kill();
                child_exited |= wait_for_child(&mut child, CHILD_REAP_TIMEOUT);
            }
            if child_exited {
                let _ = child.wait();
            }
        }
        if let Some(reader) = self.reader.take() {
            let reader_done =
                reader_finished || self.reader_done.recv_timeout(READER_JOIN_TIMEOUT).is_ok();
            if reader_done {
                let _ = reader.join();
            } else {
                self.record_shutdown_error(CodexError::Timeout);
            }
        }
        if let Some(writer) = self.writer.take() {
            let writer_deadline = Instant::now() + WRITER_JOIN_TIMEOUT;
            while Instant::now() < writer_deadline && !writer.is_finished() {
                thread::sleep(Duration::from_millis(10));
            }
            if writer.is_finished() {
                let _ = writer.join();
            } else {
                self.record_shutdown_error(CodexError::Io(std::io::Error::other(
                    "Codex stdin writer did not stop",
                )));
                // Dropping the JoinHandle detaches the writer thread.
            }
        }
    }

    fn record_shutdown_error(&mut self, error: CodexError) {
        if self.shutdown_error.is_none() {
            self.shutdown_error = Some(error.to_string());
        }
    }

    #[doc(hidden)]
    pub fn shutdown_error(&self) -> Option<String> {
        self.shutdown_error.clone()
    }
}

impl JsonRpcTransport for ProcessTransport {
    fn send_value(&mut self, value: &Value) -> Result<(), CodexError> {
        let mut bytes = serde_json::to_vec(value).map_err(|_| CodexError::MalformedJson)?;
        if bytes.len() > MAX_JSON_LINE {
            return Err(CodexError::OversizedLine);
        }
        bytes.push(b'\n');
        self.send_bytes(bytes, Instant::now() + Duration::from_secs(30))
    }

    fn send_value_until(&mut self, value: &Value, deadline: Instant) -> Result<(), CodexError> {
        let mut bytes = serde_json::to_vec(value).map_err(|_| CodexError::MalformedJson)?;
        if bytes.len() > MAX_JSON_LINE {
            return Err(CodexError::OversizedLine);
        }
        bytes.push(b'\n');
        self.send_bytes(bytes, deadline)
    }

    fn receive_value(&mut self) -> Result<RawJsonRpc, CodexError> {
        self.incoming.recv().map_err(|_| CodexError::EndOfStream)?
    }

    fn receive_value_until(&mut self, deadline: Instant) -> Result<RawJsonRpc, CodexError> {
        let now = Instant::now();
        if now >= deadline {
            self.shutdown();
            return Err(CodexError::AppServerRequestTimeout);
        }
        let remaining = deadline.duration_since(now);
        match self.incoming.recv_timeout(remaining) {
            Ok(response) => response,
            Err(RecvTimeoutError::Timeout) => {
                self.shutdown();
                Err(CodexError::AppServerRequestTimeout)
            }
            Err(RecvTimeoutError::Disconnected) => Err(CodexError::EndOfStream),
        }
    }
}

impl ProcessTransport {
    fn send_bytes(&mut self, bytes: Vec<u8>, deadline: Instant) -> Result<(), CodexError> {
        let now = Instant::now();
        if now >= deadline {
            self.shutdown();
            return Err(CodexError::AppServerRequestTimeout);
        }
        let sender = self.writer_tx.as_ref().ok_or(CodexError::EndOfStream)?;
        let (reply_tx, reply_rx) = mpsc::channel::<Result<(), CodexError>>();
        sender
            .send(WriterMessage {
                bytes,
                reply: reply_tx,
            })
            .map_err(|_| CodexError::EndOfStream)?;
        match reply_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                self.shutdown();
                Err(CodexError::AppServerRequestTimeout)
            }
            Err(RecvTimeoutError::Disconnected) => Err(CodexError::EndOfStream),
        }
    }
}

impl Drop for ProcessTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn read_json_rpc(reader: &mut impl Read) -> Result<RawJsonRpc, CodexError> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = reader.read(&mut byte)?;
        if read == 0 {
            if bytes.is_empty() {
                return Err(CodexError::EndOfStream);
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > MAX_JSON_LINE {
            return Err(CodexError::OversizedLine);
        }
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| CodexError::MalformedJson)?;
    Ok(RawJsonRpc { bytes, value })
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => return false,
        }
    }
}

#[cfg(windows)]
fn configure_hidden_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn configure_hidden_window(_command: &mut Command) {}

#[cfg(windows)]
fn terminate_owned_process_tree(process_id: u32) -> Result<(), ()> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut command = Command::new("taskkill.exe");
    command
        .args(["/PID", &process_id.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    let mut terminator = command.spawn().map_err(|_| ())?;
    if !wait_for_child(&mut terminator, OWNED_TREE_SHUTDOWN_TIMEOUT) {
        let _ = terminator.kill();
        return if wait_for_child(&mut terminator, CHILD_REAP_TIMEOUT) {
            let _ = terminator.wait();
            Ok(())
        } else {
            Err(())
        };
    }
    Ok(())
}

#[cfg(not(windows))]
fn terminate_owned_process_tree(_process_id: u32) -> Result<(), ()> {
    Ok(())
}
