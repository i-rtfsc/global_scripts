//! JSON-RPC 2.0 over stdio with **LSP-style framing** (`Content-Length` header +
//! UTF-8 JSON body), plus the **T2 one-shot transport** that spawns a plugin
//! process, sends it request(s), and reads framed responses until EOF.
//!
//! Spec: tmp/phase0-plugin-protocol.md §2.1 (framing), §2.2 (describe), §3.2
//! (complete), §5 (invoke / event). The matching Python side is `sdk/python`.
//!
//! Tiers: T2 (script) uses [`call_oneshot`] — one process per `gs` invocation
//! that may answer 1–2 requests (e.g. `describe` then `complete`) before its
//! stdin closes and it exits. T3 (resident) and T4 (wasm) reuse the framing and
//! message types but need a different transport (deferred).

use crate::manifest::CommandSpec;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

// ---- framing -------------------------------------------------------------

/// Write one framed JSON message: `Content-Length: N\r\n\r\n<body>` then flush.
pub fn write_message<W: Write>(w: &mut W, value: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(value)?;
    write!(w, "Content-Length: {}\r\n\r\n", body.len())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one framed JSON message. Returns `Ok(None)` at a clean EOF (no more
/// messages). Unknown headers are tolerated and ignored; only `Content-Length`
/// matters. A truncated frame surfaces as EOF (`None`) or an `InvalidData` error.
pub fn read_message<R: BufRead>(r: &mut R) -> io::Result<Option<Value>> {
    let mut content_length: Option<usize> = None;
    let mut saw_header = false;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            // EOF: clean if it lands on a message boundary, else a truncated frame.
            return if saw_header {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated header",
                ))
            } else {
                Ok(None)
            };
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // blank line ends the header block
        }
        saw_header = true;
        if let Some(v) = trimmed.strip_prefix("Content-Length:") {
            content_length = v.trim().parse().ok();
        }
        // any other header line is ignored
    }
    let len = content_length
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length"))?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ---- message construction & typed results --------------------------------

/// A JSON-RPC request: `{"jsonrpc":"2.0","id":<id>,"method":<m>,"params":<p>}`.
pub fn request(id: i64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// A parsed JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

/// A parsed JSON-RPC response (a message carrying an `id`).
#[derive(Debug, Clone)]
pub struct Response {
    pub id: Option<i64>,
    pub result: Option<Value>,
    pub error: Option<RpcError>,
}

/// Everything one transport exchange produced: id-bearing responses plus any
/// `event` notifications (progress/log/output) emitted along the way (§5.3).
#[derive(Debug, Default)]
pub struct Exchange {
    pub responses: Vec<Response>,
    pub events: Vec<Value>,
}

impl Exchange {
    /// The `result` of the response with this `id`, if it succeeded.
    pub fn result_for(&self, id: i64) -> Option<&Value> {
        self.responses
            .iter()
            .find(|r| r.id == Some(id))
            .and_then(|r| r.result.as_ref())
    }

    /// The error of the response with this `id`, if it failed.
    pub fn error_for(&self, id: i64) -> Option<&RpcError> {
        self.responses
            .iter()
            .find(|r| r.id == Some(id))
            .and_then(|r| r.error.as_ref())
    }
}

fn parse_response(msg: Value) -> Response {
    let id = msg.get("id").and_then(Value::as_i64);
    let result = msg.get("result").cloned();
    let error = msg.get("error").map(|e| RpcError {
        code: e.get("code").and_then(Value::as_i64).unwrap_or(0),
        message: e
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    });
    Response { id, result, error }
}

/// A `describe` result (§2.2). `commands` reuses [`CommandSpec`] — the runtime
/// tree is isomorphic to a manifest's, so the same type loads from both.
#[derive(Debug, Clone, Deserialize)]
pub struct DescribeResult {
    #[serde(default = "one")]
    pub protocol: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub commands: Vec<CommandSpec>,
}
fn one() -> u32 {
    1
}

/// Parse a `describe` result Value into [`DescribeResult`].
pub fn parse_describe(result: &Value) -> Result<DescribeResult, String> {
    serde_json::from_value(result.clone()).map_err(|e| e.to_string())
}

/// One completion candidate from a plugin's `complete` (§3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionValue {
    pub value: String,
    pub description: Option<String>,
}

/// Parse a `complete` result (§3.2) into `(values, ttl_seconds)`. Accepts both
/// the rich `{"values":[{value,description}], "ttl":N}` form and a bare/plain
/// string array element (`"emulator-5554"`), normalizing each to a value-object.
pub fn parse_complete(result: &Value) -> (Vec<CompletionValue>, Option<u64>) {
    let ttl = result.get("ttl").and_then(Value::as_u64);
    let mut out = Vec::new();
    let items = result
        .get("values")
        .and_then(Value::as_array)
        .or_else(|| result.as_array());
    if let Some(items) = items {
        for it in items {
            if let Some(s) = it.as_str() {
                out.push(CompletionValue {
                    value: s.to_string(),
                    description: None,
                });
            } else if let Some(v) = it.get("value").and_then(Value::as_str) {
                out.push(CompletionValue {
                    value: v.to_string(),
                    description: it
                        .get("description")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                });
            }
        }
    }
    (out, ttl)
}

// ---- T2 one-shot transport -----------------------------------------------

/// Spawn `program args…` as a one-shot plugin, write every `request` to its
/// stdin (then close stdin → the plugin's read loop hits EOF and exits after
/// responding), and read all framed responses + `event` notifications from its
/// stdout. `cwd` sets the working directory (usually the plugin dir).
///
/// `stderr_to_null`: completion should silence plugin logs (a Tab press must
/// not spew); invoke should inherit them (the user wants to see plugin output).
///
/// The child inherits the parent process env so the interpreter works; the
/// plugin's *authorized* env subset is delivered separately inside the `invoke`
/// params (§5.1), not via the process environment.
pub fn call_oneshot(
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    requests: &[Value],
    stderr_to_null: bool,
) -> io::Result<Exchange> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if stderr_to_null {
            Stdio::null()
        } else {
            Stdio::inherit()
        });
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd.spawn()?;

    // Write all requests, then drop stdin so the plugin sees EOF.
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "no child stdin"))?;
        for req in requests {
            write_message(&mut stdin, req)?;
        }
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "no child stdout"))?;
    let mut reader = BufReader::new(stdout);
    let mut ex = Exchange::default();
    while let Some(msg) = read_message(&mut reader)? {
        if msg.get("id").is_some() {
            ex.responses.push(parse_response(msg));
        } else if msg.get("method").and_then(Value::as_str) == Some("event") {
            if let Some(p) = msg.get("params") {
                ex.events.push(p.clone());
            }
        }
        // other notifications are ignored
    }
    let _ = child.wait();
    Ok(ex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(body: &str) -> Vec<u8> {
        format!("Content-Length: {}\r\n\r\n{}", body.len(), body).into_bytes()
    }

    #[test]
    fn framing_round_trips_multiple_messages() {
        let mut buf = Vec::new();
        write_message(&mut buf, &json!({"id": 1, "method": "describe"})).unwrap();
        write_message(&mut buf, &json!({"id": 2, "result": {"ok": true}})).unwrap();

        let mut cur = Cursor::new(buf);
        let a = read_message(&mut cur).unwrap().unwrap();
        let b = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(a["id"], 1);
        assert_eq!(a["method"], "describe");
        assert_eq!(b["result"]["ok"], true);
        // clean EOF after the last message
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn reader_tolerates_extra_headers_and_body_with_newlines() {
        let body = r#"{"text":"line1\nline2","id":7}"#;
        let mut raw = format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body.as_bytes());
        let mut cur = Cursor::new(raw);
        let v = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(v["id"], 7);
        assert_eq!(v["text"], "line1\nline2");
    }

    #[test]
    fn parse_complete_handles_objects_strings_and_ttl() {
        let rich = json!({
            "values": [
                {"value": "emulator-5554", "description": "Pixel_7"},
                {"value": "emulator-5556", "description": ""},
                "bare-string"
            ],
            "ttl": 5
        });
        let (vals, ttl) = parse_complete(&rich);
        assert_eq!(ttl, Some(5));
        assert_eq!(vals[0].value, "emulator-5554");
        assert_eq!(vals[0].description.as_deref(), Some("Pixel_7"));
        assert_eq!(vals[1].description, None, "empty description → None");
        assert_eq!(vals[2].value, "bare-string");
        // a plain top-level array also works
        let (vals2, ttl2) = parse_complete(&json!(["a", "b"]));
        assert_eq!(vals2.len(), 2);
        assert_eq!(ttl2, None);
    }

    #[test]
    fn parse_describe_reuses_command_spec() {
        let result = json!({
            "protocol": 1,
            "name": "android",
            "commands": [{
                "name": "device.logcat",
                "summary": {"zh": "查看设备日志", "en": "View device logcat"},
                "args": [{
                    "name": "level", "type": "enum", "flag": "--level",
                    "complete": {"kind": "enum", "values": ["V", "E"]}
                }]
            }]
        });
        let d = parse_describe(&result).unwrap();
        assert_eq!(d.name, "android");
        let c = &d.commands[0];
        assert_eq!(c.name, "device.logcat");
        assert_eq!(c.group(), "device");
        let lvl = c.arg("level").unwrap();
        assert_eq!(lvl.complete.kind, crate::manifest::CompleteKind::Enum);
        assert_eq!(lvl.complete.values, ["V", "E"]);
    }

    // The process transport: a `sh` mock that ignores stdin and emits framed
    // bytes verbatim via `printf %s`. Unix-only (the gs targets are POSIX here).
    #[cfg(unix)]
    fn sh_emit(payload: Vec<u8>) -> Vec<String> {
        // sh -c 'printf %s "$1"' sh <payload>
        let s = String::from_utf8(payload).unwrap();
        vec!["-c".into(), "printf %s \"$1\"".into(), "sh".into(), s]
    }

    #[cfg(unix)]
    #[test]
    fn oneshot_reads_a_framed_response() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"pong":true}}"#;
        let ex = call_oneshot(
            "sh",
            &sh_emit(frame(body)),
            None,
            &[request(1, "ping", json!({}))],
            true,
        )
        .unwrap();
        assert_eq!(ex.responses.len(), 1);
        assert_eq!(ex.result_for(1).unwrap()["pong"], true);
        assert!(ex.error_for(1).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn oneshot_collects_event_notifications_then_response() {
        let mut payload =
            frame(r#"{"jsonrpc":"2.0","method":"event","params":{"type":"log","message":"hi"}}"#);
        payload.extend(frame(
            r#"{"jsonrpc":"2.0","id":1,"result":{"exit_code":0}}"#,
        ));
        let ex = call_oneshot(
            "sh",
            &sh_emit(payload),
            None,
            &[request(1, "invoke", json!({}))],
            true,
        )
        .unwrap();
        assert_eq!(ex.events.len(), 1, "one event notification collected");
        assert_eq!(ex.events[0]["type"], "log");
        assert_eq!(ex.result_for(1).unwrap()["exit_code"], 0);
    }
}
