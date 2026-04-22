//! Filtering proxy for a rootless docker socket.
//!
//! Accepts connections on a unix socket, parses each HTTP request,
//! applies an allowlist policy, and forwards accepted requests to the
//! real rootless docker daemon. Container-create requests are validated
//! (no host namespaces, no privileged, mounts only under cwd, …) and
//! tagged with a `boxx.sandbox=<id>` label so that mutations are
//! restricted to containers this sandbox itself created.
//!
//! The proxy is single-request-per-connection: it writes `Connection:
//! close` and does not handle pipelining or keep-alive. Exec and attach
//! are denied outright, so we never need to implement HTTP hijacking.

use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use serde_json::Value;

const MAX_HEADERS: usize = 96;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CREATE_BODY: usize = 1024 * 1024;
const PIPE_BUF: usize = 16 * 1024;

/// Shown verbatim (via the daemon error envelope) to anything that
/// hits an attach path — `docker run` without `-d`, `docker attach`,
/// `docker start -a`. Written so an agent reading stderr can act on it.
const ATTACH_HINT: &str =
    "foreground attach is blocked. run detached and read output separately: \
     `docker run -d IMAGE CMD` (capture the id), then \
     `docker wait <id>` + `docker logs <id>`";

/// Analogous hint for `docker exec` / `docker attach <id>`.
const EXEC_HINT: &str =
    "exec is blocked. start a fresh container with the command you want \
     (`docker run -d IMAGE CMD`), or bake it into a new image";

/// Configuration for the proxy.
pub struct Options {
    /// Where the proxy listens (on the host filesystem; bind-mounted
    /// into the sandbox by the caller).
    pub proxy_socket: PathBuf,
    /// The real rootless docker daemon socket on the host.
    pub backend_socket: PathBuf,
    /// Label value used to scope created resources. Sandboxes with the
    /// same id share containers; conventionally this is the canonical
    /// cwd, so sandboxes in the same directory share state.
    pub sandbox_id: String,
    /// Canonicalised cwd — the only host path a container is allowed
    /// to bind-mount from.
    pub cwd: PathBuf,
}

struct State {
    backend_socket: PathBuf,
    sandbox_id: String,
    cwd: PathBuf,
}

/// Bind the listener and spawn the accept loop. Returns once the
/// socket file exists. Worker threads live until process exit.
pub fn spawn(opts: Options) -> io::Result<()> {
    let _ = std::fs::remove_file(&opts.proxy_socket);
    let listener = UnixListener::bind(&opts.proxy_socket)?;
    std::fs::set_permissions(&opts.proxy_socket, std::fs::Permissions::from_mode(0o600))?;

    let state = Arc::new(State {
        backend_socket: opts.backend_socket,
        sandbox_id: opts.sandbox_id,
        cwd: opts.cwd,
    });

    thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = state.clone();
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, &state) {
                            eprintln!("boxx: docker proxy: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("boxx: docker proxy accept: {e}");
                    return;
                }
            }
        }
    });

    Ok(())
}

// ---- request reading ----------------------------------------------

struct Request {
    method: String,
    // Raw request-target as received — passed through to the backend.
    raw_target: String,
    // Normalised path (no `/vX.Y` prefix, no query string).
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_request(stream: &mut UnixStream) -> io::Result<Request> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof before headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    };

    let mut slots = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut slots);
    let status = req
        .parse(&buf[..header_end])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parse: {e}")))?;
    if !status.is_complete() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete headers",
        ));
    }

    let method = req.method.unwrap_or("").to_string();
    let raw_target = req.path.unwrap_or("").to_string();
    let (path_no_query, _) = split_query(strip_api_version(&raw_target));
    let path = path_no_query.to_string();

    let mut headers = Vec::with_capacity(req.headers.len());
    let mut content_length: usize = 0;
    let mut chunked = false;
    let mut expect_100 = false;
    for h in req.headers.iter() {
        let name = h.name.to_string();
        let value = String::from_utf8_lossy(h.value).into_owned();
        let ln = name.to_ascii_lowercase();
        if ln == "content-length" {
            content_length = value.trim().parse().unwrap_or(0);
        } else if ln == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        } else if ln == "expect" && value.eq_ignore_ascii_case("100-continue") {
            expect_100 = true;
        }
        headers.push((name, value));
    }

    if chunked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunked request bodies not supported",
        ));
    }
    if content_length > MAX_CREATE_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }

    if expect_100 && content_length > 0 {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }

    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(&buf[header_end..]);
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof before body",
            ));
        }
        body.extend_from_slice(&tmp[..n]);
    }
    if body.len() > content_length {
        body.truncate(content_length);
    }

    Ok(Request {
        method,
        raw_target,
        path,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn strip_api_version(target: &str) -> &str {
    let Some(rest) = target.strip_prefix("/v") else {
        return target;
    };
    let end = rest
        .bytes()
        .position(|b| !(b.is_ascii_digit() || b == b'.'))
        .unwrap_or(rest.len());
    let (version, tail) = rest.split_at(end);
    if version.is_empty() || !tail.starts_with('/') {
        return target;
    }
    tail
}

fn split_query(path: &str) -> (&str, &str) {
    match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    }
}

// ---- policy -------------------------------------------------------

enum Decision {
    Forward,
    /// Forward after replacing the request body.
    ForwardWithBody(Vec<u8>),
    Deny {
        status: u16,
        message: String,
    },
}

fn deny(status: u16, msg: impl Into<String>) -> Decision {
    Decision::Deny {
        status,
        message: msg.into(),
    }
}

fn foreign() -> Decision {
    deny(403, "container is not in this sandbox")
}

fn decide(req: &Request, state: &State) -> Decision {
    let method = req.method.as_str();
    let path = req.path.as_str();

    match (method, path) {
        ("GET" | "HEAD", "/_ping") => Decision::Forward,
        ("GET", "/version") => Decision::Forward,
        ("GET", "/info") => Decision::Forward,
        ("GET", "/events") => Decision::Forward,
        ("GET", "/containers/json") => Decision::Forward,
        ("GET", "/images/json") => Decision::Forward,
        ("GET", "/images/search") => Decision::Forward,
        ("POST", "/images/create") => Decision::Forward,
        ("GET", "/images/get") => Decision::Forward,
        ("POST", "/images/load") => Decision::Forward,
        ("POST", "/containers/create") => decide_create(req, state),
        ("POST", "/containers/prune") => deny(403, "prune blocked"),
        ("POST", "/images/prune") => deny(403, "prune blocked"),
        _ => {
            if let Some(rest) = path.strip_prefix("/containers/") {
                decide_container(method, rest, state)
            } else if let Some(rest) = path.strip_prefix("/images/") {
                decide_image(method, rest)
            } else {
                deny(403, format!("endpoint {method} {path} blocked"))
            }
        }
    }
}

fn decide_container(method: &str, rest: &str, state: &State) -> Decision {
    let (id, action) = rest.split_once('/').unwrap_or((rest, ""));

    let gate = |d: Decision| -> Decision {
        if is_in_sandbox(state, id) {
            d
        } else {
            foreign()
        }
    };

    match (method, action) {
        ("POST", "attach") => deny(403, ATTACH_HINT),
        ("POST", "exec") => deny(403, EXEC_HINT),
        ("POST", "archive") | ("PUT", "archive") => deny(403, "archive write blocked"),
        ("GET", "json" | "logs" | "stats" | "top" | "changes" | "archive")
        | ("HEAD", "archive") => gate(Decision::Forward),
        ("DELETE", "") => gate(Decision::Forward),
        (
            "POST",
            "start" | "stop" | "kill" | "restart" | "wait" | "pause" | "unpause" | "rename"
            | "resize" | "update",
        ) => gate(Decision::Forward),
        _ => deny(403, format!("container endpoint /{action} blocked")),
    }
}

fn decide_image(method: &str, rest: &str) -> Decision {
    match method {
        "GET" | "HEAD" => Decision::Forward,
        "DELETE" => Decision::Forward,
        "POST" => {
            // `/{name}/tag` is the only mutating POST we allow here;
            // pull/load/create live at the top-level routes above.
            if rest.ends_with("/tag") || rest.contains("/tag?") {
                Decision::Forward
            } else {
                deny(403, "image mutation blocked")
            }
        }
        _ => deny(405, "method not allowed"),
    }
}

/// Authorise an operation on container `id` by asking the backend for
/// its labels and comparing the `boxx.sandbox` label against our own.
/// Containers missing the label — including any created outside boxx —
/// are treated as foreign and denied.
fn is_in_sandbox(state: &State, id: &str) -> bool {
    match fetch_sandbox_label(&state.backend_socket, id) {
        Ok(Some(label)) => label == state.sandbox_id,
        Ok(None) => false,
        Err(e) => {
            eprintln!("boxx: docker label lookup failed for {id}: {e}");
            false
        }
    }
}

fn fetch_sandbox_label(backend: &Path, id: &str) -> io::Result<Option<String>> {
    if !is_safe_container_ref(id) {
        return Ok(None);
    }
    let mut conn = UnixStream::connect(backend)?;
    write!(
        conn,
        "GET /containers/{id}/json HTTP/1.1\r\n\
         Host: docker\r\n\
         Connection: close\r\n\r\n"
    )?;
    conn.flush()?;
    let (status, _head, body) = read_response(&mut conn)?;
    if status != 200 {
        return Ok(None);
    }
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return Ok(None);
    };
    Ok(v.pointer("/Config/Labels/boxx.sandbox")
        .and_then(Value::as_str)
        .map(str::to_string))
}

/// Names/ids we're willing to substitute into an inspect URL. Docker's
/// own grammar is narrower than this but this is already strict enough
/// that the request can't escape the `/containers/{id}/json` template.
fn is_safe_container_ref(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    let mut has_alnum = false;
    for b in id.bytes() {
        if b.is_ascii_alphanumeric() {
            has_alnum = true;
        } else if !matches!(b, b'-' | b'_' | b'.') {
            return false;
        }
    }
    has_alnum
}

// ---- container create validation -----------------------------------

fn decide_create(req: &Request, state: &State) -> Decision {
    let mut value: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return deny(400, "create body is not valid JSON"),
    };
    let Some(obj) = value.as_object_mut() else {
        return deny(400, "create body must be a JSON object");
    };

    if let Some(hc) = obj.get("HostConfig")
        && let Err(msg) = validate_host_config(hc, &state.cwd)
    {
        return deny(403, format!("HostConfig rejected: {msg}"));
    }

    // `docker run` without `-d` sets AttachStdout/AttachStderr (and
    // AttachStdin for -i) on the create body. The daemon will accept
    // that and the client will try to attach — which we block. Reject
    // early so we don't leave an orphan container behind, and so the
    // error message points at the fix.
    if wants_foreground_attach(obj) {
        return deny(403, ATTACH_HINT);
    }

    inject_label(obj, &state.sandbox_id);

    match serde_json::to_vec(&value) {
        Ok(new_body) => Decision::ForwardWithBody(new_body),
        Err(_) => deny(500, "failed to serialise rewritten create body"),
    }
}

fn wants_foreground_attach(obj: &serde_json::Map<String, Value>) -> bool {
    ["AttachStdin", "AttachStdout", "AttachStderr", "OpenStdin", "Tty"]
        .iter()
        .any(|k| obj.get(*k).and_then(Value::as_bool).unwrap_or(false))
}

fn inject_label(obj: &mut serde_json::Map<String, Value>, sandbox_id: &str) {
    let labels = obj
        .entry("Labels")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(map) = labels.as_object_mut() {
        map.insert(
            "boxx.sandbox".to_string(),
            Value::String(sandbox_id.to_string()),
        );
    } else {
        // Labels was present but not an object — replace it.
        let mut m = serde_json::Map::new();
        m.insert(
            "boxx.sandbox".to_string(),
            Value::String(sandbox_id.to_string()),
        );
        obj.insert("Labels".to_string(), Value::Object(m));
    }
}

fn validate_host_config(hc: &Value, cwd: &Path) -> Result<(), String> {
    let Some(obj) = hc.as_object() else {
        return Err("HostConfig must be an object".into());
    };

    if obj
        .get("Privileged")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("Privileged=true".into());
    }

    for field in [
        "PidMode",
        "IpcMode",
        "UtsMode",
        "UsernsMode",
        "CgroupnsMode",
    ] {
        if let Some(v) = obj.get(field).and_then(Value::as_str) {
            check_namespace_mode(field, v)?;
        }
    }

    if let Some(v) = obj.get("NetworkMode").and_then(Value::as_str)
        && (v == "host" || v.starts_with("container:"))
    {
        return Err(format!("NetworkMode={v}"));
    }

    if let Some(v) = obj.get("CgroupParent").and_then(Value::as_str)
        && !v.is_empty()
    {
        return Err("CgroupParent set".into());
    }

    if let Some(v) = obj.get("Runtime").and_then(Value::as_str)
        && !v.is_empty()
        && v != "runc"
        && v != "default"
        && v != "crun"
    {
        return Err(format!("Runtime={v}"));
    }

    if let Some(v) = obj.get("Isolation").and_then(Value::as_str)
        && !v.is_empty()
        && v != "default"
    {
        return Err(format!("Isolation={v}"));
    }

    for field in [
        "CapAdd",
        "Devices",
        "DeviceRequests",
        "Sysctls",
        "VolumesFrom",
    ] {
        if !is_empty_or_null(obj.get(field)) {
            return Err(format!("{field} must be empty"));
        }
    }

    if let Some(arr) = obj.get("SecurityOpt").and_then(Value::as_array) {
        for entry in arr {
            let s = entry.as_str().unwrap_or("");
            if !is_safe_security_opt(s) {
                return Err(format!("SecurityOpt entry not allowed: {s}"));
            }
        }
    }

    if let Some(lc) = obj.get("LogConfig")
        && let Some(t) = lc.get("Type").and_then(Value::as_str)
        && !matches!(t, "" | "default" | "json-file" | "none" | "local")
    {
        return Err(format!("LogConfig.Type={t}"));
    }

    if let Some(binds) = obj.get("Binds").and_then(Value::as_array) {
        for b in binds {
            let s = b.as_str().unwrap_or("");
            validate_bind(s, cwd)?;
        }
    }

    if let Some(mounts) = obj.get("Mounts").and_then(Value::as_array) {
        for m in mounts {
            validate_mount(m, cwd)?;
        }
    }

    Ok(())
}

fn check_namespace_mode(field: &str, v: &str) -> Result<(), String> {
    if v.is_empty() || matches!(v, "private" | "shareable" | "default" | "host-ns-unset") {
        return Ok(());
    }
    // Rejecting `host`, `container:<id>`, and anything else we don't
    // explicitly recognise.
    Err(format!("{field}={v}"))
}

fn is_empty_or_null(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(m)) => m.is_empty(),
        Some(Value::String(s)) => s.is_empty(),
        _ => false,
    }
}

fn is_safe_security_opt(s: &str) -> bool {
    // Only permit toggles that *tighten* the default profile.
    if s.is_empty() {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "no-new-privileges:true" | "no-new-privileges=true"
    )
}

fn validate_bind(bind: &str, cwd: &Path) -> Result<(), String> {
    let mut parts = bind.splitn(3, ':');
    let src = parts.next().unwrap_or("");
    let dst = parts.next().unwrap_or("");
    if src.is_empty() || dst.is_empty() {
        return Err("malformed bind".into());
    }
    if !src.starts_with('/') {
        return Err("named volumes not allowed".into());
    }
    ensure_under_cwd(Path::new(src), cwd)
}

fn validate_mount(mount: &Value, cwd: &Path) -> Result<(), String> {
    let Some(obj) = mount.as_object() else {
        return Err("Mount must be an object".into());
    };
    let mtype = obj.get("Type").and_then(Value::as_str).unwrap_or("");
    match mtype {
        "bind" => {
            let src = obj.get("Source").and_then(Value::as_str).unwrap_or("");
            if !src.starts_with('/') {
                return Err("bind Source must be an absolute path".into());
            }
            ensure_under_cwd(Path::new(src), cwd)?;
            if let Some(bo) = obj.get("BindOptions")
                && let Some(prop) = bo.get("Propagation").and_then(Value::as_str)
                && matches!(prop, "shared" | "rshared")
            {
                return Err("shared mount propagation not allowed".into());
            }
            Ok(())
        }
        "tmpfs" => Ok(()),
        "volume" => Err("volume mounts not allowed".into()),
        "" => Err("Mount.Type required".into()),
        other => Err(format!("mount type not allowed: {other}")),
    }
}

fn ensure_under_cwd(src: &Path, cwd: &Path) -> Result<(), String> {
    let canonical = src
        .canonicalize()
        .map_err(|_| format!("bind source {} does not exist", src.display()))?;
    if !canonical.starts_with(cwd) {
        return Err(format!(
            "bind source {} is not under cwd {}",
            canonical.display(),
            cwd.display()
        ));
    }
    Ok(())
}

// ---- forwarding ---------------------------------------------------

fn handle_connection(mut client: UnixStream, state: &State) -> io::Result<()> {
    let req = match read_request(&mut client) {
        Ok(r) => r,
        Err(e) => {
            // Best-effort error report; ignore write errors.
            let _ = respond_error(&mut client, 400, &format!("bad request: {e}"));
            return Ok(());
        }
    };

    match decide(&req, state) {
        Decision::Deny { status, message } => {
            eprintln!(
                "boxx: docker deny {} {} — {}",
                req.method, req.raw_target, message
            );
            respond_error(&mut client, status, &message)
        }
        Decision::Forward => forward(req, client, state),
        Decision::ForwardWithBody(new_body) => {
            let mut req = req;
            req.body = new_body;
            forward(req, client, state)
        }
    }
}

fn forward(req: Request, mut client: UnixStream, state: &State) -> io::Result<()> {
    let mut backend = UnixStream::connect(&state.backend_socket)?;
    write_request(&mut backend, &req)?;
    pipe_response(&mut backend, &mut client)
}

fn write_request(backend: &mut UnixStream, req: &Request) -> io::Result<()> {
    write!(backend, "{} {} HTTP/1.1\r\n", req.method, req.raw_target)?;
    let mut wrote_cl = false;
    for (name, value) in &req.headers {
        let ln = name.to_ascii_lowercase();
        if ln == "content-length" {
            write!(backend, "Content-Length: {}\r\n", req.body.len())?;
            wrote_cl = true;
        } else if ln == "transfer-encoding" || ln == "host" || ln == "connection" || ln == "expect"
        {
            continue;
        } else {
            write!(backend, "{name}: {value}\r\n")?;
        }
    }
    if !wrote_cl && !req.body.is_empty() {
        write!(backend, "Content-Length: {}\r\n", req.body.len())?;
    }
    backend.write_all(b"Host: docker\r\nConnection: close\r\n\r\n")?;
    if !req.body.is_empty() {
        backend.write_all(&req.body)?;
    }
    backend.flush()
}

fn pipe_response(backend: &mut UnixStream, client: &mut UnixStream) -> io::Result<()> {
    let mut buf = vec![0u8; PIPE_BUF];
    loop {
        match backend.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if let Err(e) = client.write_all(&buf[..n]) {
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        return Ok(());
                    }
                    return Err(e);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn read_response(stream: &mut UnixStream) -> io::Result<(u16, Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof before response headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response headers too large",
            ));
        }
    };

    let mut slots = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut slots);
    resp.parse(&buf[..header_end])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parse: {e}")))?;
    let status = resp.code.unwrap_or(0);

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            let s = std::str::from_utf8(h.value).unwrap_or("");
            content_length = s.trim().parse().ok();
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            let s = std::str::from_utf8(h.value).unwrap_or("");
            if s.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }

    let raw_head = buf[..header_end].to_vec();
    let leftover = buf[header_end..].to_vec();
    let body = if chunked {
        read_chunked_body(leftover, stream, &mut tmp)?
    } else if let Some(cl) = content_length {
        read_sized_body(leftover, stream, cl, &mut tmp)?
    } else {
        // No framing info: read until EOF (caller sent Connection:
        // close, so the daemon will close after the response).
        read_until_eof(leftover, stream, &mut tmp)
    };

    Ok((status, raw_head, body))
}

fn read_sized_body(
    mut body: Vec<u8>,
    stream: &mut UnixStream,
    content_length: usize,
    tmp: &mut [u8],
) -> io::Result<Vec<u8>> {
    while body.len() < content_length {
        let n = stream.read(tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Ok(body)
}

fn read_until_eof(mut body: Vec<u8>, stream: &mut UnixStream, tmp: &mut [u8]) -> Vec<u8> {
    loop {
        match stream.read(tmp) {
            Ok(0) => return body,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return body,
        }
    }
}

/// Decode `Transfer-Encoding: chunked` framing. `buffered` holds bytes
/// already read past the header block.
fn read_chunked_body(
    mut buffered: Vec<u8>,
    stream: &mut UnixStream,
    tmp: &mut [u8],
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(buffered.len());
    let mut pos = 0;

    let ensure = |buffered: &mut Vec<u8>,
                  stream: &mut UnixStream,
                  tmp: &mut [u8],
                  need: usize|
     -> io::Result<()> {
        while buffered.len() < need {
            let n = stream.read(tmp)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof mid-chunk",
                ));
            }
            buffered.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    };

    loop {
        // Read a chunk-size line.
        let size_end = loop {
            if let Some(p) = buffered[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + p;
            }
            let n = stream.read(tmp)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof in chunk size",
                ));
            }
            buffered.extend_from_slice(&tmp[..n]);
        };
        let size_line = std::str::from_utf8(&buffered[pos..size_end])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // Ignore chunk extensions after `;`.
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad chunk size {size_hex:?}: {e}"),
            )
        })?;
        pos = size_end + 2;

        if size == 0 {
            // Trailing headers (if any) terminate with CRLFCRLF. We
            // don't use them, so just discard to the end and stop.
            return Ok(out);
        }

        ensure(&mut buffered, stream, tmp, pos + size + 2)?;
        out.extend_from_slice(&buffered[pos..pos + size]);
        pos += size + 2; // chunk data + trailing CRLF
    }
}

fn respond_error(stream: &mut UnixStream, status: u16, message: &str) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Error",
    };
    // Docker's error shape is `{"message": "..."}`. Escape the message
    // as a JSON string so quoting is safe.
    let body = serde_json::json!({"message": format!("boxx: {message}")}).to_string();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())
}

// ---- tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_api_version_strips_versioned_prefix() {
        assert_eq!(
            strip_api_version("/v1.47/containers/json"),
            "/containers/json"
        );
        assert_eq!(strip_api_version("/v1/info"), "/info");
    }

    #[test]
    fn strip_api_version_leaves_unversioned_paths() {
        assert_eq!(strip_api_version("/containers/json"), "/containers/json");
        assert_eq!(strip_api_version("/version"), "/version");
        assert_eq!(strip_api_version("/volumes"), "/volumes");
        assert_eq!(strip_api_version("/"), "/");
    }

    #[test]
    fn split_query_separates_query_string() {
        assert_eq!(split_query("/containers/json"), ("/containers/json", ""));
        assert_eq!(
            split_query("/containers/create?name=foo"),
            ("/containers/create", "name=foo")
        );
    }

    #[test]
    fn is_empty_or_null_variants() {
        assert!(is_empty_or_null(None));
        assert!(is_empty_or_null(Some(&Value::Null)));
        assert!(is_empty_or_null(Some(&serde_json::json!([]))));
        assert!(is_empty_or_null(Some(&serde_json::json!({}))));
        assert!(!is_empty_or_null(Some(&serde_json::json!(["SYS_ADMIN"]))));
        assert!(!is_empty_or_null(Some(&serde_json::json!({"k": "v"}))));
    }

    #[test]
    fn is_safe_security_opt_only_accepts_tightening_flags() {
        assert!(is_safe_security_opt(""));
        assert!(is_safe_security_opt("no-new-privileges:true"));
        assert!(is_safe_security_opt("no-new-privileges=true"));
        assert!(!is_safe_security_opt("seccomp=unconfined"));
        assert!(!is_safe_security_opt("apparmor=unconfined"));
        assert!(!is_safe_security_opt("label=disable"));
    }

    #[test]
    fn host_config_rejects_privileged() {
        let hc = serde_json::json!({"Privileged": true});
        assert!(validate_host_config(&hc, Path::new("/tmp")).is_err());
    }

    #[test]
    fn host_config_rejects_host_network() {
        let hc = serde_json::json!({"NetworkMode": "host"});
        assert!(validate_host_config(&hc, Path::new("/tmp")).is_err());
    }

    #[test]
    fn host_config_rejects_container_pid() {
        let hc = serde_json::json!({"PidMode": "container:abc123"});
        assert!(validate_host_config(&hc, Path::new("/tmp")).is_err());
    }

    #[test]
    fn host_config_rejects_capadd() {
        let hc = serde_json::json!({"CapAdd": ["SYS_ADMIN"]});
        assert!(validate_host_config(&hc, Path::new("/tmp")).is_err());
    }

    #[test]
    fn host_config_rejects_device_requests() {
        let hc = serde_json::json!({"DeviceRequests": [{"Driver": "nvidia"}]});
        assert!(validate_host_config(&hc, Path::new("/tmp")).is_err());
    }

    #[test]
    fn host_config_rejects_unconfined_seccomp() {
        let hc = serde_json::json!({"SecurityOpt": ["seccomp=unconfined"]});
        assert!(validate_host_config(&hc, Path::new("/tmp")).is_err());
    }

    #[test]
    fn host_config_accepts_empty() {
        let hc = serde_json::json!({});
        assert!(validate_host_config(&hc, Path::new("/tmp")).is_ok());
    }

    #[test]
    fn host_config_accepts_autoremove_and_tmpfs() {
        let hc = serde_json::json!({
            "AutoRemove": true,
            "ReadonlyRootfs": true,
            "Tmpfs": {"/tmp": "rw"},
            "PortBindings": {"80/tcp": [{"HostPort": "8080"}]},
        });
        assert!(validate_host_config(&hc, Path::new("/tmp")).is_ok());
    }

    #[test]
    fn bind_rejects_named_volume() {
        assert!(validate_bind("myvol:/data", Path::new("/tmp")).is_err());
    }

    #[test]
    fn bind_rejects_path_outside_cwd() {
        let tmp = std::env::temp_dir().canonicalize().unwrap();
        // /etc/passwd exists on every linux host but is not under /tmp.
        assert!(validate_bind("/etc/passwd:/mnt", &tmp).is_err());
    }

    #[test]
    fn bind_accepts_path_under_cwd() {
        let dir = std::env::temp_dir().canonicalize().unwrap();
        let bind = format!("{}:/mnt:ro", dir.display());
        assert!(validate_bind(&bind, &dir).is_ok());
    }

    #[test]
    fn mount_bind_outside_cwd_rejected() {
        let m = serde_json::json!({"Type": "bind", "Source": "/etc", "Target": "/etc"});
        let tmp = std::env::temp_dir().canonicalize().unwrap();
        assert!(validate_mount(&m, &tmp).is_err());
    }

    #[test]
    fn mount_volume_rejected() {
        let m = serde_json::json!({"Type": "volume", "Source": "v", "Target": "/data"});
        assert!(validate_mount(&m, Path::new("/tmp")).is_err());
    }

    #[test]
    fn mount_tmpfs_accepted() {
        let m = serde_json::json!({"Type": "tmpfs", "Target": "/cache"});
        assert!(validate_mount(&m, Path::new("/tmp")).is_ok());
    }

    #[test]
    fn inject_label_adds_when_missing() {
        let mut obj = serde_json::Map::new();
        inject_label(&mut obj, "sbx1");
        assert_eq!(
            obj.get("Labels").unwrap().get("boxx.sandbox").unwrap(),
            "sbx1"
        );
    }

    #[test]
    fn foreground_attach_detection() {
        assert!(!wants_foreground_attach(&serde_json::Map::new()));
        let m: serde_json::Map<_, _> = serde_json::json!({"Image": "alpine"})
            .as_object()
            .cloned()
            .unwrap();
        assert!(!wants_foreground_attach(&m));

        for flag in ["AttachStdin", "AttachStdout", "AttachStderr", "Tty", "OpenStdin"] {
            let m: serde_json::Map<_, _> = serde_json::json!({flag: true})
                .as_object()
                .cloned()
                .unwrap();
            assert!(wants_foreground_attach(&m), "flag {flag} not detected");
        }
    }

    #[test]
    fn container_ref_gate_accepts_ids_and_names() {
        assert!(is_safe_container_ref("abc123"));
        assert!(is_safe_container_ref(&"a".repeat(64)));
        assert!(is_safe_container_ref("my-container_1.2"));
    }

    #[test]
    fn container_ref_gate_rejects_path_escapes() {
        assert!(!is_safe_container_ref(""));
        assert!(!is_safe_container_ref("..")); // harmless but we still reject as non-ref
        assert!(!is_safe_container_ref("a/b"));
        assert!(!is_safe_container_ref("a b"));
        assert!(!is_safe_container_ref("a%2fb"));
        assert!(!is_safe_container_ref(&"a".repeat(200)));
    }

    #[test]
    fn inject_label_extends_existing_map() {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "Labels".to_string(),
            serde_json::json!({"existing": "value"}),
        );
        inject_label(&mut obj, "sbx1");
        let labels = obj.get("Labels").unwrap();
        assert_eq!(labels.get("existing").unwrap(), "value");
        assert_eq!(labels.get("boxx.sandbox").unwrap(), "sbx1");
    }
}
