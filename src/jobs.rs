use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rmcp::schemars::{self, JsonSchema};
use russh::{ChannelMsg, Sig};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    sync::{Notify, mpsc},
    time::{Instant, timeout, timeout_at},
};
use uuid::Uuid;

use crate::ssh::Session;

const BUFFER_LIMIT: usize = 1024 * 1024;
const JOB_LIMIT: usize = 64;
const MAX_WAIT_MS: u64 = 30_000;
const TERMINATION_GRACE: Duration = Duration::from_secs(2);

fn default_wait() -> u64 {
    1000
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecuteCommand {
    pub session_id: String,
    /// Shell command to execute on the remote host.
    pub command: String,
    /// Literal remote directory; relative paths resolve from the remote home.
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub stdin: Option<String>,
    /// No execution deadline unless specified. Timeout requests TERM, then KILL.
    pub timeout_secs: Option<u64>,
    /// Initial wait, capped at 30 seconds. A running job returns its handle.
    #[serde(default = "default_wait")]
    pub wait_ms: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetJob {
    pub job_id: String,
    /// Raw byte offset, as returned by stdout_next_offset.
    #[serde(default)]
    pub stdout_offset: u64,
    /// Raw byte offset, as returned by stderr_next_offset.
    #[serde(default)]
    pub stderr_offset: u64,
    /// Wait for new output or a status change, capped at 30 seconds.
    #[serde(default)]
    pub wait_ms: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelJob {
    pub job_id: String,
}

#[derive(Default)]
struct OutputBuffer {
    bytes: VecDeque<u8>,
    end: u64,
}

impl OutputBuffer {
    fn append(&mut self, bytes: &[u8]) {
        self.end += bytes.len() as u64;
        if bytes.len() >= BUFFER_LIMIT {
            self.bytes.clear();
            self.bytes.extend(&bytes[bytes.len() - BUFFER_LIMIT..]);
        } else {
            let discard = (self.bytes.len() + bytes.len()).saturating_sub(BUFFER_LIMIT);
            self.bytes.drain(..discard);
            self.bytes.extend(bytes);
        }
    }

    fn start(&self) -> u64 {
        self.end - self.bytes.len() as u64
    }

    fn read(&self, offset: u64) -> Result<(String, u64, bool)> {
        ensure!(offset <= self.end, "output offset exceeds available bytes");
        let start = self.start();
        let actual = offset.max(start);
        let bytes: Vec<u8> = self
            .bytes
            .iter()
            .skip((actual - start) as usize)
            .copied()
            .collect();
        // Offsets count wire bytes, even when invalid or split UTF-8 is replaced.
        Ok((
            String::from_utf8_lossy(&bytes).into_owned(),
            actual,
            offset < start,
        ))
    }
}

struct JobState {
    status: &'static str,
    terminal: bool,
    stdout: OutputBuffer,
    stderr: OutputBuffer,
    exit_code: Option<u32>,
    exit_signal: Option<String>,
    error: Option<String>,
    cancellation_requested: bool,
    timed_out: bool,
    finished_at: Option<Instant>,
}

impl Default for JobState {
    fn default() -> Self {
        Self {
            status: "starting",
            terminal: false,
            stdout: OutputBuffer::default(),
            stderr: OutputBuffer::default(),
            exit_code: None,
            exit_signal: None,
            error: None,
            cancellation_requested: false,
            timed_out: false,
            finished_at: None,
        }
    }
}

struct Job {
    id: String,
    session_id: String,
    state: Mutex<JobState>,
    changed: Notify,
    cancel: mpsc::Sender<()>,
}

struct CancelOnDrop(Option<mpsc::Sender<()>>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.try_send(());
        }
    }
}

impl Job {
    fn finish(&self, status: &'static str, error: Option<String>) {
        let mut state = self.state.lock().expect("job state poisoned");
        state.status = status;
        state.terminal = true;
        if error.is_some() {
            state.error = error;
        }
        state.finished_at = Some(Instant::now());
        drop(state);
        self.changed.notify_waiters();
    }

    fn snapshot(&self, stdout_offset: u64, stderr_offset: u64) -> Result<(Value, bool)> {
        let state = self.state.lock().expect("job state poisoned");
        let (stdout, stdout_start_offset, stdout_truncated) = state.stdout.read(stdout_offset)?;
        let (stderr, stderr_start_offset, stderr_truncated) = state.stderr.read(stderr_offset)?;
        let wait = !state.terminal
            && stdout_offset == state.stdout.end
            && stderr_offset == state.stderr.end;
        Ok((
            json!({
                "job_id": self.id,
                "session_id": self.session_id,
                "status": state.status,
                "exit_code": state.exit_code,
                "exit_signal": state.exit_signal,
                "error": state.error,
                "cancellation_requested": state.cancellation_requested,
                "timed_out": state.timed_out,
                "output_encoding": "utf8_lossy",
                "stdout": stdout,
                "stderr": stderr,
                "stdout_start_offset": stdout_start_offset,
                "stdout_next_offset": state.stdout.end,
                "stdout_truncated": stdout_truncated,
                "stderr_start_offset": stderr_start_offset,
                "stderr_next_offset": state.stderr.end,
                "stderr_truncated": stderr_truncated,
            }),
            wait,
        ))
    }

    async fn wait_terminal(&self, deadline: Instant) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.state.lock().expect("job state poisoned").terminal {
                return;
            }
            if timeout_at(deadline, changed).await.is_err() {
                return;
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct JobManager {
    jobs: Arc<Mutex<HashMap<String, Arc<Job>>>>,
    stopping: Arc<AtomicBool>,
}

impl JobManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn execute(&self, session: Arc<Session>, input: ExecuteCommand) -> Result<Value> {
        let command = build_command(&session.home, &input)?;
        ensure!(input.session_id == session.id, "session ID mismatch");
        let deadline = input
            .timeout_secs
            .map(|secs| {
                ensure!(secs != 0, "timeout_secs must be positive");
                Instant::now()
                    .checked_add(Duration::from_secs(secs))
                    .context("timeout_secs is too large")
            })
            .transpose()?;
        let permit = session
            .command_slots
            .clone()
            .try_acquire_owned()
            .context("connection already has eight running commands; poll or cancel a job")?;
        let (cancel, requests) = mpsc::channel(1);
        let job = Arc::new(Job {
            id: Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            state: Mutex::new(JobState::default()),
            changed: Notify::new(),
            cancel,
        });
        {
            let mut jobs = self.jobs.lock().expect("job registry poisoned");
            ensure!(
                !self.stopping.load(Ordering::SeqCst),
                "server is shutting down"
            );
            ensure!(
                !session.command_slots.is_closed(),
                "session is disconnecting"
            );
            if jobs.len() >= JOB_LIMIT {
                let oldest = jobs
                    .values()
                    .filter_map(|job| {
                        job.state
                            .lock()
                            .expect("job state poisoned")
                            .finished_at
                            .map(|finished| (finished, job.id.clone()))
                    })
                    .min_by_key(|(finished, _)| *finished)
                    .map(|(_, id)| id)
                    .context("all 64 retained jobs are still running")?;
                jobs.remove(&oldest);
            }
            jobs.insert(job.id.clone(), job.clone());
        }
        // Until the caller receives its handle, cancellation must not orphan a command.
        let mut cancel_on_drop = CancelOnDrop(Some(job.cancel.clone()));
        let running_job = job.clone();
        tokio::spawn(async move {
            let _permit = permit;
            run_job(
                session,
                running_job,
                command,
                input.stdin,
                deadline,
                requests,
            )
            .await;
        });
        job.wait_terminal(Instant::now() + Duration::from_millis(input.wait_ms.min(MAX_WAIT_MS)))
            .await;
        let snapshot = job.snapshot(0, 0)?.0;
        cancel_on_drop.0 = None;
        Ok(snapshot)
    }

    fn find(&self, id: &str) -> Result<Arc<Job>> {
        self.jobs
            .lock()
            .expect("job registry poisoned")
            .get(id)
            .cloned()
            .context("unknown job ID (completed jobs may have been evicted)")
    }

    pub async fn get(&self, input: GetJob) -> Result<Value> {
        let job = self.find(&input.job_id)?;
        let changed = job.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let (snapshot, should_wait) = job.snapshot(input.stdout_offset, input.stderr_offset)?;
        if should_wait && input.wait_ms != 0 {
            let _ = timeout(
                Duration::from_millis(input.wait_ms.min(MAX_WAIT_MS)),
                changed,
            )
            .await;
            return Ok(job.snapshot(input.stdout_offset, input.stderr_offset)?.0);
        }
        Ok(snapshot)
    }

    pub async fn cancel(&self, id: &str) -> Result<Value> {
        let job = self.find(id)?;
        if !job.state.lock().expect("job state poisoned").terminal {
            let _ = job.cancel.try_send(());
            job.wait_terminal(Instant::now() + Duration::from_millis(4500))
                .await;
        }
        Ok(job.snapshot(0, 0)?.0)
    }

    pub async fn cancel_session(&self, session_id: &str) {
        let jobs: Vec<_> = self
            .jobs
            .lock()
            .expect("job registry poisoned")
            .values()
            .filter(|job| job.session_id == session_id)
            .cloned()
            .collect();
        cancel_all(jobs).await;
    }

    pub async fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let jobs = self
            .jobs
            .lock()
            .expect("job registry poisoned")
            .values()
            .cloned()
            .collect();
        cancel_all(jobs).await;
    }
}

async fn cancel_all(jobs: Vec<Arc<Job>>) {
    for job in &jobs {
        let _ = job.cancel.try_send(());
    }
    let deadline = Instant::now() + Duration::from_millis(4500);
    for job in jobs {
        job.wait_terminal(deadline).await;
    }
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn build_command(home: &str, input: &ExecuteCommand) -> Result<String> {
    ensure!(!input.command.is_empty(), "command must not be empty");
    ensure!(input.command.len() <= BUFFER_LIMIT, "command exceeds 1 MiB");
    ensure!(!input.command.contains('\0'), "command contains NUL");
    ensure!(
        input.stdin.as_ref().is_none_or(|s| s.len() <= BUFFER_LIMIT),
        "stdin exceeds 1 MiB"
    );
    let cwd = crate::files::remote_path(home, input.cwd.as_deref().unwrap_or("."))?;
    ensure!(cwd.len() <= BUFFER_LIMIT, "cwd exceeds 1 MiB");
    ensure!(!cwd.contains('\0'), "cwd contains NUL");
    let mut script = String::new();
    let environment_bytes = input.env.iter().try_fold(0usize, |total, (name, value)| {
        total.checked_add(name.len())?.checked_add(value.len())
    });
    ensure!(
        environment_bytes.is_some_and(|size| size <= BUFFER_LIMIT),
        "environment exceeds 1 MiB"
    );
    for (name, value) in &input.env {
        ensure!(
            !name.is_empty()
                && name.bytes().enumerate().all(|(i, c)| {
                    c == b'_' || c.is_ascii_alphabetic() || (i != 0 && c.is_ascii_digit())
                }),
            "invalid environment variable name"
        );
        ensure!(!value.contains('\0'), "environment value contains NUL");
        if crate::files::windows_home(home) {
            script.push_str(&format!(
                "[Environment]::SetEnvironmentVariable('{}', '{}'); ",
                name,
                value.replace('\'', "''")
            ));
        } else {
            script.push_str(&format!("export {name}={}; ", quote(value)));
        }
    }
    if crate::files::windows_home(home) {
        let cwd = cwd.strip_prefix('/').unwrap_or(&cwd);
        script.push_str(&format!(
            "Set-Location -LiteralPath '{}' -ErrorAction Stop; ",
            cwd.replace('\'', "''")
        ));
        script.push_str(&input.command);
        let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        return Ok(format!(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {}",
            STANDARD.encode(bytes)
        ));
    }
    script.push_str(&format!(
        "cd -- {} && exec sh -c {}",
        quote(&cwd),
        quote(&input.command)
    ));
    Ok(format!("sh -c {}", quote(&script)))
}

async fn run_job(
    session: Arc<Session>,
    job: Arc<Job>,
    command: String,
    stdin: Option<String>,
    deadline: Option<Instant>,
    mut requests: mpsc::Receiver<()>,
) {
    let open_deadline = deadline
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(15))
        .min(Instant::now() + Duration::from_secs(15));
    let channel = tokio::select! {
        biased;
        _ = requests.recv() => {
            job.state.lock().expect("job state poisoned").cancellation_requested = true;
            job.finish("cancelled", None);
            return;
        },
        result = timeout_at(open_deadline, session.handle.channel_open_session()) => {
            match result {
                Ok(Ok(channel)) => channel,
                Ok(Err(error)) => {
                    job.finish("failed", Some(format!("could not open command channel: {error}")));
                    return;
                },
                Err(_) => {
                    let mut state = job.state.lock().expect("job state poisoned");
                    state.timed_out = deadline.is_some_and(|d| d <= Instant::now());
                    drop(state);
                    job.finish("failed", Some("command channel open timed out; no command was submitted".into()));
                    return;
                },
            }
        }
    };
    if requests.try_recv().is_ok() {
        let _ = timeout(TERMINATION_GRACE, channel.close()).await;
        job.state
            .lock()
            .expect("job state poisoned")
            .cancellation_requested = true;
        job.finish("cancelled", None);
        return;
    }
    if !matches!(
        timeout_at(open_deadline, channel.exec(true, command)).await,
        Ok(Ok(()))
    ) {
        let _ = timeout(TERMINATION_GRACE, channel.close()).await;
        job.finish(
            "unknown",
            Some("exec submission failed; remote outcome is unknown".into()),
        );
        return;
    }
    let (mut reader, writer) = channel.split();
    let writer = Arc::new(writer);
    let stdin_writer = writer.clone();
    let stdin_task = tokio::spawn(async move {
        if let Some(stdin) = stdin {
            stdin_writer.data(stdin.as_bytes()).await?;
        }
        stdin_writer.eof().await
    });
    {
        job.state.lock().expect("job state poisoned").status = "running";
        job.changed.notify_waiters();
    }
    let mut termination_deadline = None;
    let mut kill_sent = false;
    let mut stdin_task = stdin_task;
    let mut stdin_done = false;
    loop {
        // A far-future timer avoids holding a pending borrowed future across iterations.
        let timer = termination_deadline
            .or(deadline)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(365 * 24 * 60 * 60));
        tokio::select! {
            message = reader.wait() => {
                match message {
                    Some(ChannelMsg::Data {data}) => {
                        job.state.lock().expect("job state poisoned").stdout.append(&data);
                        job.changed.notify_waiters();
                    },
                    Some(ChannelMsg::ExtendedData {data, ext: 1}) => {
                        job.state.lock().expect("job state poisoned").stderr.append(&data);
                        job.changed.notify_waiters();
                    },
                    Some(ChannelMsg::ExitStatus {exit_status}) => {
                        job.state.lock().expect("job state poisoned").exit_code = Some(exit_status);
                        job.changed.notify_waiters();
                    },
                    Some(ChannelMsg::ExitSignal {signal_name, ..}) => {
                        job.state.lock().expect("job state poisoned").exit_signal = Some(format!("{signal_name:?}"));
                        job.changed.notify_waiters();
                    },
                    Some(ChannelMsg::Failure | ChannelMsg::OpenFailure(_)) => {
                        stdin_task.abort();
                        let _ = timeout(TERMINATION_GRACE, writer.close()).await;
                        job.finish("failed", Some("server rejected command execution".into()));
                        return;
                    },
                    Some(ChannelMsg::Close) | None => {
                        stdin_task.abort();
                        let state = job.state.lock().expect("job state poisoned");
                        let status = if state.exit_code.is_some() || state.exit_signal.is_some() {
                            if state.cancellation_requested {"cancelled"} else {"completed"}
                        } else {"unknown"};
                        let error = (status == "unknown").then(|| "channel closed without an exit status; remote outcome is unknown".into());
                        drop(state);
                        job.finish(status, error);
                        return;
                    },
                    _ => {},
                }
            },
            _ = requests.recv(), if termination_deadline.is_none() => {
                stdin_task.abort();
                {
                    let mut state = job.state.lock().expect("job state poisoned");
                    state.cancellation_requested = true;
                    state.status = "cancellation_requested";
                }
                job.changed.notify_waiters();
                let _ = timeout(TERMINATION_GRACE, writer.signal(Sig::TERM)).await;
                termination_deadline = Some(Instant::now() + TERMINATION_GRACE);
            },
            _ = tokio::time::sleep_until(timer) => {
                if termination_deadline.is_none() {
                    stdin_task.abort();
                    {
                        let mut state = job.state.lock().expect("job state poisoned");
                        state.timed_out = true;
                        state.cancellation_requested = true;
                        state.status = "cancellation_requested";
                    }
                    job.changed.notify_waiters();
                    let _ = timeout(TERMINATION_GRACE, writer.signal(Sig::TERM)).await;
                    termination_deadline = Some(Instant::now() + TERMINATION_GRACE);
                } else if !kill_sent {
                    let _ = timeout(TERMINATION_GRACE, writer.signal(Sig::KILL)).await;
                    kill_sent = true;
                    termination_deadline = Some(Instant::now() + TERMINATION_GRACE);
                } else {
                    let _ = timeout(TERMINATION_GRACE, writer.close()).await;
                    let confirmed = {
                        let state = job.state.lock().expect("job state poisoned");
                        state.exit_code.is_some() || state.exit_signal.is_some()
                    };
                    if confirmed {
                        job.finish("cancelled", Some("remote exit was confirmed, but the output channel did not close; remaining output may be incomplete".into()));
                    } else {
                        job.finish("unknown", Some("termination was requested but remote exit was not confirmed".into()));
                    }
                    return;
                }
            },
            result = &mut stdin_task, if !stdin_done => {
                stdin_done = true;
                if !matches!(result, Ok(Ok(()))) {
                    let mut state = job.state.lock().expect("job state poisoned");
                    if !state.cancellation_requested {
                        state.error = Some("sending stdin failed; some input may not have been delivered".into());
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(command: &str) -> ExecuteCommand {
        serde_json::from_value(json!({"session_id":"test", "command":command})).unwrap()
    }

    #[test]
    fn output_tracks_offsets_and_retains_only_tail() {
        let mut buffer = OutputBuffer::default();
        buffer.append(&vec![b'a'; BUFFER_LIMIT]);
        buffer.append(b"end");
        assert_eq!(buffer.start(), 3);
        let (text, actual, truncated) = buffer.read(0).unwrap();
        assert_eq!(text.len(), BUFFER_LIMIT);
        assert!(text.ends_with("end"));
        assert_eq!(actual, 3);
        assert!(truncated);
        assert_eq!(
            buffer.read(buffer.end).unwrap(),
            (String::new(), buffer.end, false)
        );
        assert!(buffer.read(buffer.end + 1).is_err());
        buffer.append(&vec![b'z'; BUFFER_LIMIT * 2]);
        assert_eq!(buffer.bytes.len(), BUFFER_LIMIT);
        assert_eq!(buffer.start(), BUFFER_LIMIT as u64 * 2 + 3);
    }

    #[test]
    fn validates_command_and_environment_without_restricting_shell_syntax() {
        assert!(build_command("/home/user", &input("echo a | cat")).is_ok());
        assert!(build_command("/home/user", &input("")).is_err());
        assert!(build_command("/home/user", &input("echo\0unsafe")).is_err());
        let mut request = input("true");
        request.env.insert("X; touch /tmp/oops".into(), "v".into());
        assert!(build_command("/home/user", &request).is_err());
        request.env.clear();
        request.env.insert("1INVALID".into(), "v".into());
        assert!(build_command("/home/user", &request).is_err());
        request.env.clear();
        request.env.insert("_VALID_1".into(), "v".into());
        assert!(build_command("/home/user", &request).is_ok());
    }

    #[test]
    fn windows_command_encodes_literal_environment_and_directory() {
        let mut request = input("Write-Output $env:TEST_VALUE");
        request.cwd = Some("D:/O'Brien".into());
        request
            .env
            .insert("TEST_VALUE".into(), "a'; Remove-Item x; '".into());
        let command = build_command("/C:/Users/test", &request).unwrap();
        let bytes = STANDARD
            .decode(command.rsplit_once(' ').unwrap().1)
            .unwrap();
        let words: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let script = String::from_utf16(&words).unwrap();
        assert!(script.contains("SetEnvironmentVariable('TEST_VALUE', 'a''; Remove-Item x; ''')"));
        assert!(script.contains("Set-Location -LiteralPath 'D:/O''Brien'"));
        assert!(script.ends_with("Write-Output $env:TEST_VALUE"));
    }

    #[test]
    fn byte_offsets_remain_correct_for_invalid_utf8() {
        let mut buffer = OutputBuffer::default();
        buffer.append(&[0xff, b'x']);
        let (text, actual, truncated) = buffer.read(0).unwrap();
        assert_eq!(text, "\u{fffd}x");
        assert_eq!(actual, 0);
        assert!(!truncated);
        assert_eq!(buffer.end, 2);
        assert_eq!(buffer.read(1).unwrap().0, "x");
    }

    #[tokio::test]
    async fn completion_wakes_waiters_and_preserves_stdin_delivery_errors() {
        let (cancel, _) = mpsc::channel(1);
        let job = Arc::new(Job {
            id: "job".into(),
            session_id: "session".into(),
            state: Mutex::new(JobState::default()),
            changed: Notify::new(),
            cancel,
        });
        job.state.lock().unwrap().error = Some("stdin incomplete".into());
        let completing = job.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            completing.finish("completed", None);
        });
        timeout(
            Duration::from_secs(1),
            job.wait_terminal(Instant::now() + Duration::from_secs(10)),
        )
        .await
        .unwrap();
        let (snapshot, should_wait) = job.snapshot(0, 0).unwrap();
        assert_eq!(snapshot["status"], "completed");
        assert_eq!(snapshot["error"], "stdin incomplete");
        assert!(!should_wait);
    }

    #[tokio::test]
    async fn abandoned_initial_call_requests_cancellation_but_returned_handle_does_not() {
        let (sender, mut receiver) = mpsc::channel(1);
        let armed = CancelOnDrop(Some(sender.clone()));
        drop(armed);
        assert_eq!(receiver.try_recv(), Ok(()));
        let mut disarmed = CancelOnDrop(Some(sender));
        disarmed.0 = None;
        drop(disarmed);
        assert!(receiver.try_recv().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cwd_and_env_are_literal_and_command_keeps_its_shell_syntax() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("a' $(printf BAD)");
        std::fs::create_dir(&cwd).unwrap();
        let mut request = input("printf '%s\\n' \"$TEST_VALUE\"; pwd; printf x | cat");
        request.cwd = Some(cwd.to_str().unwrap().into());
        request
            .env
            .insert("TEST_VALUE".into(), "x'$(printf BAD)\n".into());
        let command = build_command("/", &request).unwrap();
        let output = std::process::Command::new("sh")
            .args(["-c", &command])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("x'$(printf BAD)\n\n{}\nx", cwd.display())
        );
    }
}
