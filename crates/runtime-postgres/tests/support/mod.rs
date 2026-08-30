//! Shared support for `runtime-postgres` live-database integration tests.
//!
//! Every live test file under `tests/` includes this module with `mod
//! support;` and links against it independently, since each top-level file
//! under `tests/` compiles as its own test binary. Nothing here talks to a
//! database directly except the readiness check in [`DockerCrashGuard`]: this
//! module serializes destructive live tests against each other, resolves and
//! validates the environment configuration the crash-recovery scenario
//! needs, and drives `docker` by direct argv.
#![allow(dead_code)]

use postgres::{Config, NoTls};
use std::{
    env,
    ffi::OsString,
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Environment variable naming the live database this crate's integration
/// tests connect to. Unset means every live test skips.
pub const LIVE_POSTGRES_URL_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_URL";

/// Environment variable naming the Docker container ID the SIGKILL
/// crash-recovery scenario is permitted to kill and restart. CI supplies the
/// exact database-service container ID here; see `.github/workflows/ci.yml`.
pub const CRASH_CONTAINER_ID_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID";

/// Environment variable that, when set to exactly `"1"`, forbids the
/// crash-recovery scenario from silently skipping. CI sets this so a broken
/// container-ID derivation fails the run instead of passing for the wrong
/// reason.
pub const CRASH_REQUIRED_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED";

// --- Bounded, cross-process live-test lock ---------------------------------

/// Hard bound on how long [`LiveTestLock::acquire`] waits for the lock
/// before giving up. Destructive live tests (the schema/durable-store
/// conformance test and the SIGKILL crash-recovery scenario) serialize on
/// this lock because more than one of them may run concurrently as separate
/// `cargo test` binary processes, and one of them kills the whole
/// database-service container out from under every other live test. A bound
/// keeps a stuck or abandoned lock a loud failure instead of a hang.
const LIVE_LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(180);

/// Poll interval while waiting for [`LIVE_LOCK_ACQUIRE_TIMEOUT`] to elapse.
const LIVE_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Resolves the one lock-file path every live test process sharing this OS
/// temp directory contends for. `env::temp_dir()` resolves per `TMPDIR` (or
/// platform equivalent), which is commonly scoped per user rather than
/// shared host-wide, so this coordinates every live test process for one
/// temp directory/user, not necessarily the whole host. Fixed and outside
/// the crate's own build/target directories so it identifies the same file
/// regardless of which test binary or worktree invokes it.
fn live_lock_path() -> PathBuf {
    env::temp_dir().join("sunrise-edge-runtime-postgres-live-test.lock")
}

/// Process-unique counter mixed into [`LockOwner::current`] so two
/// acquisitions from the same process in quick succession (acquire, drop,
/// acquire again, all within one test binary) never produce the same
/// identity even if the system clock has not visibly advanced.
static LOCK_OWNER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The identity a [`LiveTestLock`] records in its lock file: which OS
/// process holds it, and a nonce distinguishing this specific acquisition
/// from any other acquisition (including a prior one by the same, recycled
/// PID). Both are required for [`LiveTestLock`] to answer "is the current
/// on-disk lock still the exact one I created?" before deleting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LockOwner {
    pid: u32,
    nonce: u64,
}

impl LockOwner {
    fn current() -> Self {
        let nanos_since_epoch: u64 = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos(),
        )
        .unwrap_or(0);
        let sequence = LOCK_OWNER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self {
            pid: std::process::id(),
            nonce: nanos_since_epoch ^ sequence,
        }
    }

    fn to_file_contents(self) -> String {
        format!("{}:{}", self.pid, self.nonce)
    }

    fn parse(contents: &str) -> Option<Self> {
        let (pid_text, nonce_text) = contents.trim().split_once(':')?;
        Some(Self {
            pid: pid_text.parse().ok()?,
            nonce: nonce_text.parse().ok()?,
        })
    }
}

/// Reads and parses the current on-disk lock owner, or `None` if the file is
/// missing, unreadable, or its contents do not parse as a [`LockOwner`].
fn read_lock_owner(path: &Path) -> Option<LockOwner> {
    LockOwner::parse(&fs::read_to_string(path).ok()?)
}

/// Atomically creates the lock file with `owner` as its sole contents.
/// `create_new` is POSIX `O_EXCL`/Windows `CREATE_NEW`, so two processes
/// racing to create the same path can never both succeed.
fn create_lock_file(path: &Path, owner: LockOwner) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(owner.to_file_contents().as_bytes())?;
    file.sync_all()
}

/// A held, bounded, cross-process exclusive lock. Destructive live tests
/// must acquire this before any live database work, so at most one of them
/// touches the shared live database (and, for the crash scenario, its
/// container) at a time.
///
/// The lock is released by [`Drop`], including when the holding test panics.
/// A process that is itself killed (for example, by the very SIGKILL the
/// crash scenario sends to something else going wrong and taking the test
/// harness down with it) cannot run `Drop`, so the lock file is abandoned on
/// disk. This module never reclaims an abandoned lock automatically: doing
/// so from another waiter would require a read-check-remove sequence that is
/// inherently TOCTOU (the file it read as stale could be removed and
/// recreated by a legitimate new owner between the check and the remove),
/// which could delete a newly acquired replacement lock out from under its
/// owner. Instead an abandoned lock simply fails every future
/// [`LiveTestLock::acquire`] loudly, once [`LIVE_LOCK_ACQUIRE_TIMEOUT`]
/// elapses, with a message pointing at the file to delete; cleaning it up is
/// an explicit, human decision. [`Drop`] only ever deletes the file if it
/// still records this exact acquisition (matching PID *and* nonce): if
/// something else already holds the path, this guard must not delete it.
pub struct LiveTestLock {
    path: PathBuf,
    owner: LockOwner,
}

impl LiveTestLock {
    pub fn acquire() -> Self {
        let path = live_lock_path();
        let owner = LockOwner::current();
        let deadline = Instant::now() + LIVE_LOCK_ACQUIRE_TIMEOUT;
        loop {
            match create_lock_file(&path, owner) {
                Ok(()) => return Self { path, owner },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        panic!(
                            "timed out after {LIVE_LOCK_ACQUIRE_TIMEOUT:?} waiting for the \
                             exclusive live PostgreSQL test lock at {}; if no other live test is \
                             actually running, delete this file",
                            path.display()
                        );
                    }
                    thread::sleep(LIVE_LOCK_POLL_INTERVAL);
                }
                Err(error) => panic!(
                    "failed to create live PostgreSQL test lock at {}: {error}",
                    path.display()
                ),
            }
        }
    }
}

impl Drop for LiveTestLock {
    fn drop(&mut self) {
        if read_lock_owner(&self.path) == Some(self.owner) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// --- Strict crash-scenario environment parsing ------------------------------

/// A Docker container ID as it is intended to reach `Command` argv: never
/// interpolated into a shell string, but still validated on the way in, so a
/// malformed [`CRASH_CONTAINER_ID_ENV`] fails with a clear error at parse
/// time instead of as a confusing `docker` CLI error later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerId(String);

/// Docker assigns short IDs as 12 lowercase-hex characters and full IDs as
/// 64; this validator accepts exactly that range and nothing else.
const CONTAINER_ID_MIN_LEN: usize = 12;
const CONTAINER_ID_MAX_LEN: usize = 64;

impl ContainerId {
    /// Validates `raw` as lowercase-hex, `CONTAINER_ID_MIN_LEN` to
    /// `CONTAINER_ID_MAX_LEN` characters. Rejects uppercase hex, since Docker
    /// itself never produces it and accepting it would let two textually
    /// different strings address the same container.
    pub fn parse(raw: &str) -> Result<Self, ContainerIdError> {
        let len = raw.len();
        if !(CONTAINER_ID_MIN_LEN..=CONTAINER_ID_MAX_LEN).contains(&len) {
            return Err(ContainerIdError::InvalidLength(len));
        }
        if !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContainerIdError::InvalidCharacters);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerIdError {
    InvalidLength(usize),
    InvalidCharacters,
}

impl fmt::Display for ContainerIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerIdError::InvalidLength(len) => write!(
                formatter,
                "container ID must be {CONTAINER_ID_MIN_LEN}-{CONTAINER_ID_MAX_LEN} characters, got {len}"
            ),
            ContainerIdError::InvalidCharacters => {
                write!(formatter, "container ID must be lowercase hex")
            }
        }
    }
}

impl std::error::Error for ContainerIdError {}

/// Outcome of strictly resolving whether the SIGKILL crash-recovery scenario
/// runs in this process.
#[derive(Debug)]
pub enum CrashScenario {
    /// Neither the live database URL nor the container ID is configured:
    /// every live test, including the crash scenario, is skipped.
    Skip,
    /// Run the crash scenario against this validated container.
    Run(ContainerId),
}

/// Strictly resolves [`CrashScenario`] from [`CRASH_CONTAINER_ID_ENV`] and
/// [`CRASH_REQUIRED_ENV`], given whether the caller already found
/// [`LIVE_POSTGRES_URL_ENV`] configured.
///
/// Only "both absent" skips. Every other outcome other than a fully
/// configured, valid pair is a panic:
/// - one of the live URL / container ID configured without the other is a
///   partial configuration, which always fails rather than skipping, because
///   a live test that silently downgraded to a skip on half-broken
///   configuration could pass in CI for the wrong reason;
/// - [`CRASH_REQUIRED_ENV`] set to anything other than exactly `"1"` fails,
///   rather than being coerced from `"true"`/`"0"`/etc.;
/// - `CRASH_REQUIRED_ENV=1` with nothing else configured fails instead of
///   skipping, since CI sets it precisely to convert "the scenario quietly
///   never ran" into a failure;
/// - a configured container ID that is not valid lowercase hex fails.
pub fn resolve_crash_scenario(live_url_configured: bool) -> CrashScenario {
    resolve_crash_scenario_from(
        live_url_configured,
        env::var_os(CRASH_REQUIRED_ENV),
        env::var_os(CRASH_CONTAINER_ID_ENV),
    )
}

/// Pure decision logic behind [`resolve_crash_scenario`], taking its
/// environment inputs as explicit arguments instead of reading the process
/// environment itself. Split out so unit tests can exercise every branch
/// without mutating real environment variables, which `cargo test`'s
/// default parallel-by-thread execution would otherwise race across tests.
fn resolve_crash_scenario_from(
    live_url_configured: bool,
    crash_required_raw: Option<OsString>,
    container_id_raw: Option<OsString>,
) -> CrashScenario {
    let required = parse_crash_required_flag(crash_required_raw);
    match (live_url_configured, container_id_raw) {
        (false, None) => {
            if required {
                panic!(
                    "{CRASH_REQUIRED_ENV} is set but neither {LIVE_POSTGRES_URL_ENV} nor \
                     {CRASH_CONTAINER_ID_ENV} is configured"
                );
            }
            CrashScenario::Skip
        }
        (true, None) => panic!(
            "{LIVE_POSTGRES_URL_ENV} is set but {CRASH_CONTAINER_ID_ENV} is not; partial live \
             PostgreSQL crash-test configuration is not allowed"
        ),
        (false, Some(_)) => panic!(
            "{CRASH_CONTAINER_ID_ENV} is set but {LIVE_POSTGRES_URL_ENV} is not; partial live \
             PostgreSQL crash-test configuration is not allowed"
        ),
        (true, Some(raw)) => CrashScenario::Run(parse_container_id(raw)),
    }
}

fn parse_container_id(raw: OsString) -> ContainerId {
    let text = raw
        .to_str()
        .unwrap_or_else(|| panic!("{CRASH_CONTAINER_ID_ENV} must be valid UTF-8"));
    ContainerId::parse(text)
        .unwrap_or_else(|error| panic!("{CRASH_CONTAINER_ID_ENV} is invalid: {error}"))
}

fn parse_crash_required_flag(raw: Option<OsString>) -> bool {
    match raw {
        None => false,
        Some(raw) => {
            let text = raw
                .to_str()
                .unwrap_or_else(|| panic!("{CRASH_REQUIRED_ENV} must be valid UTF-8"));
            match text {
                "1" => true,
                other => {
                    panic!("{CRASH_REQUIRED_ENV} must be exactly \"1\" when set, got {other:?}")
                }
            }
        }
    }
}

// --- Panic-safe Docker SIGKILL/start/readiness guard ------------------------

/// Bound on how long [`DockerCrashGuard::restart_and_wait_ready`] (and the
/// equivalent best-effort [`Drop`] path) waits for a fresh client connection
/// and trivial query to succeed against the restarted container before
/// giving up.
const CONTAINER_READY_TIMEOUT: Duration = Duration::from_secs(60);

/// Poll interval while waiting for [`CONTAINER_READY_TIMEOUT`] to elapse.
const CONTAINER_READY_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Builds a `docker <args>` invocation as direct argv. Every argument is a
/// separate `Command` argument, never concatenated into a string and handed
/// to a shell, so nothing in a container ID or subcommand name can be
/// reinterpreted as shell syntax.
fn docker_argv_command(args: &[&str]) -> Command {
    let mut command = Command::new("docker");
    command.args(args);
    command
}

fn docker_exit_error(label: &str, status: ExitStatus) -> io::Error {
    io::Error::other(format!("{label} exited with {status}"))
}

/// Bound on how long one spawned `docker` CLI invocation may run before this
/// guard kills the `docker` process itself and reports a timeout, rather
/// than let a hung Docker daemon or CLI turn a bounded test into an
/// unbounded hang. `docker kill`/`docker start` normally complete in well
/// under a second.
const DOCKER_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for a spawned `docker` child process to exit
/// within [`DOCKER_COMMAND_TIMEOUT`].
const DOCKER_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Runs `command` to completion using `spawn` plus `try_wait` polling
/// instead of the blocking `status()`, so a hung child is bounded by
/// [`DOCKER_COMMAND_TIMEOUT`] instead of hanging this guard forever. On
/// timeout, kills and reaps the child before returning an error; no shell
/// and no additional crate is involved, only `std::process`.
fn run_docker_command_bounded(mut command: Command, label: &str) -> io::Result<()> {
    let mut child: Child = command.spawn()?;
    let deadline = Instant::now() + DOCKER_COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(docker_exit_error(label, status))
                };
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other(format!(
                "{label} did not exit within {DOCKER_COMMAND_TIMEOUT:?} and was killed"
            )));
        }
        thread::sleep(DOCKER_COMMAND_POLL_INTERVAL);
    }
}

fn docker_kill(container_id: &ContainerId) -> io::Result<()> {
    run_docker_command_bounded(
        docker_argv_command(&["kill", "--signal=KILL", container_id.as_str()]),
        "docker kill",
    )
}

fn docker_start(container_id: &ContainerId) -> io::Result<()> {
    run_docker_command_bounded(
        docker_argv_command(&["start", container_id.as_str()]),
        "docker start",
    )
}

/// Per-attempt connect timeout for the readiness probe below. Deliberately
/// short relative to [`CONTAINER_READY_TIMEOUT`]: the poll loop, not any
/// single attempt, provides the overall bound, so one attempt hanging on a
/// dead container must not be allowed to consume the whole budget itself.
const READINESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Statement timeout applied, session-wide, to the readiness probe's own
/// connection before it runs the trivial query, so a connection that
/// completes a TCP/startup handshake but never answers a query is also
/// bounded well inside [`CONTAINER_READY_TIMEOUT`] rather than left to the
/// driver's own (much longer, or absent) default.
const READINESS_STATEMENT_TIMEOUT: Duration = Duration::from_secs(2);

/// Readiness means a brand-new client can connect and run a trivial query,
/// not merely that the container process is up: the exact readiness
/// criterion this test needs before it reconnects and reads back committed
/// data is a fresh external connection plus `SELECT 1`, not a container-local
/// probe. Built from a parsed [`Config`] (not the bare `Client::connect`
/// convenience) specifically so an explicit, short `connect_timeout` and a
/// bounded statement timeout apply to every attempt in the 60s poll loop
/// this backs, instead of inheriting the driver's unbounded defaults.
fn database_accepts_trivial_query(database_url: &str) -> bool {
    let Ok(mut config) = database_url.parse::<Config>() else {
        return false;
    };
    let statement_timeout_millis: u64 =
        u64::try_from(READINESS_STATEMENT_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    config.connect_timeout(READINESS_CONNECT_TIMEOUT);
    config.tcp_user_timeout(READINESS_STATEMENT_TIMEOUT);
    config.options(&format!("-c statement_timeout={statement_timeout_millis}"));
    let Ok(mut client) = config.connect(NoTls) else {
        return false;
    };
    let Ok(row) = client.query_one("SELECT 1", &[]) else {
        return false;
    };
    matches!(row.try_get::<_, i32>(0), Ok(1))
}

fn wait_until_ready(container_id: &ContainerId, database_url: &str) -> io::Result<()> {
    let deadline = Instant::now() + CONTAINER_READY_TIMEOUT;
    loop {
        if database_accepts_trivial_query(database_url) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "container {} did not accept a fresh PostgreSQL connection and trivial query \
                 within {CONTAINER_READY_TIMEOUT:?}",
                container_id.as_str()
            )));
        }
        thread::sleep(CONTAINER_READY_POLL_INTERVAL);
    }
}

/// Panic-safe guard around one Docker container's SIGKILL / start /
/// readiness-wait lifecycle for the crash-recovery scenario.
///
/// The intended flow is: construct the guard with the container ID and the
/// same live database URL the test itself uses, call [`Self::sigkill`], do
/// the minimal post-crash bookkeeping the scenario needs, then call
/// [`Self::restart_and_wait_ready`] before dropping the guard. If anything
/// between those calls panics, [`Drop`] still makes a best-effort attempt to
/// restart the container and wait for readiness, so a failing assertion
/// never leaves a dead database-service container for the next test run. The
/// [`Drop`] path only logs to stderr on failure rather than panicking itself
/// (a panic during unwind aborts the process instead of reporting the
/// original failure).
pub struct DockerCrashGuard {
    container_id: ContainerId,
    database_url: String,
    killed: bool,
    restarted: bool,
}

impl DockerCrashGuard {
    pub fn new(container_id: ContainerId, database_url: String) -> Self {
        Self {
            container_id,
            database_url,
            killed: false,
            restarted: false,
        }
    }

    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// Sends `docker kill --signal=KILL` to the guarded container via argv.
    /// Panics if the invocation itself fails or `docker` reports non-zero,
    /// since a scenario that cannot even confirm the kill was dispatched
    /// cannot claim anything about the recovery that follows.
    pub fn sigkill(&mut self) {
        docker_kill(&self.container_id).unwrap_or_else(|error| {
            panic!(
                "docker kill --signal=KILL {} failed: {error}",
                self.container_id.as_str()
            )
        });
        self.killed = true;
    }

    /// `docker start`s the guarded container, then boundedly waits for a
    /// fresh client connection plus a trivial query against
    /// [`Self::new`]'s `database_url` to succeed. Panics on failure or
    /// timeout.
    pub fn restart_and_wait_ready(&mut self) {
        docker_start(&self.container_id).unwrap_or_else(|error| {
            panic!(
                "docker start {} failed: {error}",
                self.container_id.as_str()
            )
        });
        wait_until_ready(&self.container_id, &self.database_url).unwrap_or_else(|error| {
            panic!(
                "container {} did not become ready: {error}",
                self.container_id.as_str()
            )
        });
        self.restarted = true;
    }
}

impl Drop for DockerCrashGuard {
    fn drop(&mut self) {
        if !self.killed || self.restarted {
            return;
        }
        eprintln!(
            "DockerCrashGuard: container {} was SIGKILLed but never explicitly restarted \
             (likely a panicking crash test); attempting a best-effort restart so it is not \
             left dead",
            self.container_id.as_str()
        );
        if let Err(error) = docker_start(&self.container_id) {
            eprintln!("DockerCrashGuard: docker start failed: {error}");
            return;
        }
        if let Err(error) = wait_until_ready(&self.container_id, &self.database_url) {
            eprintln!("DockerCrashGuard: container did not become ready: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_id_accepts_min_and_max_length_lowercase_hex() {
        assert!(ContainerId::parse(&"a".repeat(CONTAINER_ID_MIN_LEN)).is_ok());
        assert!(ContainerId::parse(&"f".repeat(CONTAINER_ID_MAX_LEN)).is_ok());
    }

    #[test]
    fn container_id_rejects_too_short_and_too_long() {
        assert_eq!(
            ContainerId::parse(&"a".repeat(CONTAINER_ID_MIN_LEN - 1)),
            Err(ContainerIdError::InvalidLength(CONTAINER_ID_MIN_LEN - 1))
        );
        assert_eq!(
            ContainerId::parse(&"a".repeat(CONTAINER_ID_MAX_LEN + 1)),
            Err(ContainerIdError::InvalidLength(CONTAINER_ID_MAX_LEN + 1))
        );
    }

    #[test]
    fn container_id_rejects_uppercase_and_non_hex() {
        assert_eq!(
            ContainerId::parse(&"A".repeat(CONTAINER_ID_MIN_LEN)),
            Err(ContainerIdError::InvalidCharacters)
        );
        assert_eq!(
            ContainerId::parse(&"g".repeat(CONTAINER_ID_MIN_LEN)),
            Err(ContainerIdError::InvalidCharacters)
        );
    }

    #[test]
    fn container_id_as_str_roundtrips() {
        let raw = "0123456789ab";
        let id = ContainerId::parse(raw).unwrap();
        assert_eq!(id.as_str(), raw);
    }

    #[test]
    fn lock_owner_round_trips_through_file_contents() {
        let owner = LockOwner {
            pid: 4242,
            nonce: 99,
        };
        assert_eq!(LockOwner::parse(&owner.to_file_contents()), Some(owner));
    }

    #[test]
    fn lock_owner_rejects_malformed_contents() {
        assert_eq!(LockOwner::parse(""), None);
        assert_eq!(LockOwner::parse("not-a-pid:0"), None);
        assert_eq!(LockOwner::parse("1:not-a-nonce"), None);
        assert_eq!(LockOwner::parse("12345"), None);
    }

    #[test]
    fn lock_owner_current_calls_are_distinct() {
        assert_ne!(LockOwner::current(), LockOwner::current());
    }

    #[test]
    fn crash_required_flag_parses_only_exact_one() {
        assert!(!parse_crash_required_flag(None));
        assert!(parse_crash_required_flag(Some(OsString::from("1"))));
    }

    #[test]
    #[should_panic(expected = "must be exactly")]
    fn crash_required_flag_rejects_other_values() {
        parse_crash_required_flag(Some(OsString::from("true")));
    }

    #[test]
    fn resolve_crash_scenario_skips_when_both_absent() {
        assert!(matches!(
            resolve_crash_scenario_from(false, None, None),
            CrashScenario::Skip
        ));
    }

    #[test]
    #[should_panic(expected = "neither")]
    fn resolve_crash_scenario_fails_when_required_but_both_absent() {
        resolve_crash_scenario_from(false, Some(OsString::from("1")), None);
    }

    #[test]
    #[should_panic(expected = "partial")]
    fn resolve_crash_scenario_fails_on_partial_configuration_url_only() {
        resolve_crash_scenario_from(true, None, None);
    }

    #[test]
    #[should_panic(expected = "partial")]
    fn resolve_crash_scenario_fails_on_partial_configuration_container_only() {
        resolve_crash_scenario_from(
            false,
            None,
            Some(OsString::from("a".repeat(CONTAINER_ID_MIN_LEN))),
        );
    }

    #[test]
    fn resolve_crash_scenario_runs_with_valid_full_configuration() {
        let raw_id = "a".repeat(CONTAINER_ID_MIN_LEN);
        match resolve_crash_scenario_from(true, None, Some(OsString::from(raw_id.clone()))) {
            CrashScenario::Run(id) => assert_eq!(id.as_str(), raw_id),
            CrashScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    #[should_panic(expected = "is invalid")]
    fn resolve_crash_scenario_fails_on_invalid_container_id() {
        resolve_crash_scenario_from(true, None, Some(OsString::from("not-hex")));
    }
}
