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
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
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
/// before giving up. Every live PostgreSQL integration-test binary serializes
/// on this lock because `cargo test` may run the shared-schema conformance,
/// SIGKILL, data-full, WAL-full, connection-exhaustion, and backup-restore
/// scenarios as separate concurrent processes. Each holder completes its own
/// bounded database/container work before releasing the next waiter. CI bounds
/// the whole job at 20 minutes; 600 seconds (10 minutes) keeps an abandoned or
/// genuinely stuck lock well inside that outer bound while allowing the normal
/// short scenarios to queue. It is intentionally not the sum of every
/// scenario's individual worst-case timeout: collectively exceeding this wait
/// budget is itself a loud CI failure that requires investigation.
const LIVE_LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(600);

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

/// Shared readiness poll behind [`wait_until_ready`] and
/// [`DisposablePostgresContainer::start`]: a fresh client connection plus a
/// trivial query, bounded by [`CONTAINER_READY_TIMEOUT`]. `label` identifies
/// the container in the timeout error only.
fn wait_for_database_ready(label: &str, database_url: &str) -> io::Result<()> {
    let deadline = Instant::now() + CONTAINER_READY_TIMEOUT;
    loop {
        if database_accepts_trivial_query(database_url) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "{label} did not accept a fresh PostgreSQL connection and trivial query within \
                 {CONTAINER_READY_TIMEOUT:?}"
            )));
        }
        thread::sleep(CONTAINER_READY_POLL_INTERVAL);
    }
}

fn wait_until_ready(container_id: &ContainerId, database_url: &str) -> io::Result<()> {
    wait_for_database_ready(
        &format!("container {}", container_id.as_str()),
        database_url,
    )
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

// --- Disk-full scenario: strict environment parsing -------------------------

/// Environment variable naming the digest-pinned PostgreSQL image the
/// disk-full scenario starts as its own disposable container (never the
/// shared CI service container). Must parse as [`PinnedImage`].
pub const DISK_FULL_IMAGE_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_IMAGE";

/// Environment variable that, when set to exactly `"1"`, forbids the
/// disk-full scenario from silently skipping.
pub const DISK_FULL_REQUIRED_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_REQUIRED";

const DIGEST_HEX_LEN: usize = 64;

/// A `<name>@sha256:<64 lowercase hex>` Docker image reference. Rejects a
/// floating tag, so this scenario (and CI) can never silently drift to a
/// different image than the one it was proven against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedImage(String);

impl PinnedImage {
    pub fn parse(raw: &str) -> Result<Self, PinnedImageError> {
        let Some((name, digest)) = raw.split_once('@') else {
            return Err(PinnedImageError::MissingDigest);
        };
        if name.is_empty() {
            return Err(PinnedImageError::EmptyName);
        }
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return Err(PinnedImageError::MissingSha256Prefix);
        };
        if hex.len() != DIGEST_HEX_LEN
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PinnedImageError::InvalidDigestHex);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinnedImageError {
    MissingDigest,
    EmptyName,
    MissingSha256Prefix,
    InvalidDigestHex,
}

impl fmt::Display for PinnedImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDigest => {
                write!(formatter, "image reference is missing an @sha256 digest")
            }
            Self::EmptyName => write!(formatter, "image reference has an empty name"),
            Self::MissingSha256Prefix => {
                write!(formatter, "image digest must start with sha256:")
            }
            Self::InvalidDigestHex => write!(
                formatter,
                "image digest must be exactly {DIGEST_HEX_LEN} lowercase hex characters"
            ),
        }
    }
}

impl std::error::Error for PinnedImageError {}

/// Outcome of strictly resolving whether the disk-full ENOSPC scenario runs
/// in this process. Unlike [`CrashScenario`], this scenario needs no
/// pre-existing live database URL: it starts and owns its own disposable
/// container, so only the pinned image and the required flag are consulted.
#[derive(Debug)]
pub enum DiskFullScenario {
    /// No disk-full image is configured: the scenario is skipped.
    Skip,
    /// Run the scenario against a disposable container started from this
    /// pinned image.
    Run(PinnedImage),
}

/// Strictly resolves [`DiskFullScenario`] from [`DISK_FULL_IMAGE_ENV`] and
/// [`DISK_FULL_REQUIRED_ENV`]. Only "both absent" skips: [`DISK_FULL_REQUIRED_ENV`]
/// set to anything other than exactly `"1"` fails, `"1"` with no image
/// configured fails instead of skipping, and a configured but malformed image
/// reference fails. An image configured without the required flag still
/// runs, since CI always sets both together but a local run should not have
/// to.
pub fn resolve_disk_full_scenario() -> DiskFullScenario {
    resolve_disk_full_scenario_from(
        env::var_os(DISK_FULL_REQUIRED_ENV),
        env::var_os(DISK_FULL_IMAGE_ENV),
    )
}

/// Pure decision logic behind [`resolve_disk_full_scenario`]; see that
/// function's doc comment for the exact rules. Split out for unit tests for
/// the same reason as [`resolve_crash_scenario_from`].
fn resolve_disk_full_scenario_from(
    required_raw: Option<OsString>,
    image_raw: Option<OsString>,
) -> DiskFullScenario {
    let required = parse_disk_full_required_flag(required_raw);
    match image_raw {
        None => {
            if required {
                panic!(
                    "{DISK_FULL_REQUIRED_ENV} is set but {DISK_FULL_IMAGE_ENV} is not configured"
                );
            }
            DiskFullScenario::Skip
        }
        Some(raw) => DiskFullScenario::Run(parse_pinned_image(raw)),
    }
}

fn parse_pinned_image(raw: OsString) -> PinnedImage {
    let text = raw
        .to_str()
        .unwrap_or_else(|| panic!("{DISK_FULL_IMAGE_ENV} must be valid UTF-8"));
    PinnedImage::parse(text)
        .unwrap_or_else(|error| panic!("{DISK_FULL_IMAGE_ENV} is invalid: {error}"))
}

fn parse_disk_full_required_flag(raw: Option<OsString>) -> bool {
    match raw {
        None => false,
        Some(raw) => {
            let text = raw
                .to_str()
                .unwrap_or_else(|| panic!("{DISK_FULL_REQUIRED_ENV} must be valid UTF-8"));
            match text {
                "1" => true,
                other => {
                    panic!("{DISK_FULL_REQUIRED_ENV} must be exactly \"1\" when set, got {other:?}")
                }
            }
        }
    }
}

// --- Disk-full scenario: bounded Docker output and pure output parsers -----

/// Maximum bytes read back from a bounded `docker` invocation's stdout/stderr
/// by [`run_docker_command_bounded_output`]. Every caller's expected output
/// (a container ID, a port mapping, a `df`/`stat` line) is at most a few
/// hundred bytes; this is generous headroom against a misbehaving command,
/// not a measured budget. A call whose output exceeds it fails loudly instead
/// of silently truncating.
const DOCKER_COMMAND_OUTPUT_MAX_BYTES: u64 = 64 * 1024;

static TEMP_OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unique_temp_file_path(label: &str, stream: &str) -> PathBuf {
    let sanitized_label: String = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    let sequence: u64 = TEMP_OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!(
        "sunrise-edge-disk-full-{sanitized_label}-{stream}-{}-{nanos}-{sequence}.log",
        std::process::id(),
    ))
}

fn read_capped_file(path: &Path, max_bytes: u64) -> io::Result<String> {
    let length = fs::metadata(path)?.len();
    if length > max_bytes {
        return Err(io::Error::other(format!(
            "{} exceeded the {max_bytes}-byte bounded output cap ({length} bytes)",
            path.display()
        )));
    }
    String::from_utf8(fs::read(path)?)
        .map_err(|error| io::Error::other(format!("output was not valid UTF-8: {error}")))
}

/// Runs `command` the same bounded way as [`run_docker_command_bounded`], but
/// additionally captures and returns its stdout. Output is redirected to a
/// capped temporary file rather than a pipe: a piped child that filled the
/// pipe buffer before this loop drained it would deadlock the poll loop
/// entirely. Both the stdout and stderr files are removed before returning,
/// whether or not the command succeeded, and a failing exit status carries
/// the captured stderr for diagnosis.
fn run_docker_command_bounded_output(command: Command, label: &str) -> io::Result<String> {
    run_docker_command_bounded_output_capped(command, label, DOCKER_COMMAND_OUTPUT_MAX_BYTES)
}

/// Same as [`run_docker_command_bounded_output`], but with an explicit output
/// cap instead of [`DOCKER_COMMAND_OUTPUT_MAX_BYTES`]. The backup-restore
/// scenario's `pg_dump` output is a bounded logical-schema-plus-small-payload
/// dump, larger than every other scenario's few-hundred-byte command output,
/// so it needs its own, still-bounded, still-explicit cap rather than
/// silently reusing the generic one.
fn run_docker_command_bounded_output_capped(
    command: Command,
    label: &str,
    max_bytes: u64,
) -> io::Result<String> {
    run_docker_command_bounded_output_capped_with_stdin(command, label, None, max_bytes)
}

/// Same as [`run_docker_command_bounded_output_capped`], but first writes
/// `stdin_bytes` to the child's stdin and closes it before entering the same
/// bounded poll loop. Used only to hand a small, fully Rust-controlled
/// in-memory config file to a container-side `tee` via direct argv, with no
/// shell and no host bind mount involved on either side. The write happens
/// before the poll loop, not concurrently with it: every caller's
/// `stdin_bytes` is small enough (a few hundred bytes, well under a pipe
/// buffer) that the write cannot block on the child draining its own stdout,
/// so this cannot deadlock the way an unbounded interleaved read/write could.
fn run_docker_command_bounded_output_with_stdin(
    command: Command,
    label: &str,
    stdin_bytes: &[u8],
    max_bytes: u64,
) -> io::Result<String> {
    run_docker_command_bounded_output_capped_with_stdin(
        command,
        label,
        Some(stdin_bytes),
        max_bytes,
    )
}

fn run_docker_command_bounded_output_capped_with_stdin(
    mut command: Command,
    label: &str,
    stdin_bytes: Option<&[u8]>,
    max_bytes: u64,
) -> io::Result<String> {
    let stdout_path = unique_temp_file_path(label, "stdout");
    let stderr_path = unique_temp_file_path(label, "stderr");
    let stdout_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout_path)?;
    let stderr_file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_path)
    {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            return Err(error);
        }
    };
    command.stdout(stdout_file);
    command.stderr(stderr_file);
    if stdin_bytes.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child: Child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            return Err(error);
        }
    };
    if let Some(bytes) = stdin_bytes {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("failed to open piped stdin for bounded command"))?;
        if let Err(error) = stdin.write_all(bytes) {
            drop(stdin);
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            return Err(error);
        }
        // Dropping the handle closes the write end, signaling EOF to the
        // child (`tee` only exits once it has seen EOF on stdin).
        drop(stdin);
    }
    let deadline = Instant::now() + DOCKER_COMMAND_TIMEOUT;
    let status_result: io::Result<()> = loop {
        let stdout_len: u64 = fs::metadata(&stdout_path)
            .map(|value| value.len())
            .unwrap_or(0);
        let stderr_len: u64 = fs::metadata(&stderr_path)
            .map(|value| value.len())
            .unwrap_or(0);
        if stdout_len > max_bytes || stderr_len > max_bytes {
            let _ = child.kill();
            let _ = child.wait();
            break Err(io::Error::other(format!(
                "{label} exceeded the {max_bytes}-byte output cap and was killed"
            )));
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(status)) => break Err(docker_exit_error(label, status)),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break Err(io::Error::other(format!(
                "{label} did not exit within {DOCKER_COMMAND_TIMEOUT:?} and was killed"
            )));
        }
        thread::sleep(DOCKER_COMMAND_POLL_INTERVAL);
    };
    let stdout_result = read_capped_file(&stdout_path, max_bytes);
    let stderr_result = read_capped_file(&stderr_path, max_bytes);
    let _ = fs::remove_file(&stdout_path);
    let _ = fs::remove_file(&stderr_path);
    status_result.map_err(|error| {
        let stderr_text = stderr_result.unwrap_or_default();
        io::Error::other(format!("{error}; stderr: {stderr_text}"))
    })?;
    stdout_result
}

/// Parses `docker port <id> 5432/tcp` output into the published host port.
/// Requires exactly one non-empty line bound to `127.0.0.1`; rejects a
/// `0.0.0.0` or `[::]` wildcard binding, since this scenario's readiness and
/// fault probes must reach the exact container it started, not whatever else
/// might be listening on every interface.
pub fn parse_published_port(output: &str) -> u16 {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let line = lines
        .next()
        .unwrap_or_else(|| panic!("docker port produced no output"));
    if lines.next().is_some() {
        panic!("docker port produced more than one published mapping: {output:?}");
    }
    let port_text = line
        .strip_prefix("127.0.0.1:")
        .unwrap_or_else(|| panic!("docker port did not bind to 127.0.0.1 (got {line:?})"));
    port_text
        .parse()
        .ok()
        .filter(|port: &u16| *port != 0)
        .unwrap_or_else(|| panic!("docker port produced an invalid port: {port_text:?}"))
}

/// Parses `df -P -k <path>` output into `(total_kib, available_kib)`. POSIX
/// `-P` guarantees one record per line, so the second line is always the
/// complete data row regardless of device-name length.
pub fn parse_df_kib(output: &str) -> (u64, u64) {
    let mut lines = output.lines();
    lines
        .next()
        .unwrap_or_else(|| panic!("df -P -k produced no header line"));
    let data_line = lines
        .next()
        .unwrap_or_else(|| panic!("df -P -k produced no data line"));
    let columns: Vec<&str> = data_line.split_whitespace().collect();
    if columns.len() < 4 {
        panic!("df -P -k data line has too few columns: {data_line:?}");
    }
    let total = columns[1]
        .parse()
        .unwrap_or_else(|_| panic!("df -P -k total column is not numeric: {:?}", columns[1]));
    let available = columns[3]
        .parse()
        .unwrap_or_else(|_| panic!("df -P -k available column is not numeric: {:?}", columns[3]));
    (total, available)
}

/// Parses `stat -c %d <path>` output into a raw device number.
pub fn parse_device_id(output: &str) -> u64 {
    output
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("stat -c %d produced a non-numeric device id: {output:?}"))
}

/// Process- and call-unique counter mixed into [`random_hex_token`]. Not a
/// cryptographic RNG: these tokens only need to avoid colliding with another
/// concurrent or prior disposable container/marker, never to resist an
/// adversary, since the whole container is destroyed at the end of the test
/// that starts it.
static RANDOM_TOKEN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn random_hex_token(hex_len: usize) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    let sequence = RANDOM_TOKEN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut state = nanos ^ u128::from(std::process::id()) ^ u128::from(sequence);
    let mut hex = String::with_capacity(hex_len);
    while hex.len() < hex_len {
        hex.push_str(&format!("{state:032x}"));
        state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    }
    hex.truncate(hex_len);
    hex
}

/// Returns a test-only secret sourced from the operating system CSPRNG.
/// Sunrise Edge treats Linux and macOS as first-class development hosts; both
/// expose `/dev/urandom`. Unlike [`random_hex_token`], this value protects the
/// disposable PostgreSQL superuser while its random port is published on the
/// host loopback interface, so collision-only entropy is not sufficient.
fn os_random_secret_hex(byte_len: usize) -> io::Result<String> {
    let mut random_bytes: Vec<u8> = vec![0_u8; byte_len];
    let mut random_source: fs::File = fs::File::open("/dev/urandom")?;
    random_source.read_exact(&mut random_bytes)?;
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let capacity: usize = byte_len
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("random secret hex length overflow"))?;
    let mut secret: String = String::with_capacity(capacity);
    for byte in random_bytes {
        secret.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        secret.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    Ok(secret)
}

// --- Disk-full scenario: disposable container guard -------------------------

/// Size cap, in bytes, of the tmpfs holding `PGDATA`/`pg_wal`/`pg_xact`. Large
/// enough for `initdb` plus the configured 64 MiB WAL ceiling with headroom;
/// this filesystem is never intentionally filled.
const PGDATA_TMPFS_BYTES: u64 = 512 * 1024 * 1024;

/// Size cap, in bytes, of the tmpfs holding the fault tablespace. This is the
/// only filesystem the scenario fills.
const BOUNDED_TMPFS_BYTES: u64 = 64 * 1024 * 1024;

/// A disposable, RAM-backed PostgreSQL container for the disk-full scenario.
/// Every mount is tmpfs with an explicit size cap so the fault the test
/// injects can never grow the host's real filesystem; see
/// `tests/postgres_disk_full.rs` for the exact scenario this backs.
///
/// Owns the whole container lifecycle. [`Drop`] force-removes the container
/// and never panics: on failure it only `eprintln!`s the container ID and its
/// `sunrise-edge-test=disk-full` label so a human can find and remove a
/// leaked container, mirroring [`LiveTestLock`]'s abandoned-resource
/// philosophy.
pub struct DisposablePostgresContainer {
    container_id: ContainerId,
    published_port: u16,
    postgres_password: String,
}

impl DisposablePostgresContainer {
    /// Starts a fresh disposable container from `image` and waits for a
    /// fresh client connection plus a trivial query to succeed against its
    /// default `postgres` database. Panics on any failure: a scenario that
    /// cannot even start its own disposable container proves nothing.
    pub fn start(image: &PinnedImage) -> Self {
        let postgres_password: String = os_random_secret_hex(32).unwrap_or_else(|error| {
            panic!("failed to read PostgreSQL test password from OS randomness: {error}")
        });
        let container_name = format!(
            "sunrise-edge-disk-full-{}-{}",
            std::process::id(),
            random_hex_token(16)
        );
        let pgdata_mount =
            format!("type=tmpfs,destination=/var/lib/postgresql,tmpfs-size={PGDATA_TMPFS_BYTES}");
        let bounded_mount = format!(
            "type=tmpfs,destination=/bounded,tmpfs-size={BOUNDED_TMPFS_BYTES},tmpfs-mode=0777"
        );
        let password_env = format!("POSTGRES_PASSWORD={postgres_password}");
        let run_output_result = run_docker_command_bounded_output(
            docker_argv_command(&[
                "run",
                "--detach",
                "--name",
                &container_name,
                "--label",
                "sunrise-edge-test=disk-full",
                "--publish",
                "127.0.0.1::5432",
                "--memory",
                "1g",
                "--memory-swap",
                "1g",
                "--pids-limit",
                "512",
                "--mount",
                &pgdata_mount,
                "--mount",
                &bounded_mount,
                "--env",
                &password_env,
                "--env",
                "POSTGRES_DB=postgres",
                "--",
                image.as_str(),
                "-c",
                "max_wal_size=64MB",
                "-c",
                "min_wal_size=32MB",
            ]),
            "docker run (disk-full container)",
        );
        let run_output = run_output_result.unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after failed run",
            )
            .err();
            panic!(
                "docker run (disk-full container) failed: {error}; cleanup by exact generated name returned {cleanup_error:?}"
            )
        });
        let container_id = ContainerId::parse(run_output.trim()).unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after invalid run output",
            )
            .err();
            panic!(
                "docker run produced an invalid container id {run_output:?}: {error}; cleanup by exact generated name returned {cleanup_error:?}"
            )
        });
        let mut container = Self {
            container_id,
            published_port: 0,
            postgres_password,
        };
        let port_output = run_docker_command_bounded_output(
            docker_argv_command(&["port", container.container_id.as_str(), "5432/tcp"]),
            "docker port (disk-full container)",
        )
        .unwrap_or_else(|error| panic!("docker port failed: {error}"));
        container.published_port = parse_published_port(&port_output);
        wait_for_database_ready(
            &format!("disk-full container {}", container.container_id.as_str()),
            &container.url("postgres"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        container
    }

    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// Builds the `postgresql://` URL for `database` against this
    /// container's published port and generated password.
    pub fn url(&self, database: &str) -> String {
        format!(
            "postgresql://postgres:{}@127.0.0.1:{}/{database}",
            self.postgres_password, self.published_port
        )
    }

    /// Runs `docker exec --user postgres <id> <args>`, bounded, with capped
    /// output. Every fault-preparation step this scenario needs (the
    /// tablespace directory, the identity marker, the `df`/`stat` probes, and
    /// the filler write/removal) is an action the unprivileged `postgres`
    /// server user can perform, so no exec in this scenario ever needs
    /// `--user root`.
    pub fn exec(&self, args: &[&str]) -> io::Result<String> {
        let mut full_args: Vec<&str> = vec![
            "exec",
            "--user",
            "postgres",
            "--",
            self.container_id.as_str(),
        ];
        full_args.extend_from_slice(args);
        run_docker_command_bounded_output(docker_argv_command(&full_args), "docker exec")
    }
}

impl Drop for DisposablePostgresContainer {
    fn drop(&mut self) {
        let result = run_docker_command_bounded(
            docker_argv_command(&["rm", "--force", "--volumes", self.container_id.as_str()]),
            "docker rm (disk-full container)",
        );
        if let Err(error) = result {
            eprintln!(
                "DisposablePostgresContainer: failed to remove container {} (label \
                 sunrise-edge-test=disk-full): {error}; remove it by hand",
                self.container_id.as_str()
            );
        }
    }
}

// --- WAL-full scenario: strict environment parsing --------------------------

/// Environment variable naming the digest-pinned PostgreSQL image the
/// bounded WAL-exhaustion scenario starts as its own disposable container
/// (never the shared CI service container, and never the disk-full
/// scenario's own container). Must parse as [`PinnedImage`].
pub const WAL_FULL_IMAGE_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_IMAGE";

/// Environment variable that, when set to exactly `"1"`, forbids the
/// WAL-exhaustion scenario from silently skipping.
pub const WAL_FULL_REQUIRED_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_REQUIRED";

/// Outcome of strictly resolving whether the bounded WAL-exhaustion scenario
/// runs in this process. Same shape and rules as [`DiskFullScenario`]: only
/// "both absent" skips.
#[derive(Debug)]
pub enum WalFullScenario {
    /// No WAL-full image is configured: the scenario is skipped.
    Skip,
    /// Run the scenario against a disposable container started from this
    /// pinned image.
    Run(PinnedImage),
}

/// Strictly resolves [`WalFullScenario`] from [`WAL_FULL_IMAGE_ENV`] and
/// [`WAL_FULL_REQUIRED_ENV`]; see [`resolve_disk_full_scenario`] for the exact
/// rules this mirrors.
pub fn resolve_wal_full_scenario() -> WalFullScenario {
    resolve_wal_full_scenario_from(
        env::var_os(WAL_FULL_REQUIRED_ENV),
        env::var_os(WAL_FULL_IMAGE_ENV),
    )
}

fn resolve_wal_full_scenario_from(
    required_raw: Option<OsString>,
    image_raw: Option<OsString>,
) -> WalFullScenario {
    let required = parse_wal_full_required_flag(required_raw);
    match image_raw {
        None => {
            if required {
                panic!("{WAL_FULL_REQUIRED_ENV} is set but {WAL_FULL_IMAGE_ENV} is not configured");
            }
            WalFullScenario::Skip
        }
        Some(raw) => WalFullScenario::Run(parse_wal_full_pinned_image(raw)),
    }
}

fn parse_wal_full_pinned_image(raw: OsString) -> PinnedImage {
    let text = raw
        .to_str()
        .unwrap_or_else(|| panic!("{WAL_FULL_IMAGE_ENV} must be valid UTF-8"));
    PinnedImage::parse(text)
        .unwrap_or_else(|error| panic!("{WAL_FULL_IMAGE_ENV} is invalid: {error}"))
}

fn parse_wal_full_required_flag(raw: Option<OsString>) -> bool {
    match raw {
        None => false,
        Some(raw) => {
            let text = raw
                .to_str()
                .unwrap_or_else(|| panic!("{WAL_FULL_REQUIRED_ENV} must be valid UTF-8"));
            match text {
                "1" => true,
                other => {
                    panic!("{WAL_FULL_REQUIRED_ENV} must be exactly \"1\" when set, got {other:?}")
                }
            }
        }
    }
}

// --- WAL-full scenario: disposable container with a separate small WAL fs --

/// Size cap, in bytes, of the tmpfs holding `PGDATA` excluding `pg_wal`. Same
/// magnitude as the disk-full scenario's unfilled PGDATA cap; this filesystem
/// is never intentionally filled.
const WAL_FULL_PGDATA_TMPFS_BYTES: u64 = 512 * 1024 * 1024;

/// Size cap, in bytes, of the tmpfs holding only `pg_wal`. This is the only
/// filesystem this scenario fills. Independent of the disk-full scenario's
/// own bounded-tablespace cap even though both happen to be 64 MiB.
const WAL_FULL_WAL_TMPFS_BYTES: u64 = 64 * 1024 * 1024;

/// Absolute path of the dedicated WAL tmpfs mount inside the container.
pub const WAL_FULL_WAL_MOUNT: &str = "/pgwal";

/// Absolute path `POSTGRES_INITDB_WALDIR` points `initdb --waldir` at: the
/// exact target the live `pg_wal` symlink must resolve to, inside
/// [`WAL_FULL_WAL_MOUNT`].
pub const WAL_FULL_WAL_DIRECTORY: &str = "/pgwal/wal";

/// `initdb` argument fixing a 2 MiB WAL segment size for this scenario's
/// cluster, set once at `initdb` time (unlike [`WAL_FULL_POSTGRES_EXTRA_OPTIONS`],
/// this cannot be changed later by `pg_ctl start`). PostgreSQL enforces
/// `min_wal_size >= 2 * wal_segment_size`, so the default 16 MiB segment size
/// would force `min_wal_size` (and therefore the number of already-allocated
/// segments live evidence shows PostgreSQL keeps recycled and ready after a
/// crash/recovery cycle) up to 32 MiB — uncomfortably close to
/// `runtime::MAX_STATE_VALUE_BYTES` (32 MiB), the largest single state value
/// this scenario's adapter-driven fault (see `tests/postgres_wal_full.rs`
/// cycle 2) can ever present. A 2 MiB segment size instead lets
/// [`WAL_FULL_POSTGRES_EXTRA_OPTIONS`] hold `min_wal_size` down at 4 MiB, so
/// that same payload keeps a wide, live-verified margin over however many
/// segments happen to already be recycled and ready, on a fresh boot or
/// after any number of prior crash/recovery cycles.
const WAL_FULL_INITDB_ARGS_ENV: &str = "POSTGRES_INITDB_ARGS=--wal-segsize=2";

/// Extra postgres server options this scenario always launches with, both on
/// initial start (via the entrypoint override below) and on every later
/// in-place `pg_ctl start` restart, so idle WAL usage stays a small, constant
/// fraction of [`WAL_FULL_WAL_TMPFS_BYTES`] instead of drifting between the
/// initial boot and a later restart. `max_wal_size` is deliberately left
/// large (64 MiB, the whole WAL mount) rather than also shrunk: live evidence
/// shows that shrinking it alongside the segment size makes the background
/// checkpointer recycle old segments aggressively enough, mid-write, to
/// dodge the fault entirely, since checkpointing is triggered as WAL usage
/// approaches `max_wal_size`, not `min_wal_size`.
const WAL_FULL_POSTGRES_EXTRA_OPTIONS: &str = "-c max_wal_size=64MB -c min_wal_size=4MB";

/// Bound on how long [`WalFullPostgresContainer::wait_until_postgres_down`]
/// waits for `pg_ctl status` to report the server is no longer running.
const WAL_FULL_POSTGRES_DOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for [`WAL_FULL_POSTGRES_DOWN_TIMEOUT`] to elapse.
const WAL_FULL_POSTGRES_DOWN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A disposable, RAM-backed PostgreSQL container for the bounded
/// WAL-exhaustion scenario. `PGDATA` (excluding `pg_wal`) lives on a large,
/// never-filled tmpfs; `pg_wal` is relocated by `initdb --waldir` onto a
/// separate, much smaller tmpfs mounted at [`WAL_FULL_WAL_MOUNT`], which is
/// the only filesystem this scenario fills.
///
/// Unlike [`DisposablePostgresContainer`], this container overrides the
/// image's entrypoint with a small supervisor shell script that backgrounds
/// `docker-entrypoint.sh postgres` and then `sleep infinity`s after it exits.
/// A real WAL write failure is fatal to the whole PostgreSQL server process
/// (see `tests/postgres_wal_full.rs` for why), which would otherwise take the
/// container's PID 1 down with it; `docker start`ing a stopped container
/// recreates every tmpfs mount empty, destroying exactly the durable evidence
/// (committed rows, the still-full WAL filesystem) this scenario exists to
/// preserve. The supervisor keeps the container itself alive across that
/// crash so [`Self::restart_postgres_in_place`] can bring PostgreSQL back up
/// with `pg_ctl start` on the same, never-torn-down tmpfs mounts.
///
/// [`Drop`] force-removes the container and never panics: on failure it only
/// `eprintln!`s the container ID and its `sunrise-edge-test=wal-full` label
/// so a human can find and remove a leaked container.
pub struct WalFullPostgresContainer {
    container_id: ContainerId,
    published_port: u16,
    postgres_password: String,
}

impl WalFullPostgresContainer {
    /// Starts a fresh disposable container from `image` and waits for a
    /// fresh client connection plus a trivial query to succeed against its
    /// default `postgres` database. Panics on any failure: a scenario that
    /// cannot even start its own disposable container proves nothing.
    pub fn start(image: &PinnedImage) -> Self {
        let postgres_password: String = os_random_secret_hex(32).unwrap_or_else(|error| {
            panic!("failed to read PostgreSQL test password from OS randomness: {error}")
        });
        let container_name = format!(
            "sunrise-edge-wal-full-{}-{}",
            std::process::id(),
            random_hex_token(16)
        );
        let pgdata_mount = format!(
            "type=tmpfs,destination=/var/lib/postgresql,tmpfs-size={WAL_FULL_PGDATA_TMPFS_BYTES}"
        );
        let wal_mount = format!(
            "type=tmpfs,destination={WAL_FULL_WAL_MOUNT},tmpfs-size={WAL_FULL_WAL_TMPFS_BYTES},tmpfs-mode=0777"
        );
        let password_env = format!("POSTGRES_PASSWORD={postgres_password}");
        let waldir_env = format!("POSTGRES_INITDB_WALDIR={WAL_FULL_WAL_DIRECTORY}");
        // The only place this module hands a string to a shell: the
        // container's own `sh`, overriding its entrypoint, never the host
        // shell. The script is a fixed constant with no interpolated
        // caller-controlled data.
        let supervisor_script = format!(
            "/usr/local/bin/docker-entrypoint.sh postgres {WAL_FULL_POSTGRES_EXTRA_OPTIONS} & wait $!; sleep infinity"
        );
        let run_output_result = run_docker_command_bounded_output(
            docker_argv_command(&[
                "run",
                "--detach",
                "--name",
                &container_name,
                "--label",
                "sunrise-edge-test=wal-full",
                "--entrypoint",
                "sh",
                "--publish",
                "127.0.0.1::5432",
                "--memory",
                "1g",
                "--memory-swap",
                "1g",
                "--pids-limit",
                "512",
                "--mount",
                &pgdata_mount,
                "--mount",
                &wal_mount,
                "--env",
                &password_env,
                "--env",
                "POSTGRES_DB=postgres",
                "--env",
                &waldir_env,
                "--env",
                WAL_FULL_INITDB_ARGS_ENV,
                "--",
                image.as_str(),
                "-c",
                &supervisor_script,
            ]),
            "docker run (wal-full container)",
        );
        let run_output = run_output_result.unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after failed run",
            )
            .err();
            panic!(
                "docker run (wal-full container) failed: {error}; cleanup by exact generated name returned {cleanup_error:?}"
            )
        });
        let container_id = ContainerId::parse(run_output.trim()).unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after invalid run output",
            )
            .err();
            panic!(
                "docker run produced an invalid container id {run_output:?}: {error}; cleanup by exact generated name returned {cleanup_error:?}"
            )
        });
        let mut container = Self {
            container_id,
            published_port: 0,
            postgres_password,
        };
        let port_output = run_docker_command_bounded_output(
            docker_argv_command(&["port", container.container_id.as_str(), "5432/tcp"]),
            "docker port (wal-full container)",
        )
        .unwrap_or_else(|error| panic!("docker port failed: {error}"));
        container.published_port = parse_published_port(&port_output);
        wait_for_database_ready(
            &format!("wal-full container {}", container.container_id.as_str()),
            &container.url("postgres"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        container
    }

    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// Builds the `postgresql://` URL for `database` against this
    /// container's published port and generated password.
    pub fn url(&self, database: &str) -> String {
        format!(
            "postgresql://postgres:{}@127.0.0.1:{}/{database}",
            self.postgres_password, self.published_port
        )
    }

    /// Runs `docker exec --user postgres <id> <args>`, bounded, with capped
    /// output. Every fault-preparation step this scenario needs (the
    /// identity marker, the `df`/`stat`/`readlink` probes, the filler
    /// write/removal, and `pg_ctl status`/`start`) is an action the
    /// unprivileged `postgres` server user can perform.
    pub fn exec(&self, args: &[&str]) -> io::Result<String> {
        let mut full_args: Vec<&str> = vec![
            "exec",
            "--user",
            "postgres",
            "--",
            self.container_id.as_str(),
        ];
        full_args.extend_from_slice(args);
        run_docker_command_bounded_output(docker_argv_command(&full_args), "docker exec")
    }

    /// True while the container's PID 1 (the supervisor script) is still
    /// running, regardless of whether the postgres server process inside it
    /// is up. Used to prove the container/tmpfs mounts survived the WAL
    /// exhaustion fault even though the database process did not.
    pub fn is_running(&self) -> bool {
        let output = run_docker_command_bounded_output(
            docker_argv_command(&[
                "inspect",
                "--format",
                "{{.State.Status}}",
                self.container_id.as_str(),
            ]),
            "docker inspect (wal-full container)",
        )
        .unwrap_or_else(|error| panic!("docker inspect failed: {error}"));
        output.trim() == "running"
    }

    /// True once `pg_ctl status -D pgdata` reports the server is not running
    /// (exit status 3). Any other non-zero exit is treated as an unexpected
    /// failure and panics, since this scenario only ever expects "running" or
    /// "not running" for a `PGDATA` it knows exists.
    fn postgres_is_down(&self, pgdata: &str) -> bool {
        match self.exec(&["pg_ctl", "status", "-D", pgdata]) {
            Ok(_) => false,
            Err(error) => {
                let message = error.to_string();
                if message.contains("exit status: 3") {
                    true
                } else {
                    panic!("unexpected `pg_ctl status -D {pgdata}` failure: {message}");
                }
            }
        }
    }

    /// Boundedly waits for the postgres server process inside this container
    /// to exit after the WAL-exhaustion fault, confirmed via `pg_ctl status`
    /// rather than a fixed sleep. This scenario's fault triggers PostgreSQL's
    /// own internal automatic-crash-recovery attempt, which (with WAL still
    /// full) also fails and brings the whole postmaster down a second time;
    /// polling `pg_ctl status` to a stable "not running" result means this
    /// call never races that internal retry.
    pub fn wait_until_postgres_down(&self, pgdata: &str) {
        let deadline = Instant::now() + WAL_FULL_POSTGRES_DOWN_TIMEOUT;
        loop {
            if self.postgres_is_down(pgdata) {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "postgres did not stop within {WAL_FULL_POSTGRES_DOWN_TIMEOUT:?} after the \
                     WAL-exhaustion fault"
                );
            }
            thread::sleep(WAL_FULL_POSTGRES_DOWN_POLL_INTERVAL);
        }
    }

    /// Restarts postgres in place with `pg_ctl start` inside this same,
    /// still-running container: never `docker start`/`docker kill`, which
    /// would tear down and recreate every tmpfs mount empty. Boundedly waits
    /// for a fresh client connection plus a trivial query against `database`
    /// afterward. Panics on failure or timeout.
    pub fn restart_postgres_in_place(&self, pgdata: &str, database: &str) {
        self.exec(&[
            "pg_ctl",
            "start",
            "-D",
            pgdata,
            "-l",
            "/tmp/sunrise-edge-wal-full-restart.log",
            "-o",
            WAL_FULL_POSTGRES_EXTRA_OPTIONS,
        ])
        .unwrap_or_else(|error| panic!("pg_ctl start -D {pgdata} failed: {error}"));
        wait_for_database_ready(
            &format!(
                "wal-full container {} (post-fault restart)",
                self.container_id.as_str()
            ),
            &self.url(database),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }
}

impl Drop for WalFullPostgresContainer {
    fn drop(&mut self) {
        let result = run_docker_command_bounded(
            docker_argv_command(&["rm", "--force", "--volumes", self.container_id.as_str()]),
            "docker rm (wal-full container)",
        );
        if let Err(error) = result {
            eprintln!(
                "WalFullPostgresContainer: failed to remove container {} (label \
                 sunrise-edge-test=wal-full): {error}; remove it by hand",
                self.container_id.as_str()
            );
        }
    }
}

// --- Connection-exhaustion scenario: strict environment parsing -------------

/// Environment variable naming the digest-pinned PostgreSQL image the bounded
/// connection-exhaustion scenario starts as its own disposable container
/// (never the shared CI service container, and never another scenario's own
/// container). Must parse as [`PinnedImage`].
pub const CONNECTION_EXHAUSTION_IMAGE_ENV: &str =
    "SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_IMAGE";

/// Environment variable that, when set to exactly `"1"`, forbids the
/// connection-exhaustion scenario from silently skipping.
pub const CONNECTION_EXHAUSTION_REQUIRED_ENV: &str =
    "SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_REQUIRED";

/// Outcome of strictly resolving whether the bounded connection-exhaustion
/// scenario runs in this process. Same shape and rules as [`DiskFullScenario`]
/// and [`WalFullScenario`]: only "both absent" skips.
#[derive(Debug)]
pub enum ConnectionExhaustionScenario {
    /// No connection-exhaustion image is configured: the scenario is skipped.
    Skip,
    /// Run the scenario against a disposable container started from this
    /// pinned image.
    Run(PinnedImage),
}

/// Strictly resolves [`ConnectionExhaustionScenario`] from
/// [`CONNECTION_EXHAUSTION_IMAGE_ENV`] and [`CONNECTION_EXHAUSTION_REQUIRED_ENV`];
/// see [`resolve_disk_full_scenario`] for the exact rules this mirrors.
pub fn resolve_connection_exhaustion_scenario() -> ConnectionExhaustionScenario {
    resolve_connection_exhaustion_scenario_from(
        env::var_os(CONNECTION_EXHAUSTION_REQUIRED_ENV),
        env::var_os(CONNECTION_EXHAUSTION_IMAGE_ENV),
    )
}

fn resolve_connection_exhaustion_scenario_from(
    required_raw: Option<OsString>,
    image_raw: Option<OsString>,
) -> ConnectionExhaustionScenario {
    let required = parse_connection_exhaustion_required_flag(required_raw);
    match image_raw {
        None => {
            if required {
                panic!(
                    "{CONNECTION_EXHAUSTION_REQUIRED_ENV} is set but \
                     {CONNECTION_EXHAUSTION_IMAGE_ENV} is not configured"
                );
            }
            ConnectionExhaustionScenario::Skip
        }
        Some(raw) => {
            ConnectionExhaustionScenario::Run(parse_connection_exhaustion_pinned_image(raw))
        }
    }
}

fn parse_connection_exhaustion_pinned_image(raw: OsString) -> PinnedImage {
    let text = raw
        .to_str()
        .unwrap_or_else(|| panic!("{CONNECTION_EXHAUSTION_IMAGE_ENV} must be valid UTF-8"));
    PinnedImage::parse(text)
        .unwrap_or_else(|error| panic!("{CONNECTION_EXHAUSTION_IMAGE_ENV} is invalid: {error}"))
}

fn parse_connection_exhaustion_required_flag(raw: Option<OsString>) -> bool {
    match raw {
        None => false,
        Some(raw) => {
            let text = raw.to_str().unwrap_or_else(|| {
                panic!("{CONNECTION_EXHAUSTION_REQUIRED_ENV} must be valid UTF-8")
            });
            match text {
                "1" => true,
                other => panic!(
                    "{CONNECTION_EXHAUSTION_REQUIRED_ENV} must be exactly \"1\" when set, got \
                     {other:?}"
                ),
            }
        }
    }
}

// --- Connection-exhaustion scenario: disposable container with a tiny cap --

/// Exact server-side connection capacity this scenario configures via
/// `-c max_connections=...`. Deliberately tiny — far below the shared CI
/// database's default — so a small, exactly bounded number of direct blocker
/// connections can deterministically saturate every slot.
pub const CONNECTION_EXHAUSTION_MAX_CONNECTIONS: u32 = 5;

/// Exact server-side `-c superuser_reserved_connections=...` this scenario
/// configures. Zero so every session this scenario opens (all as the
/// container's superuser role) is bound by the same
/// [`CONNECTION_EXHAUSTION_MAX_CONNECTIONS`] ceiling, with no separate
/// superuser-only carve-out for this scenario's counting to account for.
pub const CONNECTION_EXHAUSTION_SUPERUSER_RESERVED_CONNECTIONS: u32 = 0;

/// Exact server-side `-c reserved_connections=...` this scenario configures.
/// PostgreSQL 16 added this as a second, independent reserved pool — for
/// roles with the `pg_use_reserved_connections` predefined role, distinct
/// from [`CONNECTION_EXHAUSTION_SUPERUSER_RESERVED_CONNECTIONS`] above — so
/// it is pinned to zero explicitly for the same reason: any non-zero
/// carve-out here would also break this scenario's exact
/// blocker/slot accounting.
pub const CONNECTION_EXHAUSTION_RESERVED_CONNECTIONS: u32 = 0;

/// Size cap, in bytes, of the tmpfs holding `PGDATA`. This scenario never
/// intentionally fills any filesystem — its fault is server connection-slot
/// capacity, not disk space — so this is only a RAM-backed, disposable,
/// bounded home for the cluster.
const CONNECTION_EXHAUSTION_PGDATA_TMPFS_BYTES: u64 = 512 * 1024 * 1024;

/// A disposable, RAM-backed PostgreSQL container for the bounded
/// connection-exhaustion scenario. Started with a tiny
/// [`CONNECTION_EXHAUSTION_MAX_CONNECTIONS`], zero
/// [`CONNECTION_EXHAUSTION_SUPERUSER_RESERVED_CONNECTIONS`], and zero
/// [`CONNECTION_EXHAUSTION_RESERVED_CONNECTIONS`], so no role gets a
/// capacity carve-out this scenario's exact-count assertions would need to
/// special-case. Also starts with `autovacuum` disabled, but only as
/// optional quiescence against unrelated background activity during the
/// bounded test window: autovacuum workers and the autovacuum launcher are
/// accounted from their own separate budget (`autovacuum_max_workers`,
/// alongside `max_worker_processes` and `max_wal_senders`), never carved out
/// of `max_connections`, so this scenario's `backend_type = 'client
/// backend'`-filtered counts already exclude them regardless of this
/// setting.
///
/// [`Drop`] force-removes the container and never panics: on failure it only
/// `eprintln!`s the container ID and its
/// `sunrise-edge-test=connection-exhaustion` label so a human can find and
/// remove a leaked container.
pub struct ConnectionExhaustionPostgresContainer {
    container_id: ContainerId,
    published_port: u16,
    postgres_password: String,
}

impl ConnectionExhaustionPostgresContainer {
    /// Starts a fresh disposable container from `image` and waits for a
    /// fresh client connection plus a trivial query to succeed against its
    /// default `postgres` database. Panics on any failure: a scenario that
    /// cannot even start its own disposable container proves nothing.
    pub fn start(image: &PinnedImage) -> Self {
        let postgres_password: String = os_random_secret_hex(32).unwrap_or_else(|error| {
            panic!("failed to read PostgreSQL test password from OS randomness: {error}")
        });
        let container_name = format!(
            "sunrise-edge-connection-exhaustion-{}-{}",
            std::process::id(),
            random_hex_token(16)
        );
        let pgdata_mount = format!(
            "type=tmpfs,destination=/var/lib/postgresql,tmpfs-size={CONNECTION_EXHAUSTION_PGDATA_TMPFS_BYTES}"
        );
        let password_env = format!("POSTGRES_PASSWORD={postgres_password}");
        let max_connections_arg =
            format!("max_connections={CONNECTION_EXHAUSTION_MAX_CONNECTIONS}");
        let superuser_reserved_arg = format!(
            "superuser_reserved_connections={CONNECTION_EXHAUSTION_SUPERUSER_RESERVED_CONNECTIONS}"
        );
        let reserved_connections_arg =
            format!("reserved_connections={CONNECTION_EXHAUSTION_RESERVED_CONNECTIONS}");
        let run_output_result = run_docker_command_bounded_output(
            docker_argv_command(&[
                "run",
                "--detach",
                "--name",
                &container_name,
                "--label",
                "sunrise-edge-test=connection-exhaustion",
                "--publish",
                "127.0.0.1::5432",
                "--memory",
                "1g",
                "--memory-swap",
                "1g",
                "--pids-limit",
                "512",
                "--mount",
                &pgdata_mount,
                "--env",
                &password_env,
                "--env",
                "POSTGRES_DB=postgres",
                "--",
                image.as_str(),
                "-c",
                &max_connections_arg,
                "-c",
                &superuser_reserved_arg,
                "-c",
                &reserved_connections_arg,
                "-c",
                "autovacuum=off",
            ]),
            "docker run (connection-exhaustion container)",
        );
        let run_output = run_output_result.unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after failed run",
            )
            .err();
            panic!(
                "docker run (connection-exhaustion container) failed: {error}; cleanup by exact generated name returned {cleanup_error:?}"
            )
        });
        let container_id = ContainerId::parse(run_output.trim()).unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after invalid run output",
            )
            .err();
            panic!(
                "docker run produced an invalid container id {run_output:?}: {error}; cleanup by exact generated name returned {cleanup_error:?}"
            )
        });
        let mut container = Self {
            container_id,
            published_port: 0,
            postgres_password,
        };
        let port_output = run_docker_command_bounded_output(
            docker_argv_command(&["port", container.container_id.as_str(), "5432/tcp"]),
            "docker port (connection-exhaustion container)",
        )
        .unwrap_or_else(|error| panic!("docker port failed: {error}"));
        container.published_port = parse_published_port(&port_output);
        wait_for_database_ready(
            &format!(
                "connection-exhaustion container {}",
                container.container_id.as_str()
            ),
            &container.url("postgres"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        container
    }

    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// Builds the `postgresql://` URL for `database` against this
    /// container's published port and generated password.
    pub fn url(&self, database: &str) -> String {
        format!(
            "postgresql://postgres:{}@127.0.0.1:{}/{database}",
            self.postgres_password, self.published_port
        )
    }
}

impl Drop for ConnectionExhaustionPostgresContainer {
    fn drop(&mut self) {
        let result = run_docker_command_bounded(
            docker_argv_command(&["rm", "--force", "--volumes", self.container_id.as_str()]),
            "docker rm (connection-exhaustion container)",
        );
        if let Err(error) = result {
            eprintln!(
                "ConnectionExhaustionPostgresContainer: failed to remove container {} (label \
                 sunrise-edge-test=connection-exhaustion): {error}; remove it by hand",
                self.container_id.as_str()
            );
        }
    }
}

// --- Backup-restore scenario: strict environment parsing --------------------

/// Environment variable naming the digest-pinned PostgreSQL image the bounded
/// backup-restore rehearsal scenario starts as its own two disposable,
/// mutually isolated containers (never the shared CI service container, and
/// never another scenario's own container).
pub const BACKUP_RESTORE_IMAGE_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_IMAGE";

/// Environment variable that, when set to exactly `"1"`, forbids the
/// backup-restore scenario from silently skipping.
pub const BACKUP_RESTORE_REQUIRED_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_REQUIRED";

/// Outcome of strictly resolving whether the bounded backup-restore rehearsal
/// scenario runs in this process. Same shape and rules as [`DiskFullScenario`]:
/// only "both absent" skips.
#[derive(Debug)]
pub enum BackupRestoreScenario {
    /// No backup-restore image is configured: the scenario is skipped.
    Skip,
    /// Run the scenario against two disposable containers started from this
    /// pinned image.
    Run(PinnedImage),
}

/// Strictly resolves [`BackupRestoreScenario`] from [`BACKUP_RESTORE_IMAGE_ENV`]
/// and [`BACKUP_RESTORE_REQUIRED_ENV`]; see [`resolve_disk_full_scenario`] for
/// the exact rules this mirrors.
pub fn resolve_backup_restore_scenario() -> BackupRestoreScenario {
    resolve_backup_restore_scenario_from(
        env::var_os(BACKUP_RESTORE_REQUIRED_ENV),
        env::var_os(BACKUP_RESTORE_IMAGE_ENV),
    )
}

fn resolve_backup_restore_scenario_from(
    required_raw: Option<OsString>,
    image_raw: Option<OsString>,
) -> BackupRestoreScenario {
    let required = parse_backup_restore_required_flag(required_raw);
    match image_raw {
        None => {
            if required {
                panic!(
                    "{BACKUP_RESTORE_REQUIRED_ENV} is set but {BACKUP_RESTORE_IMAGE_ENV} is not \
                     configured"
                );
            }
            BackupRestoreScenario::Skip
        }
        Some(raw) => BackupRestoreScenario::Run(parse_backup_restore_pinned_image(raw)),
    }
}

fn parse_backup_restore_pinned_image(raw: OsString) -> PinnedImage {
    let text = raw
        .to_str()
        .unwrap_or_else(|| panic!("{BACKUP_RESTORE_IMAGE_ENV} must be valid UTF-8"));
    PinnedImage::parse(text)
        .unwrap_or_else(|error| panic!("{BACKUP_RESTORE_IMAGE_ENV} is invalid: {error}"))
}

fn parse_backup_restore_required_flag(raw: Option<OsString>) -> bool {
    match raw {
        None => false,
        Some(raw) => {
            let text = raw
                .to_str()
                .unwrap_or_else(|| panic!("{BACKUP_RESTORE_REQUIRED_ENV} must be valid UTF-8"));
            match text {
                "1" => true,
                other => panic!(
                    "{BACKUP_RESTORE_REQUIRED_ENV} must be exactly \"1\" when set, got {other:?}"
                ),
            }
        }
    }
}

// --- Backup-restore scenario: disposable containers and file transfer -------

/// Size cap, in bytes, of the tmpfs holding `PGDATA` in each backup-restore
/// container. Same magnitude as the other scenarios' unfilled PGDATA cap;
/// this scenario never intentionally fills any filesystem.
const BACKUP_RESTORE_PGDATA_TMPFS_BYTES: u64 = 512 * 1024 * 1024;

/// A disposable, RAM-backed PostgreSQL container for the bounded
/// backup-restore rehearsal scenario. The scenario starts two independent
/// instances of this type (source and target): each gets its own generated
/// container name/password and its own randomly published host port, so they
/// are genuinely separate, mutually isolated PostgreSQL server processes,
/// never two databases inside one running server.
///
/// [`Drop`] force-removes the container and never panics: on failure it only
/// `eprintln!`s the container ID and its exact role-qualified label so a human
/// can find and remove a leaked container.
pub struct BackupRestorePostgresContainer {
    container_id: ContainerId,
    published_port: u16,
    postgres_password: String,
    cleanup_label: String,
}

impl BackupRestorePostgresContainer {
    /// Starts a fresh disposable container from `image` and waits for a
    /// fresh client connection plus a trivial query to succeed against its
    /// default `postgres` database. `role` ("source" or "target") only
    /// disambiguates the generated container name/label for human
    /// diagnostics; the scenario itself tells the two containers apart by
    /// their independently generated ID, port, and password, never by this
    /// string. Panics on any failure: a scenario that cannot even start its
    /// own disposable container proves nothing.
    pub fn start(image: &PinnedImage, role: &str) -> Self {
        let postgres_password: String = os_random_secret_hex(32).unwrap_or_else(|error| {
            panic!("failed to read PostgreSQL test password from OS randomness: {error}")
        });
        let container_name = format!(
            "sunrise-edge-backup-restore-{role}-{}-{}",
            std::process::id(),
            random_hex_token(16)
        );
        let label = format!("sunrise-edge-test=backup-restore-{role}");
        let pgdata_mount = format!(
            "type=tmpfs,destination=/var/lib/postgresql,tmpfs-size={BACKUP_RESTORE_PGDATA_TMPFS_BYTES}"
        );
        let password_env = format!("POSTGRES_PASSWORD={postgres_password}");
        let run_output_result = run_docker_command_bounded_output(
            docker_argv_command(&[
                "run",
                "--detach",
                "--name",
                &container_name,
                "--label",
                &label,
                "--publish",
                "127.0.0.1::5432",
                "--memory",
                "1g",
                "--memory-swap",
                "1g",
                "--pids-limit",
                "512",
                "--mount",
                &pgdata_mount,
                "--env",
                &password_env,
                "--env",
                "POSTGRES_DB=postgres",
                "--",
                image.as_str(),
            ]),
            "docker run (backup-restore container)",
        );
        let run_output = run_output_result.unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after failed run",
            )
            .err();
            panic!(
                "docker run (backup-restore container) failed: {error}; cleanup by exact generated name returned {cleanup_error:?}"
            )
        });
        let container_id = ContainerId::parse(run_output.trim()).unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after invalid run output",
            )
            .err();
            panic!(
                "docker run produced an invalid container id {run_output:?}: {error}; cleanup by exact generated name returned {cleanup_error:?}"
            )
        });
        let mut container = Self {
            container_id,
            published_port: 0,
            postgres_password,
            cleanup_label: label,
        };
        let port_output = run_docker_command_bounded_output(
            docker_argv_command(&["port", container.container_id.as_str(), "5432/tcp"]),
            "docker port (backup-restore container)",
        )
        .unwrap_or_else(|error| panic!("docker port failed: {error}"));
        container.published_port = parse_published_port(&port_output);
        wait_for_database_ready(
            &format!(
                "backup-restore container ({role}) {}",
                container.container_id.as_str()
            ),
            &container.url("postgres"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        container
    }

    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// Builds the `postgresql://` URL for `database` against this
    /// container's published port and generated password.
    pub fn url(&self, database: &str) -> String {
        format!(
            "postgresql://postgres:{}@127.0.0.1:{}/{database}",
            self.postgres_password, self.published_port
        )
    }

    /// Runs `docker exec --user postgres <id> <args>`, bounded, with capped
    /// output. `pg_dump`/`psql`/`createdb` all connect over the container's
    /// local Unix socket as the unprivileged `postgres` server/OS user, which
    /// the official image's default `pg_hba.conf` trusts without a password,
    /// so no exec in this scenario ever needs `--user root` or the generated
    /// TCP password.
    pub fn exec(&self, args: &[&str]) -> io::Result<String> {
        let mut full_args: Vec<&str> = vec![
            "exec",
            "--user",
            "postgres",
            "--",
            self.container_id.as_str(),
        ];
        full_args.extend_from_slice(args);
        run_docker_command_bounded_output(docker_argv_command(&full_args), "docker exec")
    }

    /// Same as [`Self::exec`], but with an explicit output cap instead of
    /// [`DOCKER_COMMAND_OUTPUT_MAX_BYTES`]. Used only for `pg_dump`, whose
    /// captured stdout this scenario deliberately keeps small but which can
    /// still exceed the generic per-exec cap sized for one-line probes.
    pub fn exec_capped(&self, args: &[&str], max_bytes: u64) -> io::Result<String> {
        let mut full_args: Vec<&str> = vec![
            "exec",
            "--user",
            "postgres",
            "--",
            self.container_id.as_str(),
        ];
        full_args.extend_from_slice(args);
        run_docker_command_bounded_output_capped(
            docker_argv_command(&full_args),
            "docker exec",
            max_bytes,
        )
    }
}

impl Drop for BackupRestorePostgresContainer {
    fn drop(&mut self) {
        let result = run_docker_command_bounded(
            docker_argv_command(&["rm", "--force", "--volumes", self.container_id.as_str()]),
            "docker rm (backup-restore container)",
        );
        if let Err(error) = result {
            eprintln!(
                "BackupRestorePostgresContainer: failed to remove container {} (label {}): \
                 {error}; remove it by hand",
                self.container_id.as_str(),
                self.cleanup_label
            );
        }
    }
}

// --- PgBouncer transaction-pooling rehearsal: strict environment parsing ---

/// Environment variable naming the digest-pinned PostgreSQL image the
/// PgBouncer rehearsal starts as its own disposable backend container (never
/// the shared CI service container, and never another scenario's own
/// container).
pub const PGBOUNCER_POSTGRES_IMAGE_ENV: &str =
    "SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_POSTGRES_IMAGE";

/// Environment variable naming the digest-pinned `ghcr.io/icoretech/pgbouncer-docker`
/// image the rehearsal starts as its own disposable proxy container.
pub const PGBOUNCER_IMAGE_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_IMAGE";

/// Environment variable that, when set to exactly `"1"`, forbids the
/// PgBouncer rehearsal from silently skipping.
pub const PGBOUNCER_REQUIRED_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_REQUIRED";

/// Outcome of strictly resolving whether the bounded PgBouncer
/// transaction-pooling rehearsal runs in this process.
///
/// Unlike the single-image scenarios ([`DiskFullScenario`] and friends), this
/// scenario needs two independently pinned images (the PostgreSQL backend and
/// the PgBouncer proxy), so it follows [`CrashScenario`]'s partial-configuration
/// rule instead: only "both absent" skips. One image configured without the
/// other always fails loudly, rather than silently skipping on half-broken
/// configuration or silently running against a wrong/missing proxy image.
#[derive(Debug)]
pub enum PgBouncerScenario {
    /// Neither image is configured: the scenario is skipped.
    Skip,
    /// Run the scenario against disposable containers started from these
    /// pinned images.
    Run {
        postgres_image: PinnedImage,
        pgbouncer_image: PinnedImage,
    },
}

/// Strictly resolves [`PgBouncerScenario`] from [`PGBOUNCER_POSTGRES_IMAGE_ENV`],
/// [`PGBOUNCER_IMAGE_ENV`], and [`PGBOUNCER_REQUIRED_ENV`]; see this type's doc
/// comment for the exact rules.
pub fn resolve_pgbouncer_scenario() -> PgBouncerScenario {
    resolve_pgbouncer_scenario_from(
        env::var_os(PGBOUNCER_REQUIRED_ENV),
        env::var_os(PGBOUNCER_POSTGRES_IMAGE_ENV),
        env::var_os(PGBOUNCER_IMAGE_ENV),
    )
}

/// Pure decision logic behind [`resolve_pgbouncer_scenario`]; split out for
/// unit tests for the same reason as [`resolve_crash_scenario_from`].
fn resolve_pgbouncer_scenario_from(
    required_raw: Option<OsString>,
    postgres_image_raw: Option<OsString>,
    pgbouncer_image_raw: Option<OsString>,
) -> PgBouncerScenario {
    let required = parse_pgbouncer_required_flag(required_raw);
    match (postgres_image_raw, pgbouncer_image_raw) {
        (None, None) => {
            if required {
                panic!(
                    "{PGBOUNCER_REQUIRED_ENV} is set but neither {PGBOUNCER_POSTGRES_IMAGE_ENV} \
                     nor {PGBOUNCER_IMAGE_ENV} is configured"
                );
            }
            PgBouncerScenario::Skip
        }
        (Some(_), None) => panic!(
            "{PGBOUNCER_POSTGRES_IMAGE_ENV} is set but {PGBOUNCER_IMAGE_ENV} is not; partial \
             live PgBouncer rehearsal configuration is not allowed"
        ),
        (None, Some(_)) => panic!(
            "{PGBOUNCER_IMAGE_ENV} is set but {PGBOUNCER_POSTGRES_IMAGE_ENV} is not; partial \
             live PgBouncer rehearsal configuration is not allowed"
        ),
        (Some(postgres_raw), Some(pgbouncer_raw)) => PgBouncerScenario::Run {
            postgres_image: parse_pgbouncer_postgres_pinned_image(postgres_raw),
            pgbouncer_image: parse_pgbouncer_pinned_image(pgbouncer_raw),
        },
    }
}

fn parse_pgbouncer_postgres_pinned_image(raw: OsString) -> PinnedImage {
    let text = raw
        .to_str()
        .unwrap_or_else(|| panic!("{PGBOUNCER_POSTGRES_IMAGE_ENV} must be valid UTF-8"));
    PinnedImage::parse(text)
        .unwrap_or_else(|error| panic!("{PGBOUNCER_POSTGRES_IMAGE_ENV} is invalid: {error}"))
}

fn parse_pgbouncer_pinned_image(raw: OsString) -> PinnedImage {
    let text = raw
        .to_str()
        .unwrap_or_else(|| panic!("{PGBOUNCER_IMAGE_ENV} must be valid UTF-8"));
    PinnedImage::parse(text)
        .unwrap_or_else(|error| panic!("{PGBOUNCER_IMAGE_ENV} is invalid: {error}"))
}

fn parse_pgbouncer_required_flag(raw: Option<OsString>) -> bool {
    match raw {
        None => false,
        Some(raw) => {
            let text = raw
                .to_str()
                .unwrap_or_else(|| panic!("{PGBOUNCER_REQUIRED_ENV} must be valid UTF-8"));
            match text {
                "1" => true,
                other => {
                    panic!("{PGBOUNCER_REQUIRED_ENV} must be exactly \"1\" when set, got {other:?}")
                }
            }
        }
    }
}

// --- PgBouncer transaction-pooling rehearsal: isolated Docker network ------

/// A disposable, generated-name Docker bridge network. The PgBouncer
/// rehearsal's PostgreSQL backend and PgBouncer proxy containers are attached
/// to one of these, isolating the proxy-to-backend traffic this scenario
/// proves from Docker's default bridge and from every other live-test
/// scenario's own containers. [`Drop`] force-removes the network and never
/// panics; the caller must ensure every attached container is already
/// removed first (Docker refuses to remove a network with live attachments),
/// which the scenario achieves by declaring this guard before either
/// container so Rust's reverse-drop-order unwinds containers first.
pub struct DockerNetwork {
    name: String,
}

impl DockerNetwork {
    /// Creates a fresh, uniquely named bridge network. Panics on failure: a
    /// scenario that cannot even create its own isolated network proves
    /// nothing about PgBouncer running on one.
    pub fn create() -> Self {
        let name = format!(
            "sunrise-edge-pgbouncer-{}-{}",
            std::process::id(),
            random_hex_token(16)
        );
        run_docker_command_bounded(
            docker_argv_command(&[
                "network",
                "create",
                "--driver",
                "bridge",
                "--label",
                "sunrise-edge-test=pgbouncer",
                "--",
                &name,
            ]),
            "docker network create (pgbouncer rehearsal)",
        )
        .unwrap_or_else(|error| panic!("docker network create failed: {error}"));
        Self { name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for DockerNetwork {
    fn drop(&mut self) {
        if let Err(error) = run_docker_command_bounded(
            docker_argv_command(&["network", "rm", "--", &self.name]),
            "docker network rm (pgbouncer rehearsal)",
        ) {
            eprintln!(
                "DockerNetwork: failed to remove network {} (label sunrise-edge-test=pgbouncer): \
                 {error}; remove it by hand",
                self.name
            );
        }
    }
}

// --- PgBouncer transaction-pooling rehearsal: rendered config content ------

/// Exact PgBouncer `pool_size`/`default_pool_size`/`max_db_connections`/
/// `max_user_connections` this rehearsal configures for the tested
/// database/user pool: this scenario's whole point is proving
/// transaction-pooling multiplexing of multiple client connections over
/// exactly one physical PostgreSQL backend.
pub const PGBOUNCER_POOL_SIZE: u32 = 1;

/// Upper bound on simultaneously connected PgBouncer clients. Generous
/// relative to the handful of direct/adapter connections this scenario ever
/// opens at once; it exists so a client-count bug in the test would fail
/// loudly against a real cap instead of silently succeeding under an
/// effectively unbounded default.
pub const PGBOUNCER_MAX_CLIENT_CONN: u32 = 20;

/// Nonzero `max_prepared_statements` this rehearsal configures, proving the
/// scenario does not merely leave PgBouncer's prepared-statement support at
/// its default.
pub const PGBOUNCER_MAX_PREPARED_STATEMENTS: u32 = 16;

/// Bounded `query_wait_timeout`, in whole seconds, this rehearsal configures.
/// Short so the blocked-adapter phase of the live test stays fast; PgBouncer
/// enforces this server-side, independent of any client- or adapter-side
/// deadline.
pub const PGBOUNCER_QUERY_WAIT_TIMEOUT_SECS: u32 = 3;

/// Explicit, typed inputs to [`render_pgbouncer_ini`]. Every field is
/// program-controlled (a fixed database/role name, an internal Docker
/// network alias, and generated port numbers), never attacker- or
/// operator-supplied input, so the renderer performs no escaping; see
/// [`render_pgbouncer_ini`]'s doc comment for the exact invariant this
/// relies on.
#[derive(Debug, Clone, Copy)]
pub struct PgBouncerIniConfig<'a> {
    pub database: &'a str,
    pub backend_host: &'a str,
    pub backend_port: u16,
    pub listen_port: u16,
    pub admin_user: &'a str,
}

/// Renders the exact `pgbouncer.ini` this rehearsal writes into its proxy
/// container: transaction pooling, exactly one backend connection for the
/// tested database/user pool, a nonzero `max_prepared_statements`, and a
/// bounded `query_wait_timeout`.
///
/// None of `config`'s fields may legally contain a newline, `=`, `[`, `]`, or
/// leading/trailing whitespace (an INI-breaking value), so this function
/// panics rather than silently emitting a malformed file if one does; every
/// call site passes only fixed literals or a generated alphanumeric network
/// alias, never external input.
pub fn render_pgbouncer_ini(config: &PgBouncerIniConfig<'_>) -> String {
    for (field, value) in [
        ("database", config.database),
        ("backend_host", config.backend_host),
        ("admin_user", config.admin_user),
    ] {
        assert!(
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'),
            "PgBouncer ini field {field:?} must be non-empty alphanumeric/underscore/hyphen, got \
             {value:?}"
        );
    }
    format!(
        "[databases]\n\
         {database} = host={backend_host} port={backend_port} dbname={database} pool_size={pool_size}\n\
         \n\
         [pgbouncer]\n\
         listen_addr = 0.0.0.0\n\
         listen_port = {listen_port}\n\
         auth_type = md5\n\
         auth_file = /etc/pgbouncer/userlist.txt\n\
         pool_mode = transaction\n\
         max_client_conn = {max_client_conn}\n\
         default_pool_size = {pool_size}\n\
         max_db_connections = {pool_size}\n\
         max_user_connections = {pool_size}\n\
         max_prepared_statements = {max_prepared_statements}\n\
         query_wait_timeout = {query_wait_timeout}\n\
         admin_users = {admin_user}\n\
         stats_users = {admin_user}\n\
         logfile = /tmp/pgbouncer.log\n\
         pidfile = /tmp/pgbouncer.pid\n",
        database = config.database,
        backend_host = config.backend_host,
        backend_port = config.backend_port,
        pool_size = PGBOUNCER_POOL_SIZE,
        listen_port = config.listen_port,
        max_client_conn = PGBOUNCER_MAX_CLIENT_CONN,
        max_prepared_statements = PGBOUNCER_MAX_PREPARED_STATEMENTS,
        query_wait_timeout = PGBOUNCER_QUERY_WAIT_TIMEOUT_SECS,
        admin_user = config.admin_user,
    )
}

/// Renders one `userlist.txt` line binding `user` to `credential_hash` (an
/// `md5<32 lowercase hex>` string read back from PostgreSQL's own
/// `pg_authid.rolpassword` after the role's password is set with
/// `password_encryption = md5` in effect, never a plaintext password and
/// never computed by this test). That alphabet (lowercase hex plus the fixed
/// `md5` prefix) and every call site's `user` never contain a double quote or
/// backslash, so no escaping is required for PgBouncer's simple
/// double-quoted userlist format; this function panics rather than silently
/// emitting a corrupt entry if either ever did.
pub fn render_userlist_entry(user: &str, credential_hash: &str) -> String {
    for (field, value) in [("user", user), ("credential_hash", credential_hash)] {
        assert!(
            !value
                .bytes()
                .any(|byte| byte == b'"' || byte == b'\\' || byte == b'\n'),
            "PgBouncer userlist field {field:?} must not contain a quote, backslash, or newline, \
             got {value:?}"
        );
    }
    format!("\"{user}\" \"{credential_hash}\"\n")
}

// --- PgBouncer transaction-pooling rehearsal: disposable containers --------

const PGBOUNCER_POSTGRES_PGDATA_TMPFS_BYTES: u64 = 512 * 1024 * 1024;

/// A disposable, RAM-backed PostgreSQL container for the PgBouncer
/// rehearsal, attached to a [`DockerNetwork`] under a fixed network alias so
/// the PgBouncer proxy container can resolve it by name, and also published
/// on the host loopback interface for this test's own direct, PgBouncer-
/// bypassing verification connections (schema bootstrap, ground-truth reads
/// while the proxy's sole backend is held by a blocker). [`Drop`]
/// force-removes the container and never panics.
pub struct PgBouncerPostgresContainer {
    container_id: ContainerId,
    published_port: u16,
    postgres_password: String,
}

impl PgBouncerPostgresContainer {
    /// The fixed internal network alias/port every PgBouncer proxy container
    /// this scenario starts resolves this container by, over the shared
    /// [`DockerNetwork`].
    pub const NETWORK_ALIAS: &'static str = "sunrise-edge-pgbouncer-backend";
    const INTERNAL_PORT: u16 = 5432;

    pub fn start(image: &PinnedImage, network: &DockerNetwork) -> Self {
        let postgres_password: String = os_random_secret_hex(32).unwrap_or_else(|error| {
            panic!("failed to read PostgreSQL test password from OS randomness: {error}")
        });
        let container_name = format!(
            "sunrise-edge-pgbouncer-pg-{}-{}",
            std::process::id(),
            random_hex_token(16)
        );
        let pgdata_mount = format!(
            "type=tmpfs,destination=/var/lib/postgresql,tmpfs-size={PGBOUNCER_POSTGRES_PGDATA_TMPFS_BYTES}"
        );
        let password_env = format!("POSTGRES_PASSWORD={postgres_password}");
        let run_output_result = run_docker_command_bounded_output(
            docker_argv_command(&[
                "run",
                "--detach",
                "--name",
                &container_name,
                "--label",
                "sunrise-edge-test=pgbouncer-postgres",
                "--network",
                network.name(),
                "--network-alias",
                Self::NETWORK_ALIAS,
                "--publish",
                "127.0.0.1::5432",
                "--memory",
                "1g",
                "--memory-swap",
                "1g",
                "--pids-limit",
                "512",
                "--mount",
                &pgdata_mount,
                "--env",
                &password_env,
                "--env",
                "POSTGRES_DB=postgres",
                "--",
                image.as_str(),
                // PgBouncer's server-side (proxy-to-backend) authentication
                // needs the plaintext-derived password hash it can relay
                // itself; MD5 is the simple, universally interoperable choice
                // here (this scenario's client leg is plaintext already, so
                // MD5-vs-SCRAM buys no additional confidentiality either
                // way). Applied via `-c` so every password this scenario
                // sets afterward (`ALTER ROLE ... PASSWORD`) is stored in
                // that exact format.
                "-c",
                "password_encryption=md5",
            ]),
            "docker run (pgbouncer-rehearsal postgres container)",
        );
        let run_output = run_output_result.unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after failed run",
            )
            .err();
            panic!(
                "docker run (pgbouncer-rehearsal postgres container) failed: {error}; cleanup by \
                 exact generated name returned {cleanup_error:?}"
            )
        });
        let container_id = ContainerId::parse(run_output.trim()).unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after invalid run output",
            )
            .err();
            panic!(
                "docker run produced an invalid container id {run_output:?}: {error}; cleanup by \
                 exact generated name returned {cleanup_error:?}"
            )
        });
        let mut container = Self {
            container_id,
            published_port: 0,
            postgres_password,
        };
        let port_output = run_docker_command_bounded_output(
            docker_argv_command(&["port", container.container_id.as_str(), "5432/tcp"]),
            "docker port (pgbouncer-rehearsal postgres container)",
        )
        .unwrap_or_else(|error| panic!("docker port failed: {error}"));
        container.published_port = parse_published_port(&port_output);
        wait_for_database_ready(
            &format!(
                "pgbouncer-rehearsal postgres container {}",
                container.container_id.as_str()
            ),
            &container.url("postgres"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        container
    }

    /// Builds the direct, PgBouncer-bypassing `postgresql://` URL for
    /// `database` against this container's published port.
    pub fn url(&self, database: &str) -> String {
        format!(
            "postgresql://postgres:{}@127.0.0.1:{}/{database}",
            self.postgres_password, self.published_port
        )
    }

    /// The plaintext password every PgBouncer client this scenario opens
    /// (through the proxy) authenticates with; PgBouncer itself validates it
    /// via an MD5 challenge against the credential hash in `userlist.txt`,
    /// never this string directly.
    pub fn password(&self) -> &str {
        &self.postgres_password
    }

    pub const fn internal_port() -> u16 {
        Self::INTERNAL_PORT
    }
}

impl Drop for PgBouncerPostgresContainer {
    fn drop(&mut self) {
        let result = run_docker_command_bounded(
            docker_argv_command(&["rm", "--force", "--volumes", self.container_id.as_str()]),
            "docker rm (pgbouncer-rehearsal postgres container)",
        );
        if let Err(error) = result {
            eprintln!(
                "PgBouncerPostgresContainer: failed to remove container {} (label \
                 sunrise-edge-test=pgbouncer-postgres): {error}; remove it by hand",
                self.container_id.as_str()
            );
        }
    }
}

/// Bound on how long [`PgBouncerProxyContainer::start`] waits for the proxy
/// process to accept an admin-console login before giving up.
const PGBOUNCER_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for [`PGBOUNCER_READY_TIMEOUT`] to elapse.
const PGBOUNCER_READY_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// A disposable PgBouncer proxy container for the transaction-pooling
/// rehearsal, attached to a [`DockerNetwork`] and configured (via
/// [`render_pgbouncer_ini`]/[`render_userlist_entry`], written in with no
/// shell and no host bind mount) to route exactly one database/user pool,
/// using transaction pooling, to a [`PgBouncerPostgresContainer`] resolved by
/// its network alias. Published on the host loopback interface so this
/// test's own direct and adapter-pool clients can reach it. [`Drop`]
/// force-removes the container and never panics.
pub struct PgBouncerProxyContainer {
    container_id: ContainerId,
    published_port: u16,
    admin_user: String,
    password: String,
}

impl PgBouncerProxyContainer {
    /// Starts the proxy container idling on a bare `sleep`, writes its config
    /// files in over stdin via `tee` (direct argv, no shell, no host bind
    /// mount), starts `pgbouncer` itself as a detached in-container exec, and
    /// boundedly waits for its admin console to accept a login. Panics on any
    /// failure.
    pub fn start(
        image: &PinnedImage,
        network: &DockerNetwork,
        database: &str,
        admin_user: &str,
        password: &str,
        credential_hash: &str,
    ) -> Self {
        let container_name = format!(
            "sunrise-edge-pgbouncer-proxy-{}-{}",
            std::process::id(),
            random_hex_token(16)
        );
        let run_output_result = run_docker_command_bounded_output(
            docker_argv_command(&[
                "run",
                "--detach",
                "--name",
                &container_name,
                "--label",
                "sunrise-edge-test=pgbouncer-proxy",
                "--network",
                network.name(),
                "--publish",
                "127.0.0.1::6432",
                "--memory",
                "256m",
                "--memory-swap",
                "256m",
                "--pids-limit",
                "64",
                "--entrypoint",
                "sleep",
                "--",
                image.as_str(),
                "infinity",
            ]),
            "docker run (pgbouncer proxy container)",
        );
        let run_output = run_output_result.unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after failed run",
            )
            .err();
            panic!(
                "docker run (pgbouncer proxy container) failed: {error}; cleanup by exact \
                 generated name returned {cleanup_error:?}"
            )
        });
        let container_id = ContainerId::parse(run_output.trim()).unwrap_or_else(|error| {
            let cleanup_error = run_docker_command_bounded(
                docker_argv_command(&["rm", "--force", "--volumes", &container_name]),
                "docker rm after invalid run output",
            )
            .err();
            panic!(
                "docker run produced an invalid container id {run_output:?}: {error}: cleanup by \
                 exact generated name returned {cleanup_error:?}"
            )
        });
        let mut container = Self {
            container_id,
            published_port: 0,
            admin_user: admin_user.to_owned(),
            password: password.to_owned(),
        };
        let port_output = run_docker_command_bounded_output(
            docker_argv_command(&["port", container.container_id.as_str(), "6432/tcp"]),
            "docker port (pgbouncer proxy container)",
        )
        .unwrap_or_else(|error| panic!("docker port failed: {error}"));
        container.published_port = parse_published_port(&port_output);

        let userlist = render_userlist_entry(admin_user, credential_hash);
        container
            .exec_with_stdin(&["tee", "/etc/pgbouncer/userlist.txt"], userlist.as_bytes())
            .unwrap_or_else(|error| panic!("writing pgbouncer userlist.txt failed: {error}"));

        let ini = render_pgbouncer_ini(&PgBouncerIniConfig {
            database,
            backend_host: PgBouncerPostgresContainer::NETWORK_ALIAS,
            backend_port: PgBouncerPostgresContainer::internal_port(),
            listen_port: 6432,
            admin_user,
        });
        container
            .exec_with_stdin(&["tee", "/etc/pgbouncer/pgbouncer.ini"], ini.as_bytes())
            .unwrap_or_else(|error| panic!("writing pgbouncer.ini failed: {error}"));

        run_docker_command_bounded(
            docker_argv_command(&[
                "exec",
                "-d",
                "--user",
                "postgres",
                "--",
                container.container_id.as_str(),
                "pgbouncer",
                "/etc/pgbouncer/pgbouncer.ini",
            ]),
            "docker exec -d (pgbouncer start)",
        )
        .unwrap_or_else(|error| panic!("starting pgbouncer process failed: {error}"));

        container.wait_ready();
        container
    }

    fn exec_with_stdin(&self, args: &[&str], stdin_bytes: &[u8]) -> io::Result<String> {
        let mut full_args: Vec<&str> = vec![
            "exec",
            "-i",
            "--user",
            "postgres",
            "--",
            self.container_id.as_str(),
        ];
        full_args.extend_from_slice(args);
        run_docker_command_bounded_output_with_stdin(
            docker_argv_command(&full_args),
            "docker exec (pgbouncer config write)",
            stdin_bytes,
            DOCKER_COMMAND_OUTPUT_MAX_BYTES,
        )
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + PGBOUNCER_READY_TIMEOUT;
        loop {
            let mut config: Config = self
                .admin_url()
                .parse()
                .unwrap_or_else(|error| panic!("invalid pgbouncer admin URL: {error}"));
            config.connect_timeout(Duration::from_secs(2));
            if let Ok(mut client) = config.connect(NoTls)
                && client.simple_query("SHOW VERSION").is_ok()
            {
                return;
            }
            if Instant::now() >= deadline {
                let log_tail = run_docker_command_bounded_output(
                    docker_argv_command(&[
                        "exec",
                        "--user",
                        "postgres",
                        "--",
                        self.container_id.as_str(),
                        "cat",
                        "/tmp/pgbouncer.log",
                    ]),
                    "docker exec (pgbouncer log tail on readiness failure)",
                )
                .unwrap_or_else(|error| format!("<failed to read log: {error}>"));
                panic!(
                    "pgbouncer proxy container {} did not accept an admin-console login within \
                     {PGBOUNCER_READY_TIMEOUT:?}; log: {log_tail}",
                    self.container_id.as_str()
                );
            }
            thread::sleep(PGBOUNCER_READY_POLL_INTERVAL);
        }
    }

    /// Builds a `postgresql://` URL for `database` through this proxy, using
    /// this scenario's single generated admin/pool user and password.
    pub fn url(&self, database: &str) -> String {
        format!(
            "postgresql://{}:{}@127.0.0.1:{}/{database}",
            self.admin_user, self.password, self.published_port
        )
    }

    /// Builds the URL for PgBouncer's own virtual admin console database.
    /// Connecting here always gets a dedicated session outside the pooled
    /// backend machinery this scenario's `pool_size=1` otherwise governs, so
    /// admin evidence queries never contend with the tested database/user
    /// pool for its one backend.
    pub fn admin_url(&self) -> String {
        self.url("pgbouncer")
    }

    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }
}

impl Drop for PgBouncerProxyContainer {
    fn drop(&mut self) {
        let result = run_docker_command_bounded(
            docker_argv_command(&["rm", "--force", "--volumes", self.container_id.as_str()]),
            "docker rm (pgbouncer proxy container)",
        );
        if let Err(error) = result {
            eprintln!(
                "PgBouncerProxyContainer: failed to remove container {} (label \
                 sunrise-edge-test=pgbouncer-proxy): {error}; remove it by hand",
                self.container_id.as_str()
            );
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

    #[test]
    fn pinned_image_accepts_a_digest_reference() {
        let image = PinnedImage::parse(
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2",
        )
        .unwrap();
        assert_eq!(
            image.as_str(),
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
        );
    }

    #[test]
    fn pinned_image_rejects_a_floating_tag() {
        assert_eq!(
            PinnedImage::parse("postgres:18.6-alpine3.24"),
            Err(PinnedImageError::MissingDigest)
        );
    }

    #[test]
    fn pinned_image_rejects_empty_name() {
        assert_eq!(
            PinnedImage::parse(
                "@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
            ),
            Err(PinnedImageError::EmptyName)
        );
    }

    #[test]
    fn pinned_image_rejects_missing_sha256_prefix() {
        assert_eq!(
            PinnedImage::parse(
                "postgres@md5:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
            ),
            Err(PinnedImageError::MissingSha256Prefix)
        );
    }

    #[test]
    fn pinned_image_rejects_short_or_uppercase_hex() {
        assert_eq!(
            PinnedImage::parse("postgres@sha256:d3e1"),
            Err(PinnedImageError::InvalidDigestHex)
        );
        assert_eq!(
            PinnedImage::parse(
                "postgres@sha256:D3E1620B530C944AFA6E887D22EB899824DA68E19C52024BF98F5220C88A65B"
            ),
            Err(PinnedImageError::InvalidDigestHex)
        );
    }

    #[test]
    fn resolve_disk_full_scenario_skips_when_both_absent() {
        assert!(matches!(
            resolve_disk_full_scenario_from(None, None),
            DiskFullScenario::Skip
        ));
    }

    #[test]
    #[should_panic(expected = "must be exactly")]
    fn resolve_disk_full_scenario_fails_on_malformed_required_flag() {
        resolve_disk_full_scenario_from(Some(OsString::from("true")), None);
    }

    #[test]
    #[should_panic(expected = "is not configured")]
    fn resolve_disk_full_scenario_fails_when_required_but_no_image() {
        resolve_disk_full_scenario_from(Some(OsString::from("1")), None);
    }

    #[test]
    #[should_panic(expected = "is invalid")]
    fn resolve_disk_full_scenario_fails_on_malformed_image() {
        resolve_disk_full_scenario_from(Some(OsString::from("1")), Some(OsString::from("bad")));
    }

    #[test]
    fn resolve_disk_full_scenario_runs_with_only_image_configured() {
        let raw_image =
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
        match resolve_disk_full_scenario_from(None, Some(OsString::from(raw_image))) {
            DiskFullScenario::Run(image) => assert_eq!(image.as_str(), raw_image),
            DiskFullScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn resolve_disk_full_scenario_runs_with_required_and_image_configured() {
        let raw_image =
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
        match resolve_disk_full_scenario_from(
            Some(OsString::from("1")),
            Some(OsString::from(raw_image)),
        ) {
            DiskFullScenario::Run(image) => assert_eq!(image.as_str(), raw_image),
            DiskFullScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn parse_published_port_accepts_localhost_binding() {
        assert_eq!(parse_published_port("127.0.0.1:55432\n"), 55432);
    }

    #[test]
    #[should_panic(expected = "did not bind to 127.0.0.1")]
    fn parse_published_port_rejects_wildcard_binding() {
        parse_published_port("0.0.0.0:5432\n");
    }

    #[test]
    #[should_panic(expected = "did not bind to 127.0.0.1")]
    fn parse_published_port_rejects_ipv6_binding() {
        parse_published_port("[::]:5432\n");
    }

    #[test]
    #[should_panic(expected = "no output")]
    fn parse_published_port_rejects_empty_output() {
        parse_published_port("\n");
    }

    #[test]
    #[should_panic(expected = "more than one published mapping")]
    fn parse_published_port_rejects_multiple_mappings() {
        parse_published_port("127.0.0.1:55432\n127.0.0.1:55433\n");
    }

    #[test]
    fn parse_df_kib_reads_total_and_available_columns() {
        let output = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n\
                       tmpfs                65536     63488      2048      97% /bounded\n";
        assert_eq!(parse_df_kib(output), (65536, 2048));
    }

    #[test]
    #[should_panic(expected = "too few columns")]
    fn parse_df_kib_rejects_a_short_data_line() {
        parse_df_kib("Filesystem 1024-blocks\ntmpfs 65536\n");
    }

    #[test]
    #[should_panic(expected = "no data line")]
    fn parse_df_kib_rejects_a_header_only_output() {
        parse_df_kib("Filesystem     1024-blocks      Used Available Capacity Mounted on\n");
    }

    #[test]
    fn parse_device_id_reads_a_bare_integer() {
        assert_eq!(parse_device_id("2049\n"), 2049);
    }

    #[test]
    #[should_panic(expected = "non-numeric device id")]
    fn parse_device_id_rejects_non_numeric_output() {
        parse_device_id("not-a-device-id\n");
    }

    #[test]
    fn random_hex_token_produces_the_requested_length_and_is_lowercase_hex() {
        let token = random_hex_token(32);
        assert_eq!(token.len(), 32);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(token.bytes().all(|byte| !byte.is_ascii_uppercase()));
    }

    #[test]
    fn random_hex_token_calls_are_distinct() {
        assert_ne!(random_hex_token(32), random_hex_token(32));
    }

    #[test]
    fn os_random_secret_has_exact_lowercase_hex_length() {
        let secret: String = os_random_secret_hex(32).unwrap();
        assert_eq!(secret.len(), 64);
        assert!(
            secret
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn resolve_wal_full_scenario_skips_when_both_absent() {
        assert!(matches!(
            resolve_wal_full_scenario_from(None, None),
            WalFullScenario::Skip
        ));
    }

    #[test]
    #[should_panic(expected = "must be exactly")]
    fn resolve_wal_full_scenario_fails_on_malformed_required_flag() {
        resolve_wal_full_scenario_from(Some(OsString::from("true")), None);
    }

    #[test]
    #[should_panic(expected = "is not configured")]
    fn resolve_wal_full_scenario_fails_when_required_but_no_image() {
        resolve_wal_full_scenario_from(Some(OsString::from("1")), None);
    }

    #[test]
    #[should_panic(expected = "is invalid")]
    fn resolve_wal_full_scenario_fails_on_malformed_image() {
        resolve_wal_full_scenario_from(Some(OsString::from("1")), Some(OsString::from("bad")));
    }

    #[test]
    fn resolve_wal_full_scenario_runs_with_only_image_configured() {
        let raw_image =
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
        match resolve_wal_full_scenario_from(None, Some(OsString::from(raw_image))) {
            WalFullScenario::Run(image) => assert_eq!(image.as_str(), raw_image),
            WalFullScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn resolve_wal_full_scenario_runs_with_required_and_image_configured() {
        let raw_image =
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
        match resolve_wal_full_scenario_from(
            Some(OsString::from("1")),
            Some(OsString::from(raw_image)),
        ) {
            WalFullScenario::Run(image) => assert_eq!(image.as_str(), raw_image),
            WalFullScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn resolve_connection_exhaustion_scenario_skips_when_both_absent() {
        assert!(matches!(
            resolve_connection_exhaustion_scenario_from(None, None),
            ConnectionExhaustionScenario::Skip
        ));
    }

    #[test]
    #[should_panic(expected = "must be exactly")]
    fn resolve_connection_exhaustion_scenario_fails_on_malformed_required_flag() {
        resolve_connection_exhaustion_scenario_from(Some(OsString::from("true")), None);
    }

    #[test]
    #[should_panic(expected = "is not configured")]
    fn resolve_connection_exhaustion_scenario_fails_when_required_but_no_image() {
        resolve_connection_exhaustion_scenario_from(Some(OsString::from("1")), None);
    }

    #[test]
    #[should_panic(expected = "is invalid")]
    fn resolve_connection_exhaustion_scenario_fails_on_malformed_image() {
        resolve_connection_exhaustion_scenario_from(
            Some(OsString::from("1")),
            Some(OsString::from("bad")),
        );
    }

    #[test]
    fn resolve_connection_exhaustion_scenario_runs_with_only_image_configured() {
        let raw_image =
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
        match resolve_connection_exhaustion_scenario_from(None, Some(OsString::from(raw_image))) {
            ConnectionExhaustionScenario::Run(image) => assert_eq!(image.as_str(), raw_image),
            ConnectionExhaustionScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn resolve_connection_exhaustion_scenario_runs_with_required_and_image_configured() {
        let raw_image =
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
        match resolve_connection_exhaustion_scenario_from(
            Some(OsString::from("1")),
            Some(OsString::from(raw_image)),
        ) {
            ConnectionExhaustionScenario::Run(image) => assert_eq!(image.as_str(), raw_image),
            ConnectionExhaustionScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn resolve_backup_restore_scenario_skips_when_both_absent() {
        assert!(matches!(
            resolve_backup_restore_scenario_from(None, None),
            BackupRestoreScenario::Skip
        ));
    }

    #[test]
    #[should_panic(expected = "must be exactly")]
    fn resolve_backup_restore_scenario_fails_on_malformed_required_flag() {
        resolve_backup_restore_scenario_from(Some(OsString::from("true")), None);
    }

    #[test]
    #[should_panic(expected = "is not configured")]
    fn resolve_backup_restore_scenario_fails_when_required_but_no_image() {
        resolve_backup_restore_scenario_from(Some(OsString::from("1")), None);
    }

    #[test]
    #[should_panic(expected = "is invalid")]
    fn resolve_backup_restore_scenario_fails_on_malformed_image() {
        resolve_backup_restore_scenario_from(
            Some(OsString::from("1")),
            Some(OsString::from("bad")),
        );
    }

    #[test]
    fn resolve_backup_restore_scenario_runs_with_only_image_configured() {
        let raw_image =
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
        match resolve_backup_restore_scenario_from(None, Some(OsString::from(raw_image))) {
            BackupRestoreScenario::Run(image) => assert_eq!(image.as_str(), raw_image),
            BackupRestoreScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn resolve_backup_restore_scenario_runs_with_required_and_image_configured() {
        let raw_image =
            "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
        match resolve_backup_restore_scenario_from(
            Some(OsString::from("1")),
            Some(OsString::from(raw_image)),
        ) {
            BackupRestoreScenario::Run(image) => assert_eq!(image.as_str(), raw_image),
            BackupRestoreScenario::Skip => panic!("expected Run"),
        }
    }

    const PGBOUNCER_TEST_POSTGRES_IMAGE: &str =
        "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
    const PGBOUNCER_TEST_PROXY_IMAGE: &str = "ghcr.io/icoretech/pgbouncer-docker@sha256:53dc42879de6b87efed6ad239558cfa6fef6f08c5fa4acc109da5f5af1868b89";

    #[test]
    fn resolve_pgbouncer_scenario_skips_when_both_absent() {
        assert!(matches!(
            resolve_pgbouncer_scenario_from(None, None, None),
            PgBouncerScenario::Skip
        ));
    }

    #[test]
    #[should_panic(expected = "must be exactly")]
    fn resolve_pgbouncer_scenario_fails_on_malformed_required_flag() {
        resolve_pgbouncer_scenario_from(Some(OsString::from("true")), None, None);
    }

    #[test]
    #[should_panic(expected = "is set but neither")]
    fn resolve_pgbouncer_scenario_fails_when_required_but_both_absent() {
        resolve_pgbouncer_scenario_from(Some(OsString::from("1")), None, None);
    }

    #[test]
    #[should_panic(expected = "partial live PgBouncer rehearsal configuration is not allowed")]
    fn resolve_pgbouncer_scenario_fails_on_partial_configuration_postgres_only() {
        resolve_pgbouncer_scenario_from(
            None,
            Some(OsString::from(PGBOUNCER_TEST_POSTGRES_IMAGE)),
            None,
        );
    }

    #[test]
    #[should_panic(expected = "partial live PgBouncer rehearsal configuration is not allowed")]
    fn resolve_pgbouncer_scenario_fails_on_partial_configuration_proxy_only() {
        resolve_pgbouncer_scenario_from(
            None,
            None,
            Some(OsString::from(PGBOUNCER_TEST_PROXY_IMAGE)),
        );
    }

    #[test]
    #[should_panic(expected = "is invalid")]
    fn resolve_pgbouncer_scenario_fails_on_malformed_postgres_image() {
        resolve_pgbouncer_scenario_from(
            None,
            Some(OsString::from("bad")),
            Some(OsString::from(PGBOUNCER_TEST_PROXY_IMAGE)),
        );
    }

    #[test]
    #[should_panic(expected = "is invalid")]
    fn resolve_pgbouncer_scenario_fails_on_malformed_proxy_image() {
        resolve_pgbouncer_scenario_from(
            None,
            Some(OsString::from(PGBOUNCER_TEST_POSTGRES_IMAGE)),
            Some(OsString::from("bad")),
        );
    }

    #[test]
    fn resolve_pgbouncer_scenario_runs_with_only_images_configured() {
        match resolve_pgbouncer_scenario_from(
            None,
            Some(OsString::from(PGBOUNCER_TEST_POSTGRES_IMAGE)),
            Some(OsString::from(PGBOUNCER_TEST_PROXY_IMAGE)),
        ) {
            PgBouncerScenario::Run {
                postgres_image,
                pgbouncer_image,
            } => {
                assert_eq!(postgres_image.as_str(), PGBOUNCER_TEST_POSTGRES_IMAGE);
                assert_eq!(pgbouncer_image.as_str(), PGBOUNCER_TEST_PROXY_IMAGE);
            }
            PgBouncerScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn resolve_pgbouncer_scenario_runs_with_required_and_both_images_configured() {
        match resolve_pgbouncer_scenario_from(
            Some(OsString::from("1")),
            Some(OsString::from(PGBOUNCER_TEST_POSTGRES_IMAGE)),
            Some(OsString::from(PGBOUNCER_TEST_PROXY_IMAGE)),
        ) {
            PgBouncerScenario::Run {
                postgres_image,
                pgbouncer_image,
            } => {
                assert_eq!(postgres_image.as_str(), PGBOUNCER_TEST_POSTGRES_IMAGE);
                assert_eq!(pgbouncer_image.as_str(), PGBOUNCER_TEST_PROXY_IMAGE);
            }
            PgBouncerScenario::Skip => panic!("expected Run"),
        }
    }

    #[test]
    fn render_pgbouncer_ini_contains_required_settings() {
        let rendered = render_pgbouncer_ini(&PgBouncerIniConfig {
            database: "sunrise_edge_pgbouncer",
            backend_host: "sunrise-edge-pgbouncer-backend",
            backend_port: 5432,
            listen_port: 6432,
            admin_user: "postgres",
        });
        assert!(rendered.contains(
            "sunrise_edge_pgbouncer = host=sunrise-edge-pgbouncer-backend port=5432 \
             dbname=sunrise_edge_pgbouncer pool_size=1"
        ));
        assert!(rendered.contains("pool_mode = transaction"));
        assert!(rendered.contains("max_prepared_statements = 16"));
        assert!(rendered.contains("query_wait_timeout = 3"));
        assert!(rendered.contains("default_pool_size = 1"));
        assert!(rendered.contains("max_db_connections = 1"));
        assert!(rendered.contains("max_user_connections = 1"));
        assert!(rendered.contains("listen_port = 6432"));
        assert!(rendered.contains("admin_users = postgres"));
        assert!(rendered.contains("stats_users = postgres"));
        assert!(rendered.contains("auth_type = md5"));
    }

    #[test]
    #[should_panic(expected = "must be non-empty alphanumeric")]
    fn render_pgbouncer_ini_rejects_unsafe_database_field() {
        render_pgbouncer_ini(&PgBouncerIniConfig {
            database: "bad db\n[pgbouncer]",
            backend_host: "sunrise-edge-pgbouncer-backend",
            backend_port: 5432,
            listen_port: 6432,
            admin_user: "postgres",
        });
    }

    #[test]
    fn render_userlist_entry_produces_exact_double_quoted_line() {
        assert_eq!(
            render_userlist_entry("postgres", "md56914d066bef7dc5511d9bb50d9d81da4"),
            "\"postgres\" \"md56914d066bef7dc5511d9bb50d9d81da4\"\n"
        );
    }

    #[test]
    #[should_panic(expected = "must not contain a quote, backslash, or newline")]
    fn render_userlist_entry_rejects_embedded_quote_in_credential_hash() {
        render_userlist_entry("postgres", "md56914d0\"66bef7dc5511d9bb50d9d81da4");
    }

    #[test]
    #[should_panic(expected = "must not contain a quote, backslash, or newline")]
    fn render_userlist_entry_rejects_embedded_newline_in_user() {
        render_userlist_entry("post\ngres", "md56914d066bef7dc5511d9bb50d9d81da4");
    }
}
