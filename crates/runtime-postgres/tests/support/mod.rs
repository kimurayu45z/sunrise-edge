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
fn run_docker_command_bounded_output(mut command: Command, label: &str) -> io::Result<String> {
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
    let mut child: Child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            return Err(error);
        }
    };
    let deadline = Instant::now() + DOCKER_COMMAND_TIMEOUT;
    let status_result: io::Result<()> = loop {
        let stdout_len: u64 = fs::metadata(&stdout_path)
            .map(|value| value.len())
            .unwrap_or(0);
        let stderr_len: u64 = fs::metadata(&stderr_path)
            .map(|value| value.len())
            .unwrap_or(0);
        if stdout_len > DOCKER_COMMAND_OUTPUT_MAX_BYTES
            || stderr_len > DOCKER_COMMAND_OUTPUT_MAX_BYTES
        {
            let _ = child.kill();
            let _ = child.wait();
            break Err(io::Error::other(format!(
                "{label} exceeded the {DOCKER_COMMAND_OUTPUT_MAX_BYTES}-byte output cap and was killed"
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
    let stdout_result = read_capped_file(&stdout_path, DOCKER_COMMAND_OUTPUT_MAX_BYTES);
    let stderr_result = read_capped_file(&stderr_path, DOCKER_COMMAND_OUTPUT_MAX_BYTES);
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
        let postgres_password = random_hex_token(32);
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
        let mut full_args: Vec<&str> =
            vec!["exec", "--user", "postgres", self.container_id.as_str()];
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
}
