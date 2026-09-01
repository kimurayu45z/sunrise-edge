//! Strict, manual `--flag value` argument parsing shared by every
//! subcommand.
//!
//! There is no external argument-parsing crate here (this binary's only
//! dependency is `sunrise-edge-client`): every flag is declared explicitly
//! by name, duplicates and unknown flags are rejected, and any token that is
//! not a declared flag is treated as an unexpected positional argument.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;

/// One flag this command accepts.
#[derive(Clone, Copy, Debug)]
pub struct FlagSpec {
    /// Exact flag name, including the leading `--`.
    pub name: &'static str,
    /// Whether this flag takes exactly one following value, or is a
    /// standalone boolean switch.
    pub takes_value: bool,
}

/// A boolean-switch flag spec (`--wait`, not `--wait <value>`).
#[must_use]
pub const fn switch(name: &'static str) -> FlagSpec {
    FlagSpec {
        name,
        takes_value: false,
    }
}

/// A scalar `--flag value` spec.
#[must_use]
pub const fn scalar(name: &'static str) -> FlagSpec {
    FlagSpec {
        name,
        takes_value: true,
    }
}

/// The result of successfully parsing one subcommand's arguments.
#[derive(Debug, Default)]
pub struct ParsedArgs {
    values: BTreeMap<&'static str, String>,
}

impl ParsedArgs {
    /// Returns whether a switch/scalar flag was present at all.
    #[must_use]
    pub fn is_present(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// Returns a required scalar flag's value.
    pub fn require(&self, name: &'static str) -> Result<&str, ArgsError> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or(ArgsError::MissingFlag(name))
    }
}

/// Parses `args` against the declared `specs`, in any order.
///
/// Rejects a token that is not a declared flag (as an unexpected
/// positional argument), an unknown flag, a flag repeated more than once,
/// a scalar flag with no following value, and any value that is not valid
/// UTF-8. A scalar flag's following token starting with `--` is treated as
/// a missing value for the preceding flag rather than consumed as its
/// value: values beginning with `--` are intentionally unsupported by this
/// strict CLI, so `--amount --gas-limit` is rejected instead of silently
/// treating `--gas-limit` as `--amount`'s value.
pub fn parse_flags<I>(args: I, specs: &[FlagSpec]) -> Result<ParsedArgs, ArgsError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut values: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut iter = args.into_iter();

    while let Some(token_os) = iter.next() {
        let token = token_os
            .to_str()
            .ok_or(ArgsError::NonUtf8Token)?
            .to_string();
        if !token.starts_with("--") {
            return Err(ArgsError::UnexpectedPositional(token));
        }
        let spec = specs
            .iter()
            .find(|spec| spec.name == token)
            .ok_or_else(|| ArgsError::UnknownFlag(token.clone()))?;
        if values.contains_key(spec.name) {
            return Err(ArgsError::DuplicateFlag(spec.name));
        }
        if spec.takes_value {
            let value_os = iter.next().ok_or(ArgsError::MissingValue(spec.name))?;
            let value = value_os
                .to_str()
                .ok_or(ArgsError::NonUtf8Value(spec.name))?
                .to_string();
            if value.starts_with("--") {
                return Err(ArgsError::MissingValue(spec.name));
            }
            values.insert(spec.name, value);
        } else {
            values.insert(spec.name, String::new());
        }
    }

    Ok(ParsedArgs { values })
}

/// Fail-closed argument-parsing errors.
#[derive(Debug)]
pub enum ArgsError {
    /// A token was not valid UTF-8.
    NonUtf8Token,
    /// A flag's value was not valid UTF-8.
    NonUtf8Value(&'static str),
    /// A token that is not a declared flag appeared where a flag was
    /// expected.
    UnexpectedPositional(String),
    /// A flag not declared for this subcommand was supplied.
    UnknownFlag(String),
    /// A flag appeared more than once.
    DuplicateFlag(&'static str),
    /// A scalar flag had no following value.
    MissingValue(&'static str),
    /// A required flag was never supplied.
    MissingFlag(&'static str),
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8Token => f.write_str("command-line argument is not valid UTF-8"),
            Self::NonUtf8Value(flag) => write!(f, "value for {flag} is not valid UTF-8"),
            Self::UnexpectedPositional(token) => {
                write!(f, "unexpected positional argument: {token:?}")
            }
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
            Self::DuplicateFlag(flag) => write!(f, "flag may appear only once: {flag}"),
            Self::MissingValue(flag) => write!(f, "flag requires a value: {flag}"),
            Self::MissingFlag(flag) => write!(f, "required flag is missing: {flag}"),
        }
    }
}

impl std::error::Error for ArgsError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    const SPECS: &[FlagSpec] = &[scalar("--endpoint"), scalar("--amount"), switch("--wait")];

    #[test]
    fn parses_scalars_and_switches_in_any_order() {
        let parsed = parse_flags(
            os(&["--wait", "--amount", "5", "--endpoint", "127.0.0.1:7400"]),
            SPECS,
        )
        .unwrap();
        assert_eq!(parsed.require("--amount").unwrap(), "5");
        assert_eq!(parsed.require("--endpoint").unwrap(), "127.0.0.1:7400");
        assert!(parsed.is_present("--wait"));
    }

    #[test]
    fn rejects_duplicate_flags() {
        let error = parse_flags(os(&["--amount", "1", "--amount", "2"]), SPECS).unwrap_err();
        assert!(matches!(error, ArgsError::DuplicateFlag("--amount")));
    }

    #[test]
    fn rejects_unknown_flags() {
        let error = parse_flags(os(&["--bogus", "1"]), SPECS).unwrap_err();
        assert!(matches!(error, ArgsError::UnknownFlag(flag) if flag == "--bogus"));
    }

    #[test]
    fn rejects_missing_scalar_value() {
        let error = parse_flags(os(&["--amount"]), SPECS).unwrap_err();
        assert!(matches!(error, ArgsError::MissingValue("--amount")));
    }

    #[test]
    fn rejects_a_following_flag_like_token_as_a_missing_value() {
        let error =
            parse_flags(os(&["--amount", "--endpoint", "127.0.0.1:7400"]), SPECS).unwrap_err();
        assert!(matches!(error, ArgsError::MissingValue("--amount")));

        // Also rejected when the following token is `--` itself or an
        // unknown `--`-prefixed token: this is purely a prefix check on the
        // very next token, not a lookup against declared flag names.
        let error = parse_flags(os(&["--amount", "--", "5"]), SPECS).unwrap_err();
        assert!(matches!(error, ArgsError::MissingValue("--amount")));

        let error = parse_flags(os(&["--amount", "--bogus"]), SPECS).unwrap_err();
        assert!(matches!(error, ArgsError::MissingValue("--amount")));
    }

    #[test]
    fn rejects_unexpected_positional_arguments() {
        let error = parse_flags(os(&["extra", "--amount", "1"]), SPECS).unwrap_err();
        assert!(matches!(error, ArgsError::UnexpectedPositional(token) if token == "extra"));

        let trailing = parse_flags(os(&["--amount", "1", "trailing"]), SPECS).unwrap_err();
        assert!(matches!(trailing, ArgsError::UnexpectedPositional(token) if token == "trailing"));
    }

    #[test]
    fn require_reports_a_missing_flag() {
        let parsed = parse_flags(os(&["--wait"]), SPECS).unwrap();
        assert!(matches!(
            parsed.require("--amount"),
            Err(ArgsError::MissingFlag("--amount"))
        ));
    }
}
