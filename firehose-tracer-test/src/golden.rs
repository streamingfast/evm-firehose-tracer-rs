//! Golden-file comparison for JSON projections, with a single documented regeneration command.
//!
//! Run the suite with `GOLDEN_UPDATE=1` to rewrite every golden it touches. The pretty-printed
//! JSON written on update *is* the golden — there is no derived side file that can silently drift
//! out of sync with it.
//!
//! The comparison itself does no diffing: [`is_json_equal`](Golden::is_json_equal) and
//! [`is_text_equal`](Golden::is_text_equal) return a [`BlockDiff`] carrying the golden and captured
//! sides verbatim, and it is up to the caller to assert on it however it likes —
//! [`BlockDiff::assert_equal`], `pretty_assertions`, or a bespoke report over the `NotEqual`
//! fields. That reuses the diff the test framework already renders, instead of shipping another
//! diff engine.

use std::path::Path;

use serde_json::Value;

/// The outcome of comparing a rendering against a golden.
#[derive(Debug, Clone)]
pub enum BlockDiff {
    /// The rendering matched the golden, or the golden was just regenerated. Carries the content.
    Equal(String),
    /// The rendering differs from the golden.
    NotEqual {
        /// Human-readable context: which golden, and how to regenerate it.
        message: String,
        /// The golden's current content (empty when the golden does not exist yet).
        golden: String,
        /// The freshly captured rendering.
        new: String,
    },
}

impl BlockDiff {
    /// Returns `true` when the rendering matched the golden.
    pub fn is_equal(&self) -> bool {
        matches!(self, Self::Equal(_))
    }

    /// Asserts the two sides are equal, panicking with the framework's own value diff otherwise.
    ///
    /// A convenience for the common case; a caller wanting a different report can match on the
    /// variants directly instead.
    #[track_caller]
    pub fn assert_equal(&self) {
        if let Self::NotEqual {
            message,
            golden,
            new,
        } = self
        {
            assert_eq!(golden, new, "{message}");
        }
    }
}

/// Comparison and regeneration of JSON projection goldens.
#[derive(Debug)]
pub struct Golden;

impl Golden {
    /// Environment variable that switches every golden assertion into regeneration mode.
    pub const UPDATE_ENV: &'static str = "GOLDEN_UPDATE";

    /// Returns `true` when the suite was asked to regenerate goldens.
    pub fn update_requested() -> bool {
        std::env::var_os(Self::UPDATE_ENV).is_some_and(|value| !value.is_empty())
    }

    /// Compares a JSON projection against the golden at `path`, or rewrites it under
    /// `GOLDEN_UPDATE=1`.
    ///
    /// The value is serialised as pretty JSON with a trailing newline before comparison, so the
    /// golden is stable and line-diffable.
    pub fn is_json_equal(projection: &Value, path: &Path) -> eyre::Result<BlockDiff> {
        let mut rendered = serde_json::to_string_pretty(projection).map_err(|error| {
            eyre::eyre!("serialising projection for {}: {error}", path.display())
        })?;
        rendered.push('\n');
        Self::is_text_equal(&rendered, path)
    }

    /// Compares `rendered` against the golden at `path`, or rewrites it under `GOLDEN_UPDATE=1`.
    ///
    /// Returns an [`Err`] only for an I/O failure the caller cannot act on; a missing golden and a
    /// mismatch are both reported as [`BlockDiff::NotEqual`], not as errors.
    pub fn is_text_equal(rendered: &str, path: &Path) -> eyre::Result<BlockDiff> {
        if Self::update_requested() {
            Self::write(rendered, path)?;
            return Ok(BlockDiff::Equal(rendered.to_owned()));
        }

        let golden = match std::fs::read_to_string(path) {
            Ok(golden) => golden,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BlockDiff::NotEqual {
                    message: format!(
                        "golden {} does not exist yet — create it with `{}=1 cargo test …`",
                        path.display(),
                        Self::UPDATE_ENV,
                    ),
                    golden: String::new(),
                    new: rendered.to_owned(),
                });
            }
            Err(error) => {
                return Err(eyre::eyre!("reading golden {}: {error}", path.display()));
            }
        };

        if golden == rendered {
            return Ok(BlockDiff::Equal(rendered.to_owned()));
        }

        Ok(BlockDiff::NotEqual {
            message: format!(
                "captured projection does not match golden {} — regenerate with `{}=1 cargo \
                 test …` once every change is understood",
                path.display(),
                Self::UPDATE_ENV,
            ),
            golden,
            new: rendered.to_owned(),
        })
    }

    /// Writes `rendered` to `path`, creating the parent directory if needed.
    fn write(rendered: &str, path: &Path) -> eyre::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                eyre::eyre!("creating golden directory {}: {error}", parent.display())
            })?;
        }

        std::fs::write(path, rendered)
            .map_err(|error| eyre::eyre!("writing golden {}: {error}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard};

    use serde_json::json;

    use super::*;

    /// Serialises every test in this module.
    ///
    /// `GOLDEN_UPDATE` is process-wide and cargo runs a crate's tests concurrently, so a test that
    /// sets it would otherwise leak into a test that must see it unset.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Takes the shared lock and guarantees `GOLDEN_UPDATE` starts unset.
    fn guarded() -> MutexGuard<'static, ()> {
        let guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        set_update(None);
        guard
    }

    /// Sets or clears `GOLDEN_UPDATE`. Only ever called while [`ENV_LOCK`] is held.
    fn set_update(value: Option<&str>) {
        // SAFETY: ENV_LOCK serialises every mutation within this binary, and nothing here reads
        // the environment from another thread.
        unsafe {
            match value {
                Some(value) => std::env::set_var(Golden::UPDATE_ENV, value),
                None => std::env::remove_var(Golden::UPDATE_ENV),
            }
        }
    }

    /// Regenerates the golden at `path` from `projection`.
    fn regenerate(projection: &Value, path: &Path) {
        set_update(Some("1"));
        let result = Golden::is_json_equal(projection, path);
        set_update(None);

        assert!(result.expect("regeneration must succeed").is_equal());
    }

    #[test]
    fn a_missing_golden_is_reported_as_not_equal_with_an_empty_golden_side() {
        let _guard = guarded();
        let path = Path::new("/tmp/does-not-exist/firehose-golden-test.json");

        let diff = Golden::is_json_equal(&json!({"a": 1}), path).expect("no I/O error");

        match diff {
            BlockDiff::NotEqual {
                message,
                golden,
                new,
            } => {
                assert!(message.contains("does not exist yet"), "{message}");
                assert!(message.contains("GOLDEN_UPDATE=1"), "{message}");
                assert!(golden.is_empty(), "there is no golden to show");
                assert!(
                    new.contains("\"a\": 1"),
                    "the captured side carries the rendering"
                );
            }
            BlockDiff::Equal(_) => panic!("a missing golden cannot be equal"),
        }
    }

    #[test]
    fn a_matching_projection_is_equal() {
        let _guard = guarded();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("projection.json");
        let projection = json!({"status": "SUCCEEDED", "calls": [{"index": 1}]});

        regenerate(&projection, &path);

        let diff = Golden::is_json_equal(&projection, &path).expect("no I/O error");
        assert!(diff.is_equal(), "the regenerated golden must match");
    }

    #[test]
    fn regeneration_writes_pretty_json_with_a_trailing_newline() {
        let _guard = guarded();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("projection.json");

        regenerate(&json!({"b": 2, "a": 1}), &path);

        let written = std::fs::read_to_string(&path).expect("the golden must exist");
        assert_eq!(
            written, "{\n  \"a\": 1,\n  \"b\": 2\n}\n",
            "the parent directory is created and the rendering is stable"
        );
    }

    #[test]
    fn a_mismatch_carries_both_sides_verbatim() {
        let _guard = guarded();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("projection.json");

        regenerate(&json!({"old_value": "0x0a"}), &path);

        let diff =
            Golden::is_json_equal(&json!({"old_value": "0x0b"}), &path).expect("no I/O error");

        match diff {
            BlockDiff::NotEqual {
                message,
                golden,
                new,
            } => {
                assert!(message.contains("does not match golden"), "{message}");
                assert!(
                    golden.contains("0x0a"),
                    "the golden side is the stored content"
                );
                assert!(new.contains("0x0b"), "the new side is the fresh rendering");
            }
            BlockDiff::Equal(_) => panic!("changed values must not be equal"),
        }
    }

    #[test]
    fn assert_equal_panics_on_a_mismatch() {
        let diff = BlockDiff::NotEqual {
            message: "context".to_owned(),
            golden: "a".to_owned(),
            new: "b".to_owned(),
        };

        let result = std::panic::catch_unwind(|| diff.assert_equal());
        assert!(
            result.is_err(),
            "assert_equal must panic when the sides differ"
        );
    }

    #[test]
    fn update_is_requested_only_by_a_non_empty_value() {
        let _guard = guarded();

        assert!(!Golden::update_requested(), "unset means compare");

        set_update(Some(""));
        assert!(!Golden::update_requested(), "an empty value means compare");

        set_update(Some("1"));
        assert!(Golden::update_requested());

        set_update(None);
    }
}
