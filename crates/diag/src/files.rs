//! Local resources: secret files, the open-file limit.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use crate::report::Check;

/// A secret file: present, a regular file, non-empty and not readable by
/// everyone. Group read is accepted (Kubernetes mounts secrets that way).
/// `required = false` turns a missing file into a skip.
pub fn secret_file(id: &str, label: &str, path: &Path, required: bool) -> Check {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if required {
                Check::fail(id, format!("{label} {} does not exist", path.display()))
                    .hint("mount the secret at this path, or change the path in the configuration")
            } else {
                Check::skip(
                    id,
                    format!("{label} {} does not exist (optional)", path.display()),
                )
            };
        }
        Err(error) => {
            return Check::fail(id, format!("{label} {}: {error}", path.display()));
        }
    };
    if !meta.is_file() {
        return Check::fail(
            id,
            format!("{label} {} is not a regular file", path.display()),
        );
    }
    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(error) => {
            return Check::fail(
                id,
                format!("{label} {} cannot be read: {error}", path.display()),
            )
            .hint("the user that runs the role must be able to read it");
        }
    };
    if content.iter().all(u8::is_ascii_whitespace) {
        return Check::fail(id, format!("{label} {} is empty", path.display()))
            .hint("an empty secret is refused at start");
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o004 != 0 {
        return Check::warn(
            id,
            format!(
                "{label} {} is readable by everyone (mode {mode:03o})",
                path.display()
            ),
        )
        .hint(format!(
            "chmod 600 {} (or 640 with a group)",
            path.display()
        ));
    }
    Check::pass(
        id,
        format!(
            "{label} {} is present, non-empty, mode {mode:03o}",
            path.display()
        ),
    )
}

/// Every regular file of a secrets directory (one level, links followed): one
/// check that warns and names the files readable by everyone. A directory that
/// does not exist is a skip.
pub fn secrets_dir_modes(id: &str, dir: &Path) -> Check {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Check::skip(
            id,
            format!("secrets directory {} cannot be listed", dir.display()),
        );
    };
    let mut files = 0usize;
    let mut open: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = std::fs::metadata(entry.path()) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        files += 1;
        if meta.permissions().mode() & 0o004 != 0 {
            open.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    open.sort();
    if open.is_empty() {
        Check::pass(
            id,
            format!(
                "{files} secret file(s) in {}, none readable by everyone",
                dir.display()
            ),
        )
    } else {
        Check::warn(
            id,
            format!(
                "{} of {files} secret file(s) in {} readable by everyone: {}",
                open.len(),
                dir.display(),
                open.join(", ")
            ),
        )
        .hint(format!("chmod o-r {}/*", dir.display()))
    }
}

/// A directory that must exist.
pub fn dir_exists(id: &str, label: &str, path: &Path, required: bool) -> Check {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Check::pass(id, format!("{label} {} exists", path.display())),
        Ok(_) => Check::fail(id, format!("{label} {} is not a directory", path.display())),
        Err(_) if !required => Check::skip(
            id,
            format!("{label} {} does not exist (optional)", path.display()),
        ),
        Err(error) => Check::fail(id, format!("{label} {}: {error}", path.display()))
            .hint("create or mount the directory, or change the path in the configuration"),
    }
}

/// A limit of `/proc/self/limits`: a number or `unlimited`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Finite(u64),
    Unlimited,
}

impl Limit {
    fn parse(word: &str) -> Option<Self> {
        if word == "unlimited" {
            Some(Self::Unlimited)
        } else {
            word.parse().ok().map(Self::Finite)
        }
    }

    fn at_least(self, n: u64) -> bool {
        match self {
            Self::Finite(v) => v >= n,
            Self::Unlimited => true,
        }
    }

    fn show(self) -> String {
        match self {
            Self::Finite(v) => v.to_string(),
            Self::Unlimited => "unlimited".to_owned(),
        }
    }
}

/// The soft and hard "Max open files" of the text of `/proc/self/limits`.
pub fn parse_nofile(text: &str) -> Option<(Limit, Limit)> {
    let line = text.lines().find(|l| l.starts_with("Max open files"))?;
    let mut words = line.split_whitespace().skip(3);
    Some((Limit::parse(words.next()?)?, Limit::parse(words.next()?)?))
}

/// The `fd.limit` check for given limits: fail when the soft limit is below
/// `required`; `what` names the need ("2 per tunnel and 512 spare").
pub fn fd_limit_check(limits: (Limit, Limit), required: u64, what: &str) -> Check {
    let id = "system.open_files";
    let (soft, hard) = limits;
    if soft.at_least(required) {
        Check::pass(
            id,
            format!(
                "open files limit {} covers the {required} needed ({what})",
                soft.show()
            ),
        )
    } else if hard.at_least(required) {
        Check::fail(
            id,
            format!("open files soft limit is {}, {required} are needed ({what})", soft.show()),
        )
        .hint(format!("raise it: `ulimit -n {required}` or LimitNOFILE={required} in the unit (the hard limit allows it)"))
    } else {
        Check::fail(
            id,
            format!("open files limit is {}/{} (soft/hard), {required} are needed ({what})", soft.show(), hard.show()),
        )
        .hint(format!("raise the hard limit to at least {required}: LimitNOFILE={required}, or a container `--ulimit nofile`"))
    }
}

/// [`fd_limit_check`] with this process's limits, read from `/proc/self/limits`;
/// skipped where that file does not exist.
pub fn fd_limit(required: u64, what: &str) -> Check {
    match std::fs::read_to_string("/proc/self/limits") {
        Ok(text) => match parse_nofile(&text) {
            Some(limits) => fd_limit_check(limits, required, what),
            None => Check::skip(
                "system.open_files",
                "cannot read the open files limit from /proc/self/limits",
            ),
        },
        Err(_) => Check::skip(
            "system.open_files",
            "/proc/self/limits does not exist on this system",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;

    const LIMITS: &str = "Limit                     Soft Limit           Hard Limit           Units     \n\
                          Max processes             63000                63000                processes \n\
                          Max open files            1024                 1048576              files     \n";

    #[test]
    fn the_nofile_line_parses() {
        assert_eq!(
            parse_nofile(LIMITS),
            Some((Limit::Finite(1024), Limit::Finite(1_048_576)))
        );
        let unl = "Max open files            unlimited            unlimited            files\n";
        assert_eq!(
            parse_nofile(unl),
            Some((Limit::Unlimited, Limit::Unlimited))
        );
        assert_eq!(parse_nofile("nothing"), None);
    }

    #[test]
    fn the_threshold_is_the_required_count() {
        let l = |s, h| (Limit::Finite(s), Limit::Finite(h));
        assert_eq!(
            fd_limit_check(l(1024, 1 << 20), 1024, "x").status,
            Status::Pass
        );
        let soft_low = fd_limit_check(l(1023, 1 << 20), 1024, "x");
        assert_eq!(soft_low.status, Status::Fail);
        assert!(
            soft_low
                .hint
                .as_deref()
                .is_some_and(|h| h.contains("ulimit -n 1024"))
        );
        let hard_low = fd_limit_check(l(1023, 2048), 4096, "x");
        assert_eq!(hard_low.status, Status::Fail);
        assert!(
            hard_low
                .hint
                .as_deref()
                .is_some_and(|h| h.contains("hard limit"))
        );
        assert_eq!(
            fd_limit_check((Limit::Unlimited, Limit::Unlimited), u64::MAX, "x").status,
            Status::Pass
        );
    }

    #[test]
    fn this_process_has_a_readable_limit() {
        let check = fd_limit(16, "test");
        assert!(
            matches!(check.status, Status::Pass | Status::Skip),
            "{check:?}"
        );
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("proxyx-diag-files-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    #[test]
    fn secret_files_are_judged_on_presence_content_and_mode() {
        let dir = scratch("secrets");
        let path = dir.join("token");
        assert_eq!(
            secret_file("s.t", "token", &path, true).status,
            Status::Fail
        );
        assert_eq!(
            secret_file("s.t", "token", &path, false).status,
            Status::Skip
        );
        std::fs::write(&path, "\n").expect("write");
        assert_eq!(
            secret_file("s.t", "token", &path, true).status,
            Status::Fail
        );
        std::fs::write(&path, "s3cret\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let world = secret_file("s.t", "token", &path, true);
        assert_eq!(world.status, Status::Warn, "{world:?}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        assert_eq!(
            secret_file("s.t", "token", &path, true).status,
            Status::Pass
        );
        assert_eq!(secret_file("s.t", "token", &dir, true).status, Status::Fail);
        assert_eq!(dir_exists("d", "dir", &dir, true).status, Status::Pass);
        assert_eq!(
            dir_exists("d", "dir", &dir.join("x"), false).status,
            Status::Skip
        );
        assert_eq!(secrets_dir_modes("m", &dir).status, Status::Pass);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let open = secrets_dir_modes("m", &dir);
        assert_eq!(open.status, Status::Warn, "{open:?}");
        assert!(open.message.contains("token"), "{open:?}");
        assert_eq!(secrets_dir_modes("m", &dir.join("x")).status, Status::Skip);
        let _ = std::fs::remove_dir_all(dir);
    }
}
