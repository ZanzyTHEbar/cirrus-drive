//! Concrete credential ownership, independent of mutable principal-lock mode.

#[cfg(target_os = "linux")]
pub(crate) struct Context {
    pub(super) bus: zbus::blocking::Connection,
}

#[cfg(target_os = "linux")]
impl Context {
    pub(crate) fn connection(&self) -> &zbus::blocking::Connection {
        &self.bus
    }
}

#[cfg(target_os = "macos")]
pub(crate) use darwin::Context;
#[cfg(target_os = "macos")]
pub(crate) use darwin::KeychainConfig;

#[cfg(target_os = "macos")]
mod darwin {
    use std::os::fd::OwnedFd;
    use std::sync::Arc;

    use rustix::fs::{self, FileType};
    use rustix::process;

    use crate::account_storage::StorageRoot;
    use crate::secrets::CredentialError;

    pub(crate) const MARKER: &str = "credentials.lock";
    pub(crate) const CONTENT: &[u8] = b"cirrus-drive credential writer lock v1\n";

    /// Explicit Keychain access group shared by the native app and extension.
    ///
    /// This is not the filesystem App Group. The OS checks actual entitlements
    /// on every Keychain operation; construction does not provision membership.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct KeychainConfig {
        access_group: String,
    }

    impl KeychainConfig {
        /// Validates an explicitly supplied group without contacting Keychain.
        ///
        /// # Errors
        /// Rejects empty, unbounded, whitespace or control-containing groups.
        pub(crate) fn new(access_group: &str) -> Result<Self, CredentialError> {
            if access_group.is_empty()
                || access_group.len() > 1024
                || access_group
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(CredentialError::invalid("Keychain access group is invalid"));
            }
            Ok(Self {
                access_group: access_group.to_owned(),
            })
        }
    }

    struct Ownership {
        config: KeychainConfig,
        // None is deliberately read-only: never acquire a writer during save.
        writer: Option<OwnedFd>,
        root: StorageRoot,
    }

    // Store clones only this concrete ownership handle, not Guard. A Store may
    // survive principal downgrade without borrowing the whole mutable Guard;
    // the same writer open-file description remains held, never reopened.
    #[derive(Clone)]
    pub(crate) struct Context(Arc<Ownership>);

    impl Context {
        pub(crate) const MARKER: &str = MARKER;
        pub(crate) const CONTENT: &[u8] = CONTENT;

        pub(crate) fn new(
            config: &KeychainConfig,
            root: StorageRoot,
            writer: Option<OwnedFd>,
        ) -> Result<Self, CredentialError> {
            let context = Self(Arc::new(Ownership {
                config: config.clone(),
                writer,
                root,
            }));
            context.revalidate()?;
            Ok(context)
        }

        pub(crate) fn access_group(&self) -> &str {
            &self.0.config.access_group
        }

        pub(crate) fn revalidate_principal(
            &self,
            principal: &OwnedFd,
            marker: &str,
            content: &[u8],
        ) -> Result<(), CredentialError> {
            let changed = || CredentialError::invalid("retained account ownership changed");
            // Guard has revalidated this same retained storage capability.
            // Only metadata and bounded pread touch the retained marker OFDs.
            validate_marker(self.0.root.directory(), principal, marker, content)
                .map_err(|_| changed())?;
            self.revalidate()
        }

        pub(crate) fn require_writer(&self) -> Result<(), CredentialError> {
            if self.0.writer.is_none() {
                return Err(CredentialError::invalid(
                    "read-only account ownership cannot save credentials",
                ));
            }
            self.revalidate()
        }

        pub(crate) fn revalidate(&self) -> Result<(), CredentialError> {
            if self.access_group().is_empty() {
                return Err(CredentialError::invalid(
                    "Keychain access group is required",
                ));
            }
            if let Some(fd) = &self.0.writer {
                validate_marker(self.0.root.directory(), fd, MARKER, CONTENT)
                    .map_err(|_| CredentialError::invalid("credential writer ownership changed"))?;
            }
            Ok(())
        }
    }

    // Validate either retained coordination OFD without reopening, cloning,
    // seeking or flocking it. This never touches a database descriptor.
    fn validate_marker(
        directory: &OwnedFd,
        fd: &OwnedFd,
        marker: &str,
        expected: &[u8],
    ) -> Result<(), CredentialError> {
        let changed = || CredentialError::invalid("retained account ownership changed");
        // Both internal versioned marker contents fit this fixed bound.
        let mut bytes = [0; 128];
        if expected.len() >= bytes.len() {
            return Err(changed());
        }
        let stat = fs::fstat(fd).map_err(|_| changed())?;
        let named =
            fs::statat(directory, marker, fs::AtFlags::SYMLINK_NOFOLLOW).map_err(|_| changed())?;
        for s in [&stat, &named] {
            if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
                || s.st_uid != process::geteuid().as_raw()
                || s.st_mode & 0o7777 != 0o600
                || s.st_nlink != 1
                || s.st_size != expected.len() as i64
            {
                return Err(changed());
            }
        }
        if (stat.st_dev, stat.st_ino) != (named.st_dev, named.st_ino) {
            return Err(changed());
        }
        super::super::darwin_acl::check_file(fd).map_err(|_| changed())?;
        let size =
            rustix::io::pread(fd, &mut bytes[..expected.len() + 1], 0).map_err(|_| changed())?;
        if &bytes[..size] != expected {
            return Err(changed());
        }
        Ok(())
    }
}
