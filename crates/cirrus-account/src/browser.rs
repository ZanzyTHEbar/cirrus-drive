use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use zbus::zvariant::{OwnedObjectPath, Value};

/// Opens a one-time authorization URL without logging or persisting it.
pub trait Browser {
    /// Opens the authorization URL in an external browser.
    ///
    /// # Errors
    /// Returns an error if the browser cannot be requested.
    fn open(&self, authorization_url: &str) -> io::Result<()>;
}

/// Opens the system browser through the desktop portal, not process arguments.
#[derive(Debug, Default)]
pub struct PortalBrowser {
    // Portal requests are asynchronous and belong to the calling connection.
    connection: Mutex<Option<zbus::blocking::Connection>>,
}

impl Browser for PortalBrowser {
    fn open(&self, authorization_url: &str) -> io::Result<()> {
        let connection = zbus::blocking::Connection::session()
            .map_err(|_| io::Error::other("desktop session bus is unavailable"))?;
        let proxy = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.OpenURI",
        )
        .map_err(|_| io::Error::other("desktop browser portal is unavailable"))?;
        let options: HashMap<&str, Value<'_>> = HashMap::new();
        let _: OwnedObjectPath = proxy
            .call("OpenURI", &("", authorization_url, options))
            .map_err(|_| io::Error::other("desktop browser portal could not open authorization"))?;
        drop(proxy);
        *self
            .connection
            .lock()
            .map_err(|_| io::Error::other("browser portal lock failed"))? = Some(connection);
        Ok(())
    }
}
