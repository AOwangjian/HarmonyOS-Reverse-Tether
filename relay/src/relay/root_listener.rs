// The register process creates this loopback listener in the root network
// namespace before starting the relay in its device network namespace.
// Accepted USB tunnel sockets retain the root namespace; newly created
// Internet sockets use the isolated namespace and its kernel qdiscs.
use std::io;
use mio::net::TcpListener;

pub fn inherited(port: u16) -> io::Result<Option<TcpListener>> {
    let value = match std::env::var("PI_REGISTER_LISTEN_FD") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid inherited listener")),
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::FromRawFd;
        let fd = value.parse::<i32>().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid listener fd"))?;
        if fd < 3 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "listener fd must be at least 3")); }
        // Ownership is transferred by the parent through exec's inherited-fd
        // contract. This constructor runs once, before the selector starts.
        let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        let address = listener.local_addr()?;
        if !address.ip().is_loopback() || address.port() != port {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "inherited listener must match the loopback port"));
        }
        listener.set_nonblocking(true)?;
        Ok(Some(TcpListener::from_std(listener)?))
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = (value, port); Err(io::Error::new(io::ErrorKind::Unsupported, "inherited listener requires Linux")) }
}
