use alloc::vec::Vec;
use core::fmt::Debug;

use crate::Error;

/// Client-side PAKE hook for integrating non-standard key exchanges into TLS.
pub trait PakeClient: Debug + Send + Sync {
    /// Returns the opaque PAKE extension payload to place in `ClientHello`.
    fn client_hello_extension(&self) -> Result<Vec<u8>, Error>;

    /// Consumes the server's `ServerHello` PAKE extension payload and returns
    /// the PAKE shared secret bytes that should feed the TLS 1.3 handshake secret.
    fn complete_with_server_hello_extension(
        &self,
        server_hello_extension: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

/// Server-side PAKE hook for integrating non-standard key exchanges into TLS.
pub trait PakeServer: Debug + Send + Sync {
    /// Consumes the client's `ClientHello` PAKE extension payload and returns:
    /// 1) the `ServerHello` PAKE extension payload to send back
    /// 2) the PAKE shared secret bytes that should feed the TLS 1.3 handshake secret
    fn handle_client_hello_extension(
        &self,
        client_hello_extension: &[u8],
    ) -> Result<PakeServerResponse, Error>;
}

/// Result produced by [`PakeServer::handle_client_hello_extension`].
#[derive(Clone, Debug)]
pub struct PakeServerResponse {
    /// Opaque PAKE payload for the server's `ServerHello` extension.
    pub server_hello_extension: Vec<u8>,
    /// PAKE shared secret bytes used as the TLS 1.3 handshake input keying material.
    pub shared_secret: Vec<u8>,
}
