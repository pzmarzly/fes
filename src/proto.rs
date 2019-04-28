use protocol_derive::Protocol;

use crate::signature::SigningPubKey;

#[derive(Debug, PartialEq, Protocol)]
pub enum ClientToServer {
    UpgradeRequest(String),
}

#[derive(Debug, PartialEq, Protocol)]
pub enum ServerToClient {
    UpgradeResponse(String, SigningPubKey),
}
