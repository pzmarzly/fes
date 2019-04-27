use protocol_derive::Protocol;
use crate::id::PartialIdentity;

#[derive(Debug, PartialEq, Protocol)]
pub enum ClientToServer {
    UpgradeRequest(String),
}

#[derive(Debug, PartialEq, Protocol)]
pub enum ServerToClient {
    UpgradeResponse(String, PartialIdentity),
}
