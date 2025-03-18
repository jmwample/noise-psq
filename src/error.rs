// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Errors that occur during Nym noise negotiation

use snow::Error;
use std::io;
use std::num::TryFromIntError;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum NoiseError {
    #[error("encountered a Noise decryption error")]
    DecryptionError,

    #[error("encountered a Noise Protocol error - {0}")]
    ProtocolError(Error),

    #[error("encountered an IO error - {0}")]
    IoError(#[from] io::Error),

    #[error("Incorrect state")]
    IncorrectStateError,

    #[error("Handshake timeout")]
    HandshakeTimeoutError(#[from] tokio::time::error::Elapsed),

    #[error("Handshake did not complete")]
    HandshakeError,

    #[error(transparent)]
    IntConversionError(#[from] TryFromIntError),
}

impl From<Error> for NoiseError {
    fn from(err: Error) -> Self {
        match err {
            Error::Decrypt => NoiseError::DecryptionError,
            err => NoiseError::ProtocolError(err),
        }
    }
}
