// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Errors that occur during Nym noise negotiation

use std::io;
use std::num::TryFromIntError;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum NoiseError {
    #[error("encountered a Noise decryption error")]
    DecryptionError,

    #[error("encountered a Noise Protocol error - {0}")]
    ProtocolError(snow::Error),

    #[error("encountered an PSQ error {0:?}")]
    PsqError(libcrux_psq::Error),

    #[error("encountered an PSQ error {0:?}")]
    KemError(libcrux_kem::Error),

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

impl From<snow::Error> for NoiseError {
    fn from(err: snow::Error) -> Self {
        match err {
            snow::Error::Decrypt => NoiseError::DecryptionError,
            err => NoiseError::ProtocolError(err),
        }
    }
}

impl From<libcrux_psq::Error> for NoiseError {
    fn from(value: libcrux_psq::Error) -> Self {
        NoiseError::PsqError(value)
    }
}

impl From<libcrux_kem::Error> for NoiseError {
    fn from(value: libcrux_kem::Error) -> Self {
        NoiseError::KemError(value)
    }
}
