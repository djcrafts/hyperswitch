//! Cryptography utilities for connectors
//! 
//! This module provides a consistent interface to the cryptographic functions in common_utils.
//! Connectors should use these utilities instead of implementing their own cryptographic
//! operations or using the ring crate directly.

use common_utils::{
    consts::BASE64_ENGINE, 
    crypto::{self, GenerateDigest, HmacSha256, SignMessage, VerifySignature},
    errors::{self, CustomResult},
};
use error_stack::report;
use masking::Secret;

/// Generate a SHA256 HMAC signature for the given message and secret key
/// 
/// # Arguments
/// 
/// * `message` - The message to sign
/// * `secret_key` - The secret key to use for signing
/// 
/// # Returns
/// 
/// A hex-encoded string containing the signature
pub fn generate_hmac_sha256_signature(
    message: &[u8],
    secret_key: &[u8],
) -> CustomResult<String, errors::CryptoError> {
    let signature = HmacSha256
        .sign_message(secret_key, message)
        .map_err(|error| report!(error))?;
    Ok(hex::encode(signature))
}

/// Generate a SHA256 HMAC signature and encode it using base64
/// 
/// # Arguments
/// 
/// * `message` - The message to sign
/// * `secret_key` - The secret key to use for signing
/// 
/// # Returns
/// 
/// A base64-encoded string containing the signature
pub fn generate_hmac_sha256_base64_signature(
    message: &[u8], 
    secret_key: &[u8],
) -> CustomResult<String, errors::CryptoError> {
    let signature = HmacSha256
        .sign_message(secret_key, message)
        .map_err(|error| report!(error))?;
    Ok(BASE64_ENGINE.encode(signature))
}

/// Verify a SHA256 HMAC signature
/// 
/// # Arguments
/// 
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
/// * `secret_key` - The secret key used for signing
/// 
/// # Returns
/// 
/// `true` if the signature is valid, `false` otherwise
pub fn verify_hmac_sha256_signature(
    message: &[u8],
    signature: &[u8],
    secret_key: &[u8],
) -> CustomResult<bool, errors::CryptoError> {
    HmacSha256.verify_signature(secret_key, signature, message)
}

/// Generate a SHA256 digest for the given message
/// 
/// # Arguments
/// 
/// * `message` - The message to hash
/// 
/// # Returns
/// 
/// A vector containing the digest
pub fn generate_sha256_digest(
    message: &[u8],
) -> CustomResult<Vec<u8>, errors::CryptoError> {
    crypto::Sha256.generate_digest(message)
}

/// Generate a SHA256 digest and encode it as a hex string
/// 
/// # Arguments
/// 
/// * `message` - The message to hash
/// 
/// # Returns
/// 
/// A hex-encoded string containing the digest
pub fn generate_sha256_hex_digest(
    message: &[u8],
) -> CustomResult<String, errors::CryptoError> {
    let digest = generate_sha256_digest(message)?;
    Ok(hex::encode(digest))
}

/// Generate a SHA256 digest and encode it using base64
/// 
/// # Arguments
/// 
/// * `message` - The message to hash
/// 
/// # Returns
/// 
/// A base64-encoded string containing the digest
pub fn generate_sha256_base64_digest(
    message: &[u8],
) -> CustomResult<String, errors::CryptoError> {
    let digest = generate_sha256_digest(message)?;
    Ok(BASE64_ENGINE.encode(digest))
}