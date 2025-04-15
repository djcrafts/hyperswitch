# Crypto Utilities for Connectors

This module provides a consistent interface to the cryptographic functions in the `common_utils` crate. Connectors should use these utilities instead of implementing their own cryptographic operations or directly using low-level crypto libraries like `ring`.

## Available Functions

### HMAC-SHA256

- `generate_hmac_sha256_signature` - Generate a hex-encoded HMAC-SHA256 signature
- `generate_hmac_sha256_base64_signature` - Generate a base64-encoded HMAC-SHA256 signature
- `verify_hmac_sha256_signature` - Verify an HMAC-SHA256 signature

### SHA256

- `generate_sha256_digest` - Generate a SHA256 digest as a byte vector
- `generate_sha256_hex_digest` - Generate a hex-encoded SHA256 digest
- `generate_sha256_base64_digest` - Generate a base64-encoded SHA256 digest

## Migration Guide

When migrating connector code to use these utilities:

1. Remove direct imports of `ring::hmac` or other low-level crypto libraries
2. Add `use crate::crypto_utils;` to your connector's imports
3. Replace instances of `hmac::Key::new(hmac::HMAC_SHA256, secret_key.as_bytes())` followed by `hmac::sign(&key, message)` with:
   ```rust
   crypto_utils::generate_hmac_sha256_signature(message, secret_key.as_bytes())
   ```
4. Replace custom SHA256 digest implementations with:
   ```rust
   crypto_utils::generate_sha256_digest(message)
   ```

## Examples

### Before:

```rust
let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key.as_bytes());
let tag = hmac::sign(&key, message.as_bytes());
let hmac_sign = hex::encode(tag);
```

### After:

```rust
let hmac_sign = crypto_utils::generate_hmac_sha256_signature(
    message.as_bytes(),
    secret_key.as_bytes()
)?;
```

## Connectors To Update

The following connectors have been identified as using their own cryptographic implementations and should be updated to use the common utilities:

1. ✅ Rapyd - Updated to use `crypto_utils`
2. Cybersource - Uses custom `generate_signature` and `generate_digest` methods
3. Bankofamerica - Uses custom `generate_signature` method
4. Worldline - Uses direct `hmac::Key` and `hmac::sign`
5. Fiserv - Uses direct `hmac::Key` and `hmac::sign`
6. Payeezy - Uses direct `hmac::Key` and `hmac::sign`
7. Redsys - Uses custom `des_encrypt` function
8. Riskified - Uses direct `hmac::Key` and `hmac::sign`

## Benefits

- Improved security by using vetted implementations
- Reduced code duplication
- Easier maintenance and updates
- Consistent behavior across connectors