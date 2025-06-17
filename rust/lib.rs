//! # ML-DSA-44 Rust Wrapper
//! 
//! A Rust wrapper for the ML-DSA-44 (Module-Lattice-Based Digital Signature Algorithm) 
//! post-quantum cryptographic signature scheme.
//!
//! ## Features
//! - Key generation from random or seed
//! - Digital signature creation and verification
//! - Context-aware signing (optional context data)
//! - Safe Rust API with proper error handling
//! - Secure seed handling (seeds are cleared after use)
//!
//! ## Example
//! ```rust
//! use ml_dsa_44::{Keypair, sign, verify};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate keypair
//! let keypair = Keypair::generate()?;
//!
//! // Sign message
//! let message = b"Hello, post-quantum world!";
//! let signature = sign(message, &keypair.secret_key)?;
//!
//! // Verify signature
//! let is_valid = verify(&signature, message, &keypair.public_key)?;
//! assert!(is_valid);
//!
//! // Generate from seed (seed will be cleared after use)
//! let mut seed = [0x42u8; 32];
//! let keypair_from_seed = Keypair::from_seed(&mut seed)?;
//! // seed is now zeroed out for security
//! # Ok(())
//! # }
//! ```

use std::os::raw::{c_int, c_uchar};

/// ML-DSA-44 algorithm constants
pub mod constants {
    pub const PUBLIC_KEY_BYTES: usize = 1312;
    pub const SECRET_KEY_BYTES: usize = 2560;
    pub const SIGNATURE_BYTES: usize = 2420;
    pub const SEED_BYTES: usize = 32;
}

/// Error types for ML-DSA-44 operations
#[derive(Debug, Clone, PartialEq)]
pub enum MlDsaError {
    KeyGeneration,
    Signing,
    Verification,
    InvalidSignature,
    InvalidInput,
}

impl std::fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlDsaError::KeyGeneration => write!(f, "Key generation failed"),
            MlDsaError::Signing => write!(f, "Signing failed"),
            MlDsaError::Verification => write!(f, "Verification failed"),
            MlDsaError::InvalidSignature => write!(f, "Invalid signature"),
            MlDsaError::InvalidInput => write!(f, "Invalid input"),
        }
    }
}

impl std::error::Error for MlDsaError {}

pub type Result<T> = std::result::Result<T, MlDsaError>;

/// Public key (1312 bytes)
#[derive(Clone)]
pub struct PublicKey(pub [u8; constants::PUBLIC_KEY_BYTES]);

/// Secret key (2560 bytes)
#[derive(Clone)]
pub struct SecretKey(pub [u8; constants::SECRET_KEY_BYTES]);

/// Digital signature (up to 2420 bytes)
#[derive(Clone)]
pub struct Signature {
    pub data: Vec<u8>,
}

/// Keypair containing public and secret keys
#[derive(Clone)]
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

// FFI declarations
extern "C" {
    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(
        pk: *mut c_uchar,
        sk: *mut c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_fseed(
        pk: *mut c_uchar,
        sk: *mut c_uchar,
        seed: *mut c_uchar, // Changed from *const to *mut
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
        sig: *mut c_uchar,
        siglen: *mut libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        sk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(
        sig: *mut c_uchar,
        siglen: *mut libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        ctx: *const c_uchar,
        ctxlen: libc::size_t,
        sk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
        sig: *const c_uchar,
        siglen: libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        pk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
        sig: *const c_uchar,
        siglen: libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        ctx: *const c_uchar,
        ctxlen: libc::size_t,
        pk: *const c_uchar,
    ) -> c_int;
}

impl Keypair {
    /// Generate a new keypair using system randomness
    pub fn generate() -> Result<Self> {
        let mut pk = [0u8; constants::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; constants::SECRET_KEY_BYTES];

        let result = unsafe {
            PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        };

        if result != 0 {
            return Err(MlDsaError::KeyGeneration);
        }

        Ok(Keypair {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Generate keypair from a 32-byte seed (deterministic)
    /// 
    /// **Security Note**: The seed will be cleared (zeroed) after use for security reasons.
    /// This is done by the underlying C implementation to prevent seed reuse.
    /// 
    /// # Arguments
    /// * `seed` - A mutable reference to a 32-byte seed that will be cleared after use
    /// 
    /// # Example
    /// ```rust
    /// # use ml_dsa_44::{Keypair, constants};
    /// let mut seed = [0x42u8; constants::SEED_BYTES];
    /// let keypair = Keypair::from_seed(&mut seed)?;
    /// // seed is now [0u8; 32] - cleared for security
    /// # Ok::<(), ml_dsa_44::MlDsaError>(())
    /// ```
    pub fn from_seed(seed: &mut [u8; constants::SEED_BYTES]) -> Result<Self> {
        let mut pk = [0u8; constants::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; constants::SECRET_KEY_BYTES];

        let result = unsafe {
            PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_fseed(
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
                seed.as_mut_ptr(), // Now correctly passing mutable pointer
            )
        };

        if result != 0 {
            return Err(MlDsaError::KeyGeneration);
        }

        Ok(Keypair {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }
}

/// Sign a message with the secret key
pub fn sign(message: &[u8], secret_key: &SecretKey) -> Result<Signature> {
    let mut sig = vec![0u8; constants::SIGNATURE_BYTES];
    let mut siglen = constants::SIGNATURE_BYTES;

    let result = unsafe {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
            sig.as_mut_ptr(),
            &mut siglen,
            message.as_ptr(),
            message.len(),
            secret_key.0.as_ptr(),
        )
    };

    if result != 0 {
        return Err(MlDsaError::Signing);
    }

    sig.truncate(siglen);
    Ok(Signature { data: sig })
}

/// Sign a message with context data
pub fn sign_with_context(
    message: &[u8],
    context: &[u8],
    secret_key: &SecretKey,
) -> Result<Signature> {
    let mut sig = vec![0u8; constants::SIGNATURE_BYTES];
    let mut siglen = constants::SIGNATURE_BYTES;

    let result = unsafe {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(
            sig.as_mut_ptr(),
            &mut siglen,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            secret_key.0.as_ptr(),
        )
    };

    if result != 0 {
        return Err(MlDsaError::Signing);
    }

    sig.truncate(siglen);
    Ok(Signature { data: sig })
}

/// Verify a signature
pub fn verify(signature: &Signature, message: &[u8], public_key: &PublicKey) -> Result<bool> {
    let result = unsafe {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
            signature.data.as_ptr(),
            signature.data.len(),
            message.as_ptr(),
            message.len(),
            public_key.0.as_ptr(),
        )
    };

    Ok(result == 0)
}

/// Verify a signature with context data
pub fn verify_with_context(
    signature: &Signature,
    message: &[u8],
    context: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    let result = unsafe {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
            signature.data.as_ptr(),
            signature.data.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            public_key.0.as_ptr(),
        )
    };

    Ok(result == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::generate().unwrap();
        assert_eq!(keypair.public_key.0.len(), constants::PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret_key.0.len(), constants::SECRET_KEY_BYTES);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate().unwrap();
        let message = b"Hello, ML-DSA-44!";
        
        let signature = sign(message, &keypair.secret_key).unwrap();
        let is_valid = verify(&signature, message, &keypair.public_key).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_sign_and_verify_with_context() {
        let keypair = Keypair::generate().unwrap();
        let message = b"Hello, world!";
        let context = b"test context";
        
        let signature = sign_with_context(message, context, &keypair.secret_key).unwrap();
        let is_valid = verify_with_context(&signature, message, context, &keypair.public_key).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [42u8; constants::SEED_BYTES];
        let mut seed1 = seed;
        let mut seed2 = seed;
        
        let keypair1 = Keypair::from_seed(&mut seed1).unwrap();
        let keypair2 = Keypair::from_seed(&mut seed2).unwrap();
        
        assert_eq!(keypair1.public_key.0, keypair2.public_key.0);
        assert_eq!(keypair1.secret_key.0, keypair2.secret_key.0);
        
        // Both seeds should be cleared
        assert_eq!(seed1, [0u8; constants::SEED_BYTES]);
        assert_eq!(seed2, [0u8; constants::SEED_BYTES]);
    }

    #[test]
    fn test_seed_clearing() {
        let original_seed = [0x42u8; constants::SEED_BYTES];
        let mut seed = original_seed;
        
        let _keypair = Keypair::from_seed(&mut seed).unwrap();
        
        // Seed should be cleared after use
        assert_ne!(seed, original_seed);
        assert_eq!(seed, [0u8; constants::SEED_BYTES]);
    }
}