//! Lockboxer
//!
//! Configurable fork of [Lockbox](https://github.com/scrogson/lockbox).
//! It is used in accordance with the [project's license](https://github.com/scrogson/lockbox/blob/58b771fd5115295fd4282b754086fd0b6126e420/Cargo.toml#L6).
//!
//! This library provides encryption and decryption using the AES-GCM (Galois/Counter Mode) algorithm.
//! It ensures data integrity and confidentiality while providing flexibility for various use cases.
//!
//! # Features
//!
//! - Simple and intuitive API for encrypting and decrypting data.
//! - Support for customizable tags, Additional Authenticated Data (AAD), and Initialization Vectors (IV).
//! - Secure default settings to avoid common cryptographic pitfalls.
//! - Error handling with detailed, meaningful messages.

mod cipher;
mod config;
mod tag;

use crate::cipher::{Aes256GcmIv16, Cipher, IvLength};
use crate::tag::{TagDecoder, TagEncoder};
use aes_gcm::aead::{Generate, Payload};
use aes_gcm::{Aes256Gcm, Key};
use thiserror::Error;

pub use crate::config::VaultConfig;

pub type Vault = VaultWithConfig<DefaultIvLength>;
pub type VaultIv16 = VaultWithConfig<IvLength16>;
pub type DefaultIvLength = IvLength12;

pub type IvLength12 = Aes256Gcm;
pub type IvLength16 = Aes256GcmIv16;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Random number generator error")]
    Rng,

    #[error("AES-GCM encrypt error")]
    Encrypt,

    #[error("AES-GCM decrypt error")]
    Decrypt,

    #[error("Unsupported version")]
    UnsupportedVersion,

    #[error("Unsupported tag")]
    UnsupportedTag,

    #[error("Decrypted data is not valid UTF-8")]
    Utf8,
}

/// Generates a random 256-bit (32-byte) key for AES-256 encryption.
///
/// # Returns
///
/// A `Result` containing the generated key as a `Vec<u8>` or an `Error`.
///
/// # Errors
///
/// Returns an `Error::Rng` if the system's random number generator fails.
///
/// # Example
///
/// ```
/// let key = lockboxer::generate_key()?;
/// println!("Generated key: {:?}", key);
/// # Ok::<(), lockboxer::Error>(())
/// ```
pub fn generate_key() -> Result<Vec<u8>, Error> {
    let key = Key::<Aes256Gcm>::try_generate().map_err(|_| Error::Rng)?;
    Ok(key.to_vec())
}

/// Vault provides methods for encrypting and decrypting data using the AES-GCM algorithm.
///
/// This struct supports customizable tags, Initialization Vectors (IV), and Additional Authenticated Data (AAD).
#[derive(Clone)]
pub struct VaultWithConfig<I: IvLength = DefaultIvLength> {
    cipher: Cipher<I>,
    config: VaultConfig,
}

impl<I: IvLength> VaultWithConfig<I> {
    /// Creates a new `Vault` instance with default config.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice representing the encryption key (32 bytes for AES-256).
    ///
    /// # Returns
    ///
    /// A `Result` containing a new `Vault` instance or an `Error`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::InvalidKeyLength` if the key has the wrong length.
    ///
    /// # Example
    ///
    /// ```
    /// use lockboxer::Vault;
    ///
    /// let key = [0u8; 32]; // 256-bit key for AES-256
    /// let vault = Vault::try_new(&key)?;
    /// # Ok::<(), lockboxer::Error>(())
    /// ```
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            cipher: Cipher::try_new(key).map_err(|_| Error::InvalidKeyLength)?,
            config: VaultConfig::default(),
        })
    }

    /// Sets a custom tag for the vault.
    ///
    /// # Arguments
    ///
    /// * `tag` - A string that represents a version or identifier for the cipher.
    ///
    /// # Returns
    ///
    /// `Vault` instance with the updated tag.
    ///
    /// # Security
    ///
    /// The tag is stored as a plaintext header and is not covered by the
    /// AES-GCM authentication: it labels and routes ciphertexts but must
    /// not be relied on for integrity. Use [`with_aad`](Self::with_aad)
    /// for authenticated context.
    ///
    /// # Example
    ///
    /// ```
    /// use lockboxer::Vault;
    ///
    /// let key = [0u8; 32];
    /// let vault = Vault::try_new(&key)?.with_tag("Custom.Tag.V1");
    /// # Ok::<(), lockboxer::Error>(())
    /// ```
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.config.tag = tag.into();
        self
    }

    /// Sets custom Additional Authenticated Data (AAD) for the vault.
    ///
    /// # Arguments
    ///
    /// * `aad` - A string representing Additional Authenticated Data.
    ///
    /// # Returns
    ///
    /// `Vault` instance with the updated AAD.
    ///
    /// # Example
    ///
    /// ```
    /// use lockboxer::Vault;
    ///
    /// let key = [0u8; 32];
    /// let vault = Vault::try_new(&key)?.with_aad("Custom.AAD");
    /// # Ok::<(), lockboxer::Error>(())
    /// ```
    pub fn with_aad(mut self, aad: impl Into<String>) -> Self {
        self.config.aad = aad.into();
        self
    }

    /// Returns the vault's configuration.
    ///
    /// # Example
    ///
    /// ```
    /// use lockboxer::Vault;
    ///
    /// let key = [0u8; 32];
    /// let vault = Vault::try_new(&key)?.with_tag("Custom.Tag.V1");
    /// assert_eq!(vault.config().tag, "Custom.Tag.V1");
    /// # Ok::<(), lockboxer::Error>(())
    /// ```
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Encrypts the provided plaintext.
    ///
    /// Generates a random Initialization Vector (IV) for each encryption.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - A byte slice of the data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` or an `Error`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::Rng` if the system's random number generator
    /// fails, or an `Error::Encrypt` if encryption fails.
    ///
    /// # Example
    ///
    /// ```
    /// use lockboxer::{Vault, generate_key};
    ///
    /// let key = generate_key()?;
    /// let vault = Vault::try_new(&key)?;
    ///
    /// let encrypted = vault.encrypt(b"Hello, world!")?;
    /// # Ok::<(), lockboxer::Error>(())
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let iv = self.cipher.init_iv().map_err(|_| Error::Rng)?;
        let aad = self.config.aad.as_bytes();

        // Encrypt the plaintext with AAD
        let ciphertext_with_tag = self
            .cipher
            .encrypt(
                Payload {
                    msg: plaintext,
                    aad,
                },
                &iv,
            )
            .map_err(|_| Error::Encrypt)?;

        // Split ciphertext and authentication tag
        let (ciphertext, ciphertag) =
            ciphertext_with_tag.split_at(ciphertext_with_tag.len() - self.cipher.tag_length());

        // Encode the tag using TagEncoder
        let encoded_tag = TagEncoder::encode(self.config.tag.as_bytes());

        // Concatenate Encoded Tag, IV, Ciphertag, and Ciphertext
        let mut encoded =
            Vec::with_capacity(encoded_tag.len() + iv.len() + ciphertext_with_tag.len());
        encoded.extend_from_slice(&encoded_tag); // Encoded Tag
        encoded.extend_from_slice(&iv);
        encoded.extend_from_slice(ciphertag); // Ciphertag
        encoded.extend_from_slice(ciphertext); // Ciphertext

        Ok(encoded)
    }

    /// Decrypts the provided ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - A byte slice of the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `String` or an `Error`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::UnsupportedVersion` if the header cannot be
    /// decoded, an `Error::UnsupportedTag` if the tag does not match the
    /// vault's tag, an `Error::Decrypt` if decryption fails, or an
    /// `Error::Utf8` if the plaintext is not valid UTF-8.
    ///
    /// # Example
    ///
    /// ```
    /// use lockboxer::{Vault, generate_key};
    ///
    /// let key = generate_key()?;
    /// let vault = Vault::try_new(&key)?;
    ///
    /// let encrypted = vault.encrypt(b"Hello, world!")?;
    /// let decrypted = vault.decrypt(&encrypted)?;
    /// assert_eq!(decrypted.as_bytes(), b"Hello, world!");
    /// # Ok::<(), lockboxer::Error>(())
    /// ```
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<String, Error> {
        // Decode the tag using TagDecoder
        let (tag, remainder) =
            TagDecoder::decode(ciphertext).map_err(|_| Error::UnsupportedVersion)?;
        if tag != self.config.tag.as_bytes() {
            return Err(Error::UnsupportedTag);
        }

        let aad = self.config.aad.as_bytes();

        let plaintext = self
            .cipher
            .decrypt(remainder, aad)
            .map_err(|_| Error::Decrypt)?;

        // Return the decrypted data as a UTF-8 string; a unit error keeps
        // the rejected plaintext out of caller error values and logs
        String::from_utf8(plaintext).map_err(|_| Error::Utf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &[u8] = b"Hello, world";

    #[test]
    fn works_with_default_config() {
        let key = generate_key().expect("key generation failed");
        let vault = Vault::try_new(&key).expect("vault creation failed");

        let encrypted = vault.encrypt(PLAINTEXT).expect("encryption failed");
        let decrypted = vault.decrypt(&encrypted).expect("decryption failed");

        assert_eq!(decrypted.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn works_with_16_byte_iv_length() {
        let key = generate_key().expect("key generation failed");
        let vault = VaultIv16::try_new(&key).expect("vault creation failed");

        let encrypted = vault.encrypt(PLAINTEXT).expect("encryption failed");
        let decrypted = vault.decrypt(&encrypted).expect("decryption failed");

        assert_eq!(decrypted.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn works_with_custom_tag() {
        let key = generate_key().expect("key generation failed");
        let vault = Vault::try_new(&key)
            .expect("vault creation failed")
            .with_tag("Custom.Tag.V1");

        let encrypted = vault.encrypt(PLAINTEXT).expect("encryption failed");
        let decrypted = vault.decrypt(&encrypted).expect("decryption failed");

        assert_eq!(decrypted.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn works_with_custom_aad() {
        let key = generate_key().expect("key generation failed");
        let vault: VaultWithConfig<DefaultIvLength> = VaultWithConfig::try_new(&key)
            .expect("vault creation failed")
            .with_aad("Custom AAD");

        let encrypted = vault.encrypt(PLAINTEXT).expect("encryption failed");
        let decrypted = vault.decrypt(&encrypted).expect("decryption failed");

        assert_eq!(decrypted.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn decryption_fails_with_wrong_tag() {
        let key = generate_key().expect("key generation failed");
        let vault_1 = Vault::try_new(&key)
            .expect("vault creation failed")
            .with_tag("Tag.V1");
        let vault_2 = Vault::try_new(&key)
            .expect("vault creation failed")
            .with_tag("Tag.V2");

        let encrypted = vault_1.encrypt(PLAINTEXT).expect("encryption failed");
        assert!(vault_2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn decryption_fails_with_wrong_aad() {
        let key = generate_key().expect("key generation failed");
        let vault_1 = Vault::try_new(&key)
            .expect("vault creation failed")
            .with_aad("AAD.V1");
        let vault_2 = Vault::try_new(&key)
            .expect("vault creation failed")
            .with_aad("AAD.V2");

        let encrypted = vault_1.encrypt(PLAINTEXT).expect("encryption failed");
        assert!(vault_2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn decryption_fails_with_invalid_ciphertext() {
        let key = generate_key().expect("key generation failed");
        let vault = Vault::try_new(&key).expect("vault creation failed");

        let invalid_ciphertext = b"Invalid data";
        assert!(vault.decrypt(invalid_ciphertext).is_err());
    }

    #[test]
    fn decryption_fails_with_truncated_ciphertext() {
        let key = generate_key().expect("key generation failed");
        let vault = Vault::try_new(&key).expect("vault creation failed");

        // Valid tag header ("AES.GCM.V1") followed by a remainder shorter
        // than IV (12 bytes) + Ciphertag (16 bytes)
        let truncated_ciphertext = hex::decode("010a4145532e47434d2e56310000000000").unwrap();
        assert!(vault.decrypt(&truncated_ciphertext).is_err());
    }

    // Fixtures generated with lockboxer v0.2.0 (aes-gcm 0.10.3) pin the wire
    // format, catching encoding changes that round-trip tests would miss.

    const FIXTURE_KEY_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn fixture_key() -> Vec<u8> {
        hex::decode(FIXTURE_KEY_HEX).unwrap()
    }

    #[test]
    fn decrypts_v0_2_0_ciphertext_with_default_config() {
        let ciphertext = hex::decode(
            "010a4145532e47434d2e5631820e66c5bccdbb3ac076aa21c1ab5c86729463ae\
             27600fe52aeb913ff95f2f35c6f598171f00542c",
        )
        .unwrap();

        let vault = Vault::try_new(&fixture_key()).expect("vault creation failed");
        assert_eq!(vault.decrypt(&ciphertext).unwrap().as_bytes(), PLAINTEXT);
    }

    #[test]
    fn decrypts_v0_2_0_ciphertext_with_16_byte_iv() {
        let ciphertext = hex::decode(
            "010a4145532e47434d2e5631e886d5a9d84ecebf632f94d6cfd499a4e1d897b9\
             1a06912d0355c47ec8a8249682ededba217bd03c88494ca3",
        )
        .unwrap();

        let vault = VaultIv16::try_new(&fixture_key()).expect("vault creation failed");
        assert_eq!(vault.decrypt(&ciphertext).unwrap().as_bytes(), PLAINTEXT);
    }

    #[test]
    fn decrypts_v0_2_0_ciphertext_with_custom_tag_and_aad() {
        let ciphertext = hex::decode(
            "010d437573746f6d2e5461672e563149a59cacd4976401ecae30eff3c9c95f78\
             c8d4d5362d4686209703c220a218eb91fd7eece81fdf4d",
        )
        .unwrap();

        let vault = Vault::try_new(&fixture_key())
            .expect("vault creation failed")
            .with_tag("Custom.Tag.V1")
            .with_aad("Custom AAD");
        assert_eq!(vault.decrypt(&ciphertext).unwrap().as_bytes(), PLAINTEXT);
    }
}
