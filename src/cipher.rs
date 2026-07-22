use aes_gcm::aead::array::typenum::Unsigned;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, Generate, KeyInit, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Error, Key, Nonce};

pub type Aes256GcmIv16 = AesGcm<Aes256, U16>;

mod private {
    pub trait Sealed {}

    impl Sealed for aes_gcm::Aes256Gcm {}
    impl Sealed for super::Aes256GcmIv16 {}
}

/// Supported AES-256-GCM variants, distinguished by IV length.
///
/// This trait is sealed: the wire format depends on the exact IV and
/// tag sizes of the supported variants, so it cannot be implemented
/// outside this crate.
pub trait IvLength: KeyInit + Aead + private::Sealed {}

impl IvLength for Aes256Gcm {}

impl IvLength for Aes256GcmIv16 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cipher<I: IvLength> {
    cipher: I,
}

impl<I: IvLength> Cipher<I> {
    pub(crate) fn try_new(key: &[u8]) -> Result<Self, Error> {
        let key = Key::<I>::try_from(key).map_err(|_| Error)?;

        Ok(Cipher {
            cipher: I::new(&key),
        })
    }

    pub(crate) fn tag_length(&self) -> usize {
        I::TagSize::USIZE
    }

    pub(crate) fn init_iv(&self) -> Result<Nonce<I::NonceSize>, Error> {
        Nonce::<I::NonceSize>::try_generate().map_err(|_| Error)
    }

    pub(crate) fn encrypt(
        &self,
        payload: Payload,
        nonce: &Nonce<I::NonceSize>,
    ) -> Result<Vec<u8>, Error> {
        self.cipher.encrypt(nonce, payload)
    }

    pub(crate) fn decrypt(&self, remainder: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let iv_length = I::NonceSize::USIZE;
        let tag_length = I::TagSize::USIZE;

        // Reject inputs too short to contain an IV and a Ciphertag
        if remainder.len() < iv_length + tag_length {
            return Err(Error);
        }

        // Extract IV, Ciphertag, and Ciphertext
        let iv = &remainder[..iv_length];
        let ciphertag = &remainder[iv_length..iv_length + tag_length];
        let ciphertext = &remainder[iv_length + tag_length..]; // Remaining is ciphertext

        // Combine ciphertext and ciphertag for decryption
        let mut combined_ciphertext = Vec::with_capacity(remainder.len() - iv_length);
        combined_ciphertext.extend_from_slice(ciphertext);
        combined_ciphertext.extend_from_slice(ciphertag); // Append the tag for decryption

        let payload = Payload {
            msg: &combined_ciphertext,
            aad,
        };

        let nonce = Nonce::try_from(iv).map_err(|_| Error)?;
        self.cipher.decrypt(&nonce, payload)
    }
}
