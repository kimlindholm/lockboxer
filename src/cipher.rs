use aes_gcm::aead::array::typenum::Unsigned;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, AeadInOut, Generate, KeyInit, Payload, Tag};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Error, Key, Nonce};
use zeroize::Zeroize;

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
pub trait IvLength: KeyInit + Aead + AeadInOut + private::Sealed {}

impl IvLength for Aes256Gcm {}

impl IvLength for Aes256GcmIv16 {}

#[derive(Clone)]
pub(crate) struct Cipher<I: IvLength> {
    cipher: I,
}

impl<I: IvLength> Cipher<I> {
    pub(crate) fn try_new(key: &[u8]) -> Result<Self, Error> {
        let mut key = Key::<I>::try_from(key).map_err(|_| Error)?;
        let cipher = I::new(&key);
        key.as_mut_slice().zeroize();

        Ok(Cipher { cipher })
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

    pub(crate) fn decrypt(&self, mut remainder: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let iv_length = I::NonceSize::USIZE;
        let tag_length = I::TagSize::USIZE;

        // Reject inputs too short to contain an IV and a Ciphertag
        if remainder.len() < iv_length + tag_length {
            return Err(Error);
        }

        // Extract IV and Ciphertag; the rest is ciphertext
        let nonce = Nonce::try_from(&remainder[..iv_length]).map_err(|_| Error)?;
        let ciphertag =
            Tag::<I>::try_from(&remainder[iv_length..iv_length + tag_length]).map_err(|_| Error)?;

        // Decrypt the ciphertext in place, then drop the IV and Ciphertag
        // prefix to leave only the plaintext
        let ciphertext = &mut remainder[iv_length + tag_length..];
        self.cipher
            .decrypt_inout_detached(&nonce, aad, ciphertext.into(), &ciphertag)?;

        remainder.drain(..iv_length + tag_length);
        Ok(remainder)
    }
}
