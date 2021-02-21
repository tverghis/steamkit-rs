use openssl::{error::ErrorStack, pkey::PKey, rand, rsa::Padding};

use crate::Error;

const STEAM_PK: &'static [u8] = include_bytes!("../steam_pk.pem");

pub struct SessionKey {
    plain: [u8; 32],
    encrypted: [u8; 128],
}

impl SessionKey {
    pub fn new() -> Result<Self, Error> {
        let mut plain = [0; 32];
        let mut encrypted = [0; 128];

        // Generate 32 random bytes for the `plain` buffer
        rand::rand_bytes(&mut plain)?;

        // Encrypt those bytes
        rsa_encrypt(&plain, &mut encrypted)?;

        Ok(SessionKey { plain, encrypted })
    }

    pub fn plain(&self) -> &[u8; 32] {
        &self.plain
    }

    pub fn encrypted(&self) -> &[u8; 128] {
        &self.encrypted
    }
}

fn rsa_encrypt(from: &[u8], to: &mut [u8]) -> Result<usize, ErrorStack> {
    let rsa = &PKey::public_key_from_pem(STEAM_PK)?.rsa()?;
    rsa.public_encrypt(from, to, Padding::PKCS1)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rsa_encrypt() {
        let from = "Hello, world!".as_bytes();
        let mut to = vec![0u8; 128];

        // This should implictly test that:
        //  - the key is formatted correctly
        //  - the output buffer is at least the minimum size
        //  - we've used padding appropriately
        // If any of these are false, the function will panic and fail our test.
        rsa_encrypt(from, &mut to).unwrap();

        // We're using a 1024-bit key, so the output size should never grow past 128.
        assert_eq!(to.len(), 128);
    }
}
