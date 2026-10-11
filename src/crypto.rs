use aes::Aes128Enc;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::AeadInOut;
use anyhow::{Result, anyhow};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const HKDF_SHA256_BLOCK_LEN: usize = 32;
const HKDF_SHA256_MAX_OUTPUT_LEN: usize = HKDF_SHA256_BLOCK_LEN * u8::MAX as usize;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("hmac sha256 key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[derive(Clone)]
pub struct HmacSha256Key {
    inner: Hmac<Sha256>,
}

impl HmacSha256Key {
    pub fn new(key: &[u8]) -> Self {
        Self {
            inner: <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac sha256 key"),
        }
    }

    pub fn mac(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = self.inner.clone();
        mac.update(data);
        let out = mac.finalize().into_bytes();
        let mut arr = [0_u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}

pub fn hkdf_sha256_array<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; N]> {
    if N > HKDF_SHA256_MAX_OUTPUT_LEN {
        return Err(anyhow!("hkdf expand failed"));
    }
    let mut out = [0_u8; N];
    hkdf_sha256_expand(&hmac_sha256(salt, ikm), info, &mut out)?;
    Ok(out)
}

fn hkdf_sha256_expand(
    prk: &[u8; HKDF_SHA256_BLOCK_LEN],
    info: &[u8],
    out: &mut [u8],
) -> Result<()> {
    type HmacSha256 = Hmac<Sha256>;

    let mut prev = [0_u8; HKDF_SHA256_BLOCK_LEN];
    let mut prev_len = 0_usize;
    let mut counter = 1_u8;
    let mut offset = 0_usize;

    while offset < out.len() {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(prk).expect("hkdf sha256 prk");
        if prev_len != 0 {
            mac.update(&prev[..prev_len]);
        }
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        prev.copy_from_slice(&block);
        prev_len = HKDF_SHA256_BLOCK_LEN;

        let take = (out.len() - offset).min(HKDF_SHA256_BLOCK_LEN);
        out[offset..offset + take].copy_from_slice(&prev[..take]);
        offset += take;
        if offset < out.len() {
            counter = counter
                .checked_add(1)
                .ok_or_else(|| anyhow!("hkdf expand failed"))?;
        }
    }

    Ok(())
}

#[derive(Clone)]
pub struct Aes128BlockCipher {
    inner: Aes128Enc,
}

impl Aes128BlockCipher {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            inner: Aes128Enc::new(key.into()),
        }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut out = Array::from(*block);
        self.inner.encrypt_block(&mut out);
        let mut arr = [0_u8; 16];
        arr.copy_from_slice(&out);
        arr
    }
}

#[derive(Clone)]
pub struct Aes128GcmCipher {
    inner: Aes128Gcm,
}

impl Aes128GcmCipher {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            inner: Aes128Gcm::new(key.into()),
        }
    }

    pub fn encrypt_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16]> {
        let tag = self
            .inner
            .encrypt_inout_detached(nonce.into(), aad, buffer.into())
            .map_err(|_| anyhow!("aes128gcm encrypt failed"))?;
        let mut out = [0_u8; 16];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    pub fn decrypt_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        self.inner
            .decrypt_inout_detached(nonce.into(), aad, buffer.into(), &Array::from(*tag))
            .map_err(|_| anyhow!("aes128gcm decrypt failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Aes128BlockCipher, Aes128GcmCipher, HmacSha256Key, hkdf_sha256_array, hmac_sha256,
    };
    use hkdf::Hkdf;
    use sha2::Sha256;

    fn reference_hkdf<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; N] {
        let mut out = [0_u8; N];
        Hkdf::<Sha256>::new(Some(salt), ikm)
            .expand(info, &mut out)
            .expect("reference hkdf should expand");
        out
    }

    #[test]
    fn hkdf_sha256_array_matches_reference_for_protocol_lengths() {
        let ikm = b"akarin-hkdf-array-ikm";
        let salt = b"akarin-hkdf-array-salt";
        let info = b"akarin-hkdf-array-info";

        assert_eq!(
            hkdf_sha256_array::<8>(ikm, salt, info).unwrap(),
            reference_hkdf::<8>(ikm, salt, info)
        );
        assert_eq!(
            hkdf_sha256_array::<16>(ikm, salt, info).unwrap(),
            reference_hkdf::<16>(ikm, salt, info)
        );
        assert_eq!(
            hkdf_sha256_array::<32>(ikm, salt, info).unwrap(),
            reference_hkdf::<32>(ikm, salt, info)
        );
        assert_eq!(
            hkdf_sha256_array::<64>(ikm, salt, info).unwrap(),
            reference_hkdf::<64>(ikm, salt, info)
        );
    }

    #[test]
    fn aes128gcm_rejects_modified_tag() {
        let cipher = Aes128GcmCipher::new(&[3_u8; 16]);
        let nonce = [5_u8; 12];
        let aad = b"akarin-aad";
        let mut buffer = b"tamper-me".to_vec();
        let mut tag = cipher.encrypt_detached(&nonce, aad, &mut buffer).unwrap();
        tag[0] ^= 0x80;

        cipher
            .decrypt_detached(&nonce, aad, &mut buffer, &tag)
            .expect_err("tampered tag must fail");
    }

    #[test]
    fn aes128_block_cipher_matches_fips197_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        assert_eq!(Aes128BlockCipher::new(&key).encrypt_block(&block), expected);
    }

    #[test]
    fn hmac_sha256_key_matches_one_shot_hmac() {
        let keys: [&[u8]; 3] = [
            b"",
            b"0123456789abcdef",
            b"a-key-longer-than-the-sha256-block-size-of-sixty-four-bytes-so-it-gets-hashed-first",
        ];
        let data: [&[u8]; 3] = [
            b"",
            b"sixteen-byte-msg",
            b"a message that spans more than one sha256 compression block once the ipad prefix is included",
        ];

        for key in keys {
            let keyed = HmacSha256Key::new(key);
            for chunk in data {
                assert_eq!(keyed.mac(chunk), hmac_sha256(key, chunk));
            }
        }
    }

    /// NIST GCM test case 4 (AES-128). Both peers must produce byte-identical
    /// ciphertext and tags, so this guards against any `aes-gcm` upgrade
    /// changing the output.
    #[test]
    fn aes128gcm_matches_nist_test_case_4() {
        let key = hex_array::<16>("feffe9928665731c6d6a8f9467308308");
        let nonce = hex_array::<12>("cafebabefacedbaddecaf888");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let expected_ct = hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        );
        let expected_tag = hex("5bc94fbc3221a5db94fae95ae7121a47");

        let cipher = Aes128GcmCipher::new(&key);
        let mut buffer = plaintext.clone();
        let tag = cipher.encrypt_detached(&nonce, &aad, &mut buffer).unwrap();
        assert_eq!(buffer, expected_ct, "ciphertext diverged from NIST vector");
        assert_eq!(
            tag.as_slice(),
            expected_tag,
            "tag diverged from NIST vector"
        );

        cipher
            .decrypt_detached(&nonce, &aad, &mut buffer, &tag)
            .expect("round trip must verify");
        assert_eq!(buffer, plaintext);
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_array<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }
}
