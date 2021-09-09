use algebra::groups::Group;
use algebra::jubjub::{JubjubPoint, JubjubScalar, JUBJUB_SCALAR_LEN};
use crypto::basics::signatures::schnorr;
use crypto::basics::signatures::schnorr::{KeyPair, PublicKey};
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use utils::errors::ZeiError;
use utils::serialization::ZeiFromToBytes;
use wasm_bindgen::prelude::*;

const AXFR_SECRET_KEY_LENGTH: usize = JUBJUB_SCALAR_LEN;
const AXFR_PUBLIC_KEY_LENGTH: usize = JubjubPoint::COMPRESSED_LEN;

/// Public key used to address an Anonymous records and verify transaction spending it
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AXfrPubKey(pub(crate) schnorr::PublicKey<JubjubPoint>);

/// Keypair associated with an Anonymous records. It is used to spending it.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct AXfrKeyPair(pub(crate) schnorr::KeyPair<JubjubPoint, JubjubScalar>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct AXfrSignature(pub(crate) schnorr::Signature<JubjubPoint, JubjubScalar>);

impl AXfrKeyPair {
    /// Generate a new signature key pair
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> AXfrKeyPair {
        AXfrKeyPair(schnorr::KeyPair::generate(prng))
    }

    /// Multiply the secret key scalar by `factor` producing a new "randomized" KeyPair
    pub fn randomize(&self, factor: &JubjubScalar) -> AXfrKeyPair {
        AXfrKeyPair(self.0.randomize(factor))
    }

    /// Return public key
    pub fn pub_key(&self) -> AXfrPubKey {
        AXfrPubKey(self.0.pub_key.clone())
    }

    /// Return secret key scalar value
    pub(crate) fn get_secret_scalar(&self) -> JubjubScalar {
        self.0.get_secret_scalar()
    }

    pub fn sign(&self, msg: &[u8]) -> AXfrSignature {
        AXfrSignature(self.0.sign(msg))
    }
}

impl ZeiFromToBytes for AXfrKeyPair {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.zei_to_bytes()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != (AXFR_SECRET_KEY_LENGTH + AXFR_PUBLIC_KEY_LENGTH) {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let keypair: KeyPair<JubjubPoint, JubjubScalar> =
                schnorr::KeyPair::zei_from_bytes(bytes).c(d!(""))?;

            Ok(AXfrKeyPair(keypair))
        }
    }
}

impl AXfrPubKey {
    /// Implicitly multiply the associated secret key scalar by `factor` producing a new "randomized" key
    pub fn randomize(&self, factor: &JubjubScalar) -> AXfrPubKey {
        AXfrPubKey(self.0.randomize(factor))
    }
    /// return a reference to the EC group point defining the public key
    pub fn as_jubjub_point(&self) -> &JubjubPoint {
        self.0.point_ref()
    }

    pub(crate) fn from_jubjub_point(point: JubjubPoint) -> AXfrPubKey {
        AXfrPubKey(schnorr::PublicKey::from_point(point))
    }

    /// Signature verification function
    pub fn verify(&self, msg: &[u8], sig: &AXfrSignature) -> Result<()> {
        self.0.verify(msg, &sig.0).c(d!())
    }
}

impl ZeiFromToBytes for AXfrPubKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.zei_to_bytes()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AXFR_PUBLIC_KEY_LENGTH {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let point: JubjubPoint = JubjubPoint::zei_from_bytes(bytes)
                .c(d!("error in deserializing JubJub point"))?;
            Ok(AXfrPubKey {
                0: PublicKey::from_point(point),
            })
        }
    }
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::keys::{AXfrKeyPair, AXfrPubKey};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;
    use utils::serialization::ZeiFromToBytes;

    #[test]
    fn test_axfr_pub_key_serialization() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);

        let pub_key: AXfrPubKey = keypair.pub_key();

        let bytes = pub_key.zei_to_bytes();
        assert_ne!(bytes.len(), 0);
        
        let reformed_pub_key = AXfrPubKey::zei_from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(pub_key, reformed_pub_key);

        
        //Added for a negative test
        
        let mut bytes_2 = bytes.clone();
        assert_ne!(bytes_2.len(), 0);

        bytes_2[7] = 34;

        let reformed_pub_key_2 = AXfrPubKey::zei_from_bytes(bytes_2.as_slice()).unwrap();
        assert_ne!(pub_key, reformed_pub_key_2);

    }

    #[test]
    fn test_axfr_key_pair_serialization() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);

        let bytes: Vec<u8> = keypair.zei_to_bytes();
        assert_ne!(bytes.len(), 0);

        let reformed_key_pair = AXfrKeyPair::zei_from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(keypair, reformed_key_pair);

        
        //Added by me for a negative test
        
        let mut bytes_2 = bytes.clone();
        assert_ne!(bytes_2.len(), 0);

        bytes_2[7] = 34;
        
        let reformed_key_pair_2 = AXfrKeyPair::zei_from_bytes(bytes_2.as_slice()).unwrap();
        assert_ne!(keypair, reformed_key_pair_2);
    }
}
