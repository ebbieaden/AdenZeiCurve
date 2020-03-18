use crate::api::anon_creds::{
  ACConfidentialRevealProof, ACIssuerPublicKey, AttributeCiphertext, AttributeDecKey,
  AttributeEncKey,
};
use crate::basic_crypto::hybrid_encryption::ZeiHybridCipher;
use crate::crypto::chaum_pedersen::ChaumPedersenProofX;
use crate::crypto::pedersen_elgamal::PedersenElGamalEqProof;
use crate::serialization;
use crate::xfr::asset_mixer::AssetMixProof;
use crate::xfr::sig::{XfrMultiSig, XfrPublicKey};
use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::utils::u8_bigendian_slice_to_u128;
use crate::xfr::asset_record::AssetRecordType;
use crate::xfr::asset_tracer::{RecordDataCiphertext, RecordDataDecKey, RecordDataEncKey};
use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

/// Asset Type identifier
pub type AssetType = [u8; 16];

pub fn asset_type_to_scalar(asset_type: &AssetType) -> Scalar {
  let type_as_u128 = u8_bigendian_slice_to_u128(&asset_type[..]);
  Scalar::from(type_as_u128)
}

/// A Transfer note: contains a transfer body and a (multi)signature
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrNote {
  pub body: XfrBody,
  pub multisig: XfrMultiSig,
}

impl XfrNote {
  pub fn outputs_iter(&self) -> std::slice::Iter<BlindAssetRecord> {
    self.body.outputs.iter()
  }
}

/// A Transfer's body: contains a inputs, outputs, proofs and messages to participants (asset tracer and output owners)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrBody {
  pub inputs: Vec<BlindAssetRecord>,
  pub outputs: Vec<BlindAssetRecord>,
  pub proofs: XfrProofs,
  pub asset_tracing_memos: Vec<Option<AssetTracerMemo>>,
  pub owners_memos: Vec<Option<OwnerMemo>>, // If confidential amount or asset type, lock the amount and/or asset type to the public key in asset_record
}

/// A transfer input or output record as seen in the ledger
/// Amount and asset type can be confidential or non confidential
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlindAssetRecord {
  pub amount: XfrAmount,        // Amount being transferred
  pub asset_type: XfrAssetType, // Asset type being transferred
  pub public_key: XfrPublicKey, // ownership address
}

impl BlindAssetRecord {
  pub fn get_record_type(&self) -> AssetRecordType {
    let conf_amount = match self.amount {
      XfrAmount::Confidential(_) => true,
      _ => false,
    };
    let conf_asset_type = match self.asset_type {
      XfrAssetType::Confidential(_) => true,
      _ => false,
    };
    AssetRecordType::from_booleans(conf_amount, conf_asset_type)
  }
}

/// Amount in blind asset record: if confidential, provide commitments for lower and hight 32 bits
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum XfrAmount {
  // amount is a 64 bit positive integer expressed in base 2^32 in confidential transactions
  Confidential((CompressedRistretto, CompressedRistretto)),
  NonConfidential(u64),
}

impl XfrAmount {
  /// Returns true only if amount is confidential
  /// # Example:
  /// ```
  /// use zei::xfr::structs::XfrAmount;
  /// use curve25519_dalek::ristretto::CompressedRistretto;
  /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
  /// assert!(xfr_amount.is_confidential());
  /// let xfr_amount = XfrAmount::NonConfidential(100u64);
  /// assert!(!xfr_amount.is_confidential());
  /// ```
  pub fn is_confidential(&self) -> bool {
    match self {
      XfrAmount::Confidential(_) => true,
      _ => false,
    }
  }
  /// Return Some(amount) if amount is non-confidential. Otherwise, return None
  /// # Example:
  /// ```
  /// use zei::xfr::structs::XfrAmount;
  /// use curve25519_dalek::ristretto::CompressedRistretto;
  /// let xfr_amount = XfrAmount::NonConfidential(100u64);
  /// assert_eq!(xfr_amount.get_amount().unwrap(), 100u64);
  /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
  /// assert!(xfr_amount.get_amount().is_none());
  /// ```
  pub fn get_amount(&self) -> Option<u64> {
    match self {
      XfrAmount::NonConfidential(x) => Some(*x),
      _ => None,
    }
  }

  /// Return Some((c1,c2)), where (c1,c2) is a commitment to the amount
  /// if amount is confidential. Otherwise, return None
  /// # Example:
  /// ```
  /// use zei::xfr::structs::XfrAmount;
  /// use curve25519_dalek::ristretto::CompressedRistretto;
  /// let xfr_amount = XfrAmount::NonConfidential(100u64);
  /// assert!(xfr_amount.get_commitments().is_none());
  /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
  /// assert_eq!(xfr_amount.get_commitments().unwrap(), (CompressedRistretto::default(), CompressedRistretto::default()));
  /// ```
  pub fn get_commitments(&self) -> Option<(CompressedRistretto, CompressedRistretto)> {
    match self {
      XfrAmount::Confidential(x) => Some(*x),
      _ => None,
    }
  }
}

/// Asset type in BlindAsset record: if confidential, provide commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum XfrAssetType {
  Confidential(CompressedRistretto),
  NonConfidential(AssetType),
}

impl XfrAssetType {
  /// Returns true only if amount is confidential
  /// # Example:
  /// ```
  /// use zei::xfr::structs::XfrAssetType;
  /// use curve25519_dalek::ristretto::CompressedRistretto;
  /// let xfr_asset_type = XfrAssetType::Confidential(CompressedRistretto::default());
  /// assert!(xfr_asset_type.is_confidential());
  /// let xfr_asset_type = XfrAssetType::NonConfidential([0u8;16]);
  /// assert!(!xfr_asset_type.is_confidential());
  /// ```
  pub fn is_confidential(&self) -> bool {
    match self {
      XfrAssetType::Confidential(_) => true,
      _ => false,
    }
  }

  /// Return Some(asset_type) if asset_type is non-confidential. Otherwise, return None
  /// # Example:
  /// ```
  /// use zei::xfr::structs::XfrAssetType;
  /// use curve25519_dalek::ristretto::CompressedRistretto;
  /// let xfr_asset_type = XfrAssetType::NonConfidential([0u8;16]);
  /// assert_eq!(xfr_asset_type.get_asset_type().unwrap(), [0u8;16]);
  /// let xfr_asset_type = XfrAssetType::Confidential(CompressedRistretto::default());
  /// assert!(xfr_asset_type.get_asset_type().is_none());
  /// ```
  pub fn get_asset_type(&self) -> Option<AssetType> {
    match self {
      XfrAssetType::NonConfidential(x) => Some(*x),
      _ => None,
    }
  }

  /// Return Some(c), where c is a commitment to the asset_type
  /// if asset_type is confidential. Otherwise, return None
  /// # Example:
  /// ```
  /// use zei::xfr::structs::XfrAssetType;
  /// use curve25519_dalek::ristretto::CompressedRistretto;
  /// let xfr_asset_type = XfrAssetType::NonConfidential([0u8;16]);
  /// assert!(xfr_asset_type.get_commitment().is_none());
  /// let xfr_amount = XfrAssetType::Confidential(CompressedRistretto::default());
  /// assert_eq!(xfr_amount.get_commitment().unwrap(), CompressedRistretto::default());
  /// ```
  pub fn get_commitment(&self) -> Option<CompressedRistretto> {
    match self {
      XfrAssetType::Confidential(x) => Some(*x),
      _ => None,
    }
  }
}

/// Public Asset Tracer Encryption keys
/// Identity attributes are encrypted with keys.attrs_enc_key
/// Amount and Asset Type encrypted with keys.record_data_enc_key
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerEncKeys {
  pub record_data_enc_key: RecordDataEncKey,
  pub attrs_enc_key: AttributeEncKey,
}

/// Secret Asset Tracer Decryption keys
/// Identity attributed are encrypted with keys.attrs_enc_key
/// Amount and Asset Type encrypted with keys.record_data_enc_key
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerDecKeys {
  pub record_data_dec_key: RecordDataDecKey,
  pub attrs_dec_key: AttributeDecKey,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerKeyPair {
  pub enc_key: AssetTracerEncKeys,
  pub dec_key: AssetTracerDecKeys,
}

/// An asset and identity tracking policy for an asset record
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssetTracingPolicy {
  pub enc_keys: AssetTracerEncKeys,
  pub asset_tracking: bool, // track amount and asset type
  pub identity_tracking: Option<IdentityRevealPolicy>, // get identity attribute of asset holder
}

/// An identity reveal policy. It indicates the credential issuer public key
/// and a reveal_map indicating which attributes needs to be revealed (by the position they
/// occur in the credential)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityRevealPolicy {
  pub cred_issuer_pub_key: ACIssuerPublicKey,
  pub reveal_map: Vec<bool>, // i-th is true, if i-th attribute is to be revealed
}

/// Information directed to an asset tracer
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerMemo {
  pub enc_key: AssetTracerEncKeys,
  // amount is a 64 bit positive integer expressed in base 2^32 in confidential transaction
  pub lock_amount: Option<(RecordDataCiphertext, RecordDataCiphertext)>, //None if amount is not confidential
  pub lock_asset_type: Option<RecordDataCiphertext>, // None asset_type is not confidential
  pub lock_attributes: Option<Vec<AttributeCiphertext>>,
}

/// Information directed to secret key holder of a BlindAssetRecord
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnerMemo {
  pub blind_share: CompressedEdwardsY,
  pub lock: ZeiHybridCipher,
}

// ASSET RECORD STRUCTURES

/// A BlindAssetRecord with revealed commitment openings.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct OpenAssetRecord {
  pub blind_asset_record: BlindAssetRecord, //TODO have a reference here, and lifetime parameter. We will avoid copying info unnecessarily.
  pub amount: u64,
  pub amount_blinds: (Scalar, Scalar), // use Scalar::zero() if unneeded
  pub asset_type: AssetType,
  pub type_blind: Scalar, // use Scalar::zero() if unneeded
}

impl OpenAssetRecord {
  pub fn get_record_type(&self) -> AssetRecordType {
    self.blind_asset_record.get_record_type()
  }
  pub fn get_asset_type(&self) -> &AssetType {
    &self.asset_type
  }
  pub fn get_amount(&self) -> &u64 {
    &self.amount
  }
  pub fn get_pub_key(&self) -> &XfrPublicKey {
    &self.blind_asset_record.public_key
  }
}

/// An input or output record and associated information (policies and memos) used to build XfrNotes/XfrBodys.
/// It contains all the information used to the generate valid XfrNote/XfrBody.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetRecord {
  pub open_asset_record: OpenAssetRecord,
  pub tracking_policy: Option<AssetTracingPolicy>,
  pub identity_proof: Option<ACConfidentialRevealProof>,
  pub asset_tracer_memo: Option<AssetTracerMemo>,
  pub owner_memo: Option<OwnerMemo>,
}

/// An asset record template: amount, asset type, owner public key, type and tracking
#[derive(Deserialize, Serialize)]
pub struct AssetRecordTemplate {
  pub amount: u64,
  pub asset_type: AssetType,
  pub public_key: XfrPublicKey, // ownership address
  pub asset_record_type: AssetRecordType,
  pub asset_tracking: Option<AssetTracingPolicy>,
}

// PROOFS STRUCTURES

// TODO is this clippy warning a problem?
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AssetTypeAndAmountProof {
  AssetMix(AssetMixProof),        // multi-type fully confidential Xfr
  ConfAmount(XfrRangeProof),      // single-type and public, confidental amount
  ConfAsset(ChaumPedersenProofX), // single-type confidential, public amount
  ConfAll((XfrRangeProof, ChaumPedersenProofX)), // fully confidential single type
  NoProof,                        // non-confidential transaction
}

/// I contain the proofs of a transfer note
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrProofs {
  pub asset_type_and_amount_proof: AssetTypeAndAmountProof,
  pub asset_tracking_proof: AssetTrackingProofs,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct XfrRangeProof {
  #[serde(with = "serialization::zei_obj_serde")]
  pub range_proof: RangeProof,
  pub xfr_diff_commitment_low: CompressedRistretto, //lower 32 bits transfer amount difference commitment
  pub xfr_diff_commitment_high: CompressedRistretto, //higher 32 bits transfer amount difference commitment
}

/// Proof of records' data and identity tracking
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTrackingProofs {
  pub asset_type_and_amount_proofs: Vec<PedersenElGamalEqProof>, // None if confidential amount and confidential asset type flag are off. Otherwise, value proves that decryption of lock_amounts and/or asset type yield the same as values committed in amount_commitments in BlindAssetRecord outputs
  pub inputs_identity_proofs: Vec<Option<ACConfidentialRevealProof>>, //None if asset policy does not require identity tracking for input. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
  pub outputs_identity_proofs: Vec<Option<ACConfidentialRevealProof>>, //None if asset policy does not require identity tracking for output. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
}

impl PartialEq for XfrRangeProof {
  fn eq(&self, other: &XfrRangeProof) -> bool {
    self.range_proof.to_bytes() == other.range_proof.to_bytes()
    && self.xfr_diff_commitment_low == other.xfr_diff_commitment_low
    && self.xfr_diff_commitment_high == other.xfr_diff_commitment_high
  }
}

impl Eq for XfrRangeProof {}

#[cfg(test)]

// TODO remove or uncomment the section below

mod test {
  /*
  use crate::xfr::sig::XfrMultiSig;
  use crate::xfr::structs::{AssetTrackingProofs, AssetTypeAndAmountProof};
  use crate::xfr::tests::tests::create_xfr;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rmp_serde::{Deserializer, Serializer};
  use serde::de::Deserialize;
  use serde::ser::Serialize;


  fn do_test_serialization(xfr_type: XfrType, asset_tracking: bool) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let asset_type = [0u8; 16];
    let input_amount = [(10u64, asset_type), (20u64, asset_type)];
    let out_amount = [(1u64, asset_type),
                      (2u64, asset_type),
                      (1u64, asset_type),
                      (10u64, asset_type),
                      (16u64, asset_type)];

    let (xfr_note, _, _, _, _) = create_xfr(&mut prng,
                                            &input_amount,
                                            &out_amount,
                                            );

    //serializing signatures
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.multisig
                       .serialize(&mut Serializer::new(&mut vec))
                       .is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let multisig_de: XfrMultiSig = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note.multisig, multisig_de);

    //serializing proofs
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.body
                       .proofs
                       .serialize(&mut Serializer::new(&mut vec))
                       .is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let proofs_de = XfrProofs::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note.body.proofs, proofs_de);

    let json_str = serde_json::to_string(&xfr_note.body.proofs.asset_tracking_proof).unwrap();
    let proofs_de: AssetTrackingProofs = serde_json::from_str(json_str.as_str()).unwrap();
    assert_eq!(xfr_note.body.proofs.asset_tracking_proof, proofs_de);

    let json_str =
      serde_json::to_string(&xfr_note.body.proofs.asset_type_and_amount_proof).unwrap();
    let proofs_de: AssetTypeAndAmountProof = serde_json::from_str(json_str.as_str()).unwrap();
    assert_eq!(xfr_note.body.proofs.asset_type_and_amount_proof, proofs_de);

    //serializing body
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.body
                       .serialize(&mut Serializer::new(&mut vec))
                       .is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let body_de = XfrBody::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note.body, body_de);

    let json_str = serde_json::to_string(&xfr_note.body).unwrap();
    let body_de: XfrBody = serde_json::from_str(json_str.as_str()).unwrap();
    assert_eq!(xfr_note.body, body_de);

    let bincode_vec = bincode::serialize(&xfr_note.body).unwrap();
    let body_de: XfrBody = bincode::deserialize(bincode_vec.as_slice()).unwrap();
    assert_eq!(xfr_note.body, body_de);

    //serializing whole Xfr
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.serialize(&mut Serializer::new(&mut vec)).is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let xfr_de = XfrNote::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note, xfr_de);

    let bincode_vec = bincode::serialize(&xfr_note).unwrap();
    let note_de: XfrNote = bincode::deserialize(bincode_vec.as_slice()).unwrap();
    assert_eq!(xfr_note, note_de);

    let json_str = serde_json::to_string(&xfr_note).unwrap();
    let note_de: XfrNote = serde_json::from_str(json_str.as_str()).unwrap();
    assert_eq!(xfr_note, note_de);
  }


  #[test]
  fn test_serialization() {
    do_test_serialization(XfrType::NonConfidential_SingleAsset, false);
    do_test_serialization(XfrType::NonConfidentialAmount_ConfidentialAssetType_SingleAsset,
                          false);
    do_test_serialization(XfrType::ConfidentialAmount_NonConfidentialAssetType_SingleAsset,
                          false);
    do_test_serialization(XfrType::Confidential_SingleAsset, false);

    do_test_serialization(XfrType::ConfidentialAmount_NonConfidentialAssetType_SingleAsset,
                          true);
    do_test_serialization(XfrType::Confidential_SingleAsset, true);
  }

  */
}
