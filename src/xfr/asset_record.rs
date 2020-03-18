use crate::algebra::groups::Scalar as ZeiScalar;
use crate::api::anon_creds::{
  ac_confidential_open_commitment, ACCommitmentKey, ACUserSecretKey, AttributeCiphertext,
  ConfidentialAC, Credential,
};
use crate::basic_crypto::elgamal::elgamal_encrypt;
use crate::basic_crypto::hybrid_encryption::{hybrid_decrypt, hybrid_encrypt};
use crate::errors::ZeiError;
use crate::utils::{u64_to_bigendian_u8array, u64_to_u32_pair, u8_bigendian_slice_to_u64};
use crate::xfr::sig::{XfrPublicKey, XfrSecretKey};
use crate::xfr::structs::{
  asset_type_to_scalar, AssetRecord, AssetRecordTemplate, AssetTracerEncKeys, AssetTracerMemo,
  AssetTracingPolicy, AssetType, BlindAssetRecord, OpenAssetRecord, OwnerMemo, XfrAmount,
  XfrAssetType,
};
use boolinator::Boolinator;
use bulletproofs::PedersenGens;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// AssetRecrod confidentiality flags. Indicated if amount and/or assettype should be confidential
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum AssetRecordType {
  NonConfidentialAmount_ConfidentialAssetType,
  ConfidentialAmount_NonConfidentialAssetType,
  ConfidentialAmount_ConfidentialAssetType,
  NonConfidentialAmount_NonConfidentialAssetType,
}

impl AssetRecordType {
  /// Return (true,_) if amount is confidential,
  /// Return (_,false) if type is confidential,
  pub fn get_booleans(self) -> (bool, bool) {
    // confidential amount, confidential asset type
    match self {
      AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType => (false, false),
      AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => (true, false),
      AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => (false, true),
      AssetRecordType::ConfidentialAmount_ConfidentialAssetType => (true, true),
    }
  }

  pub fn is_confidential_amount(self) -> bool {
    match self {
      AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
      | AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => false,
      _ => true,
    }
  }
  pub fn is_confidential_asset_type(self) -> bool {
    match self {
      AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
      | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => false,
      _ => true,
    }
  }
  pub fn is_confidential_amount_and_type(self) -> bool {
    match self {
      AssetRecordType::ConfidentialAmount_ConfidentialAssetType => true,
      _ => false,
    }
  }

  pub fn from_booleans(conf_amt: bool, conf_type: bool) -> Self {
    match (conf_amt, conf_type) {
      (false, false) => AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
      (true, false) => AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
      (false, true) => AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
      (true, true) => AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
    }
  }
}

impl AssetRecord {
  /// Build a record input from OpenAssetRecord with no associated policy
  /// Important: It assumes that RecordInput will be used as an input to xfr_note_gen and not as an output
  /// since OpenAsset record was recovered from a BlindAsset record. This means owner_memo field is None.
  pub fn from_open_asset_record_no_asset_tracking(oar: OpenAssetRecord) -> AssetRecord {
    AssetRecord { open_asset_record: oar,
                  tracking_policy: None,
                  identity_proof: None,
                  asset_tracer_memo: None,
                  owner_memo: None }
  }

  /// Build a record input from OpenAssetRecord with an associated policy that has no identity tracking
  /// Important: It assumes that RecordInput will be used as an input to xfr_note_gen and not as an output
  /// since OpenAsset record was recovered from a BlindAsset record. This means owner_memo field is be None.
  pub fn from_open_asset_record_with_asset_tracking_but_no_identity(
    oar: OpenAssetRecord,
    asset_tracking_policy: AssetTracingPolicy)
    -> Result<AssetRecord, ZeiError> {
    // 1. check for inconsistency errors
    if asset_tracking_policy.identity_tracking.is_some() {
      return Err(ZeiError::ParameterError); // should use from_open_asset_record_with_identity_tracking method
    };
    // 2. compute tracer_memo
    let (amount_info, asset_type_info) = if asset_tracking_policy.asset_tracking {
      let amount_info = match oar.get_record_type() {
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
        | AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => None,
        _ => {
          let amount = u64_to_u32_pair(oar.amount);
          Some((amount.0, amount.1, &oar.amount_blinds.0, &oar.amount_blinds.1))
        }
      };
      let asset_type_info = match oar.get_record_type() {
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
        | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => None,
        _ => Some((asset_type_to_scalar(&oar.asset_type), &oar.type_blind)),
      };
      (amount_info, asset_type_info)
    } else {
      (None, None)
    };
    let asset_tracer_memo = compute_tracer_memo(&asset_tracking_policy.enc_keys,
                                                amount_info,
                                                asset_type_info,
                                                None);
    Ok(AssetRecord { open_asset_record: oar,
                     tracking_policy: Some(asset_tracking_policy),
                     identity_proof: None,
                     asset_tracer_memo: Some(asset_tracer_memo),
                     owner_memo: None })
  }

  /// Build a record input from OpenAssetRecord with an associated policy
  /// Important: It assumes that RecordInput will be used as an input to xfr_note_gen and not as an output
  /// since OpenAsset record was recovered from a BlindAsset record. This means owner_memo field is be None.
  pub fn from_open_asset_record_with_identity_tracking<R: CryptoRng + RngCore>(
    prng: &mut R,
    oar: OpenAssetRecord,
    asset_tracking_policy: AssetTracingPolicy,
    credential_sec_key: &ACUserSecretKey,
    credential: &Credential,
    credential_commitment_key: &ACCommitmentKey)
    -> Result<AssetRecord, ZeiError> {
    // 1. check for inconsistency errors
    let identity_tracking = asset_tracking_policy.identity_tracking
                                                 .as_ref()
                                                 .ok_or(ZeiError::ParameterError)?;
    if credential.issuer_pub_key != identity_tracking.cred_issuer_pub_key {
      return Err(ZeiError::ParameterError);
    }

    // 2. compute tracer_memo
    let (amount_info, asset_type_info) = if asset_tracking_policy.asset_tracking {
      let amount_info = match oar.get_record_type() {
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
        | AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => None,
        _ => {
          let amount = u64_to_u32_pair(oar.amount);
          Some((amount.0, amount.1, &oar.amount_blinds.0, &oar.amount_blinds.1))
        }
      };
      let asset_type_info = match oar.get_record_type() {
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
        | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => None,
        _ => Some((asset_type_to_scalar(&oar.asset_type), &oar.type_blind)),
      };
      (amount_info, asset_type_info)
    } else {
      (None, None)
    };

    // Identity reveal proof and ciphertexts
    let confidential_reveal =
      ac_confidential_open_commitment(prng,
                                      credential_sec_key,
                                      credential,
                                      credential_commitment_key,
                                      &asset_tracking_policy.enc_keys.attrs_enc_key,
                                      identity_tracking.reveal_map.as_slice(),
                                      &[])?;
    let (attrs, identity_proof) = confidential_reveal.get_fields();
    let asset_tracer_memo = compute_tracer_memo(&asset_tracking_policy.enc_keys,
                                                amount_info,
                                                asset_type_info,
                                                Some(attrs));
    Ok(AssetRecord { open_asset_record: oar,
                     tracking_policy: Some(asset_tracking_policy),
                     identity_proof: Some(identity_proof),
                     asset_tracer_memo: Some(asset_tracer_memo),
                     owner_memo: None })
  }

  pub fn from_template_no_identity_tracking<R: CryptoRng + RngCore>(
    prng: &mut R,
    template: &AssetRecordTemplate)
    -> Result<AssetRecord, ZeiError> {
    if let Some(policy) = &template.asset_tracking {
      if policy.identity_tracking.is_some() {
        return Err(ZeiError::ParameterError);
      }
    }
    build_record_input_from_template(prng, &template, None)
  }

  pub fn from_template_with_identity_tracking<R: CryptoRng + RngCore>(
    prng: &mut R,
    template: &AssetRecordTemplate,
    credential_user_sec_key: &ACUserSecretKey,
    credential: &Credential,
    credential_key: &ACCommitmentKey)
    -> Result<AssetRecord, ZeiError> {
    match &template.asset_tracking {
      None => Err(ZeiError::ParameterError), // identity tracking must have asset_tracking policy
      Some(policy) => {
        match &policy.identity_tracking {
          None => Err(ZeiError::ParameterError), // policy must have a identity tracking policy
          Some(reveal_policy) => {
            let conf_ac = ac_confidential_open_commitment(prng,
                                                          credential_user_sec_key,
                                                          credential,
                                                          credential_key,
                                                          &policy.enc_keys.attrs_enc_key,
                                                          &reveal_policy.reveal_map,
                                                          &[])?;
            build_record_input_from_template(prng, &template, Some(conf_ac))
          }
        }
      }
    }
  }
}

impl AssetRecordTemplate {
  /// Creates a AssetRecordTemplate with no associated asset tracing policy
  pub fn with_no_asset_tracking(amount: u64,
                                asset_type: AssetType,
                                asset_record_type: AssetRecordType,
                                address: XfrPublicKey)
                                -> AssetRecordTemplate {
    AssetRecordTemplate { amount,
                          asset_type,
                          public_key: address,
                          asset_record_type,
                          asset_tracking: None }
  }
  pub fn with_asset_tracking(amount: u64,
                             asset_type: AssetType,
                             asset_record_type: AssetRecordType,
                             address: XfrPublicKey,
                             policy: AssetTracingPolicy)
                             -> AssetRecordTemplate {
    let mut template =
      AssetRecordTemplate::with_no_asset_tracking(amount, asset_type, asset_record_type, address);
    template.asset_tracking = Some(policy);
    template
  }
}
fn sample_blind_asset_record<R: CryptoRng + RngCore>(
  prng: &mut R,
  pc_gens: &PedersenGens,
  asset_record: &AssetRecordTemplate,
  identity_ctexts: Option<Vec<AttributeCiphertext>>)
  -> (BlindAssetRecord, (Scalar, Scalar), Scalar, Option<AssetTracerMemo>, Option<OwnerMemo>) {
  let type_scalar = asset_type_to_scalar(&asset_record.asset_type);

  let (confidential_amount, confidential_asset) = match &asset_record.asset_record_type {
    AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType => (false, false),
    AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => (true, false),
    AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => (false, true),
    AssetRecordType::ConfidentialAmount_ConfidentialAssetType => (true, true),
  };

  let (amount_blind_low, amount_blind_high, type_blind, blind_share) = if confidential_asset
                                                                          || confidential_amount
  {
    let (derived_point, blind_share) = sample_point_and_blind_share(prng, &asset_record.public_key);
    let type_blind = compute_blind_factor(&derived_point, b"asset_type");
    let amount_blind_low = compute_blind_factor(&derived_point, b"amount_low");
    let amount_blind_high = compute_blind_factor(&derived_point, b"amount_high");
    (amount_blind_low, amount_blind_high, type_blind, blind_share)
  } else {
    (Scalar::zero(), Scalar::zero(), Scalar::zero(), CompressedEdwardsY::default())
  };

  let (amount_low, amount_high) = u64_to_u32_pair(asset_record.amount);
  let mut amount_type_bytes = vec![];

  // build amount fields
  let (xfr_amount, amount_blinds) = if confidential_amount {
    let amount_bytes = u64_to_bigendian_u8array(asset_record.amount);
    amount_type_bytes.extend_from_slice(&amount_bytes[..]);

    let amount_commitment_low = pc_gens.commit(Scalar::from(amount_low), amount_blind_low);
    let amount_commitment_high = pc_gens.commit(Scalar::from(amount_high), amount_blind_high);
    let xfr_amount = XfrAmount::Confidential((amount_commitment_low.compress(),
                                              amount_commitment_high.compress()));
    (xfr_amount, (amount_blind_low, amount_blind_high))
  } else {
    let xfr_amount = XfrAmount::NonConfidential(asset_record.amount);
    (xfr_amount, (Scalar::zero(), Scalar::zero()))
  };

  // build asset type fields
  let (xfr_asset_type, type_blind) = if confidential_asset {
    amount_type_bytes.extend_from_slice(&asset_record.asset_type);
    let xfr_asset_type =
      XfrAssetType::Confidential(pc_gens.commit(type_scalar, type_blind).compress());
    (xfr_asset_type, type_blind)
  } else {
    (XfrAssetType::NonConfidential(asset_record.asset_type), Scalar::zero())
  };

  // asset tracing amount
  let tracer_memo = match &asset_record.asset_tracking {
    Some(tracking_policy) => {
      let (amount_info, asset_type_info) = if tracking_policy.asset_tracking {
        (confidential_amount.as_some((amount_low,
                                      amount_high,
                                      &amount_blind_low,
                                      &amount_blind_high)),
         confidential_asset.as_some((type_scalar, &type_blind)))
      } else {
        (None, None)
      };
      Some(compute_tracer_memo(&tracking_policy.enc_keys,
                               amount_info,
                               asset_type_info,
                               identity_ctexts))
    }
    None => None,
  };

  let owner_memo = if confidential_asset || confidential_amount {
    let lock = hybrid_encrypt(prng,
                              &asset_record.public_key.0,
                              amount_type_bytes.as_slice()).unwrap();
    Some(OwnerMemo { blind_share, lock })
  } else {
    None
  };
  let blind_asset_record = BlindAssetRecord { public_key: asset_record.public_key,
                                              amount: xfr_amount,
                                              asset_type: xfr_asset_type };

  (blind_asset_record, amount_blinds, type_blind, tracer_memo, owner_memo)
}

fn compute_tracer_memo(tracer_enc_key: &AssetTracerEncKeys,
                       amount_info: Option<(u32, u32, &Scalar, &Scalar)>, //amount low and high and blindings
                       asset_type_info: Option<(Scalar, &Scalar)>,
                       attributes: Option<Vec<AttributeCiphertext>>)
                       -> AssetTracerMemo {
  let pc_gens = PedersenGens::default();
  let lock_amount =
    amount_info.map(|(amount_low, amount_high, blind_low, blind_high)| {
                 let ctext_amount_low = elgamal_encrypt(&pc_gens.B,
                                                        &Scalar::from_u32(amount_low),
                                                        blind_low,
                                                        &tracer_enc_key.record_data_enc_key);
                 let ctext_amount_high = elgamal_encrypt(&pc_gens.B,
                                                         &Scalar::from_u32(amount_high),
                                                         blind_high,
                                                         &tracer_enc_key.record_data_enc_key);
                 (ctext_amount_low, ctext_amount_high)
               });

  let lock_asset_type = asset_type_info.map(|(type_scalar, blind)| {
                                         elgamal_encrypt(&pc_gens.B,
                                                         &type_scalar,
                                                         blind,
                                                         &tracer_enc_key.record_data_enc_key)
                                       });

  AssetTracerMemo { enc_key: tracer_enc_key.clone(),
                    lock_amount,
                    lock_asset_type,
                    lock_attributes: attributes }
}

/// Build OpenAssetRecord and associated memos from an Asset Record Template
/// and encrypted identity attributes to confidentially reveal (if policy indicates so).
/// Used to create outputs blind asset record from an asset record template.
/// Return:
///  - OpenAssetRecord,
///  - Option<AssetTracerMemo> // Some(memo) if required by asset_record.asset_tracking policy
///  - Option<OwnerMemo> // Some(memo)  if asset_record.asset_record_type has a confidential flag
pub fn build_open_asset_record<R: CryptoRng + RngCore>(
  prng: &mut R,
  pc_gens: &PedersenGens,
  asset_record: &AssetRecordTemplate,
  identity_ctexts: Option<Vec<AttributeCiphertext>>)
  -> (OpenAssetRecord, Option<AssetTracerMemo>, Option<OwnerMemo>) {
  let (blind_asset_record, amount_blinds, type_blind, asset_tracing_memo, owner_memo) =
    sample_blind_asset_record(prng, pc_gens, asset_record, identity_ctexts);

  let open_asset_record = OpenAssetRecord { blind_asset_record,
                                            amount: asset_record.amount,
                                            amount_blinds,
                                            asset_type: asset_record.asset_type,
                                            type_blind };

  (open_asset_record, asset_tracing_memo, owner_memo)
}

/// Build BlindAssetRecord and associated memos  from an Asset Record Template
/// and encrypted identity attributes to confidentially reveal (if policy indicates so).
/// Used to create outputs blind asset record from an asset record template.
/// Return:
///  - BlindAssetRecord,
///  - Option<AssetTracerMemo> // Some(memo) if required by asset_record.asset_tracking policy
///  - Option<OwnerMemo> // Some(memo)  if asset_record.asset_record_type has a confidential flag
pub fn build_blind_asset_record<R: CryptoRng + RngCore>(
  prng: &mut R,
  pc_gens: &PedersenGens,
  asset_record: &AssetRecordTemplate,
  identity_ctexts: Option<Vec<AttributeCiphertext>>)
  -> (BlindAssetRecord, Option<AssetTracerMemo>, Option<OwnerMemo>) {
  let (blind_asset_record, _, _, asset_tracing_memo, owner_memo) =
    sample_blind_asset_record(prng, pc_gens, asset_record, identity_ctexts);

  (blind_asset_record, asset_tracing_memo, owner_memo)
}

fn sample_point_and_blind_share<R: CryptoRng + RngCore>(
  prng: &mut R,
  public_key: &XfrPublicKey)
  -> (CompressedEdwardsY, CompressedEdwardsY) {
  let blind_key = Scalar::random(prng);
  let pk_point = public_key.get_curve_point().unwrap();
  let derived_point: EdwardsPoint = blind_key * pk_point;
  let blind_share = blind_key * ED25519_BASEPOINT_POINT;
  (derived_point.compress(), blind_share.compress())
}

pub(crate) fn derive_point_from_blind_share(blind_share: &CompressedEdwardsY,
                                            secret_key: &XfrSecretKey)
                                            -> Result<CompressedEdwardsY, ZeiError> {
  let blind_share_decompressed = blind_share.decompress()
                                            .ok_or(ZeiError::DecompressElementError)?;
  Ok(secret_key.as_scalar_multiply_by_curve_point(&blind_share_decompressed)
               .compress())
}

pub(crate) fn compute_blind_factor(point: &CompressedEdwardsY, aux: &'static [u8]) -> Scalar {
  let mut hasher = Sha512::new();
  hasher.input(point.as_bytes());
  hasher.input(aux);
  Scalar::from_hash(hasher)
}

/// Open a blind asset record using owner secret key and associated owner's memo.
/// Return Ok(OpenAssetRecord) or
/// ZeiError if case of decryption error or inconsistent plaintext error.
/// Used by transfers receivers
pub fn open_blind_asset_record(input: &BlindAssetRecord,
                               owner_memo: &Option<OwnerMemo>,
                               secret_key: &XfrSecretKey)
                               -> Result<OpenAssetRecord, ZeiError> {
  let amount;
  let mut asset_type = [0u8; 16];
  let amount_blind_low;
  let amount_blind_high;
  let type_blind;
  let mut shared_point = CompressedEdwardsY::default();

  let mut i = 0;
  let amount_type = match owner_memo {
    None => vec![],
    Some(memo) => {
      shared_point = derive_point_from_blind_share(&memo.blind_share, secret_key)?;
      hybrid_decrypt(&memo.lock, &secret_key.0)?
    }
  };

  match input.amount {
    XfrAmount::Confidential(_) => {
      amount = u8_bigendian_slice_to_u64(&amount_type[0..8]);
      amount_blind_low = compute_blind_factor(&shared_point, b"amount_low");
      amount_blind_high = compute_blind_factor(&shared_point, b"amount_high");
      i += 8;
    }
    XfrAmount::NonConfidential(a) => {
      amount = a;
      amount_blind_low = Scalar::zero();
      amount_blind_high = Scalar::zero();
    }
  }

  match input.asset_type {
    XfrAssetType::Confidential(_) => {
      asset_type.copy_from_slice(&amount_type[i..i + 16]);
      type_blind = compute_blind_factor(&shared_point, b"asset_type");
    }
    XfrAssetType::NonConfidential(a) => {
      asset_type = a;
      type_blind = Scalar::zero();
    }
  };

  // TODO check correctness of BlindAssetRecord
  Ok(OpenAssetRecord { asset_type,
                       amount,
                       blind_asset_record: input.clone(),
                       amount_blinds: (amount_blind_low, amount_blind_high),
                       type_blind })
}

/// Generates an RecordInput from an asset_record using identity proof of identity tracking
/// and corresponding ciphertexts.
/// This function is used to generate an output for gen_xfr_note/body
fn build_record_input_from_template<R: CryptoRng + RngCore>(prng: &mut R,
                                                            asset_record: &AssetRecordTemplate,
                                                            identity_proof: Option<ConfidentialAC>)
                                                            -> Result<AssetRecord, ZeiError> {
  // Check input consistency:
  // - if no policy, then no identity proof needed
  // - if policy and identity tracking, then identity proof is needed
  // - if policy but no identity tracking, then no identity proof is needed
  if asset_record.asset_tracking.is_none() && identity_proof.is_some()
     || asset_record.asset_tracking.is_some()
        && (asset_record.asset_tracking
                        .as_ref()
                        .unwrap()
                        .identity_tracking
                        .is_some()
            && identity_proof.is_none()
            || asset_record.asset_tracking
                           .as_ref()
                           .unwrap()
                           .identity_tracking
                           .is_none()
               && identity_proof.is_some())
  {
    return Err(ZeiError::ParameterError);
  }

  // 1. get ciphertext and proofs from from identity proof structure
  let pc_gens = PedersenGens::default();
  let (attr_ctext, reveal_proof) = match identity_proof {
    None => (None, None),
    Some(conf_ac) => {
      let (c, p) = conf_ac.get_fields();
      (Some(c), Some(p))
    }
  };

  // 2. Use record template and ciphertexts to build open asset record
  let (open_asset_record, asset_tracing_memo, owner_memo) =
    build_open_asset_record(prng, &pc_gens, asset_record, attr_ctext);

  // 3. Return record input containing open asset record, tracking policy, identity reveal proof,
  //    asset_tracer_memo, and owner_memo
  Ok(AssetRecord { open_asset_record,
                   tracking_policy: asset_record.asset_tracking.clone(),
                   identity_proof: reveal_proof,
                   asset_tracer_memo: asset_tracing_memo,
                   owner_memo })
}

#[cfg(test)]
mod test {
  use super::{build_blind_asset_record, build_open_asset_record, open_blind_asset_record};
  use crate::algebra::bls12_381::{BLSScalar, BLSG1};
  use crate::algebra::groups::Group;
  use crate::basic_crypto::elgamal::{elgamal_key_gen, ElGamalEncKey};
  use crate::utils::{u64_to_u32_pair, u8_bigendian_slice_to_u128};
  use crate::xfr::asset_record::AssetRecordType;
  // use crate::xfr::lib::XfrType;
  use crate::xfr::sig::XfrKeyPair;
  use crate::xfr::structs::{
    AssetRecordTemplate, AssetTracerEncKeys, AssetTracingPolicy, AssetType, OpenAssetRecord,
    XfrAmount, XfrAssetType,
  };
  use crate::xfr::tests::tests::{create_xfr, gen_key_pair_vec};
  use bulletproofs::PedersenGens;
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;
  use itertools::Itertools;
  use rand::Rng;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  fn do_test_build_open_asset_record(record_type: AssetRecordType, asset_tracking: bool) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let amount = 100u64;
    let asset_type = [0u8; 16];
    let keypair = XfrKeyPair::generate(&mut prng);
    let tracing_policy = match asset_tracking {
      true => {
        let (_sk, xfr_pub_key) =
          elgamal_key_gen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);
        let (_sk, id_reveal_pub_key) =
          elgamal_key_gen::<_, BLSScalar, BLSG1>(&mut prng, &BLSG1::get_base());
        let tracer_enc_key = AssetTracerEncKeys { record_data_enc_key:
                                                    ElGamalEncKey(xfr_pub_key.get_point()),
                                                  attrs_enc_key: id_reveal_pub_key };
        let tracing_policy = AssetTracingPolicy { enc_keys: tracer_enc_key,
                                                  asset_tracking: true,
                                                  identity_tracking: None };
        Some(tracing_policy)
      }
      false => None,
    };

    let asset_record = if asset_tracking {
      AssetRecordTemplate::with_asset_tracking(amount,
                                               asset_type,
                                               record_type,
                                               keypair.get_pk(),
                                               tracing_policy.unwrap())
    } else {
      AssetRecordTemplate::with_no_asset_tracking(amount, asset_type, record_type, keypair.get_pk())
    };

    let (open_ar, asset_tracer_memo, owner_memo) =
      build_open_asset_record(&mut prng, &pc_gens, &asset_record, None);

    assert_eq!(amount, open_ar.amount);
    assert_eq!(asset_type, open_ar.asset_type);
    assert_eq!(keypair.get_pk_ref(), &open_ar.blind_asset_record.public_key);

    let expected_bar_amount;
    let expected_bar_asset_type;

    let (confidential_amount, confidential_asset) = record_type.get_booleans();
    if confidential_amount {
      let (low, high) = u64_to_u32_pair(amount);
      let commitment_low = pc_gens.commit(Scalar::from(low), open_ar.amount_blinds.0)
                                  .compress();
      let commitment_high = pc_gens.commit(Scalar::from(high), open_ar.amount_blinds.1)
                                   .compress();
      expected_bar_amount = XfrAmount::Confidential((commitment_low, commitment_high));
    } else {
      expected_bar_amount = XfrAmount::NonConfidential(amount)
      //expected_bar_lock_amount_none = true;
    }

    if confidential_asset {
      let type_as_u128 = u8_bigendian_slice_to_u128(&asset_record.asset_type[..]);
      let type_scalar = Scalar::from(type_as_u128);
      expected_bar_asset_type =
        XfrAssetType::Confidential(pc_gens.commit(type_scalar, open_ar.type_blind).compress());
    } else {
      expected_bar_asset_type = XfrAssetType::NonConfidential(asset_type);
      //expected_bar_lock_type_none = true;
    }
    assert_eq!(expected_bar_amount, open_ar.blind_asset_record.amount);

    assert_eq!(expected_bar_asset_type,
               open_ar.blind_asset_record.asset_type);
    assert_eq!(confidential_asset || confidential_amount,
               owner_memo.is_some());

    assert_eq!(asset_tracking, asset_tracer_memo.is_some());
    if asset_tracking {
      assert_eq!(confidential_asset,
                 asset_tracer_memo.as_ref()
                                  .unwrap()
                                  .lock_asset_type
                                  .is_some());
      assert_eq!(confidential_amount,
                 asset_tracer_memo.as_ref().unwrap().lock_amount.is_some());
    } else {
      assert!(asset_tracer_memo.is_none());
    }
  }

  #[test]
  fn test_build_open_asset_record() {
    do_test_build_open_asset_record(AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType, false);
    do_test_build_open_asset_record(AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType, true);
    do_test_build_open_asset_record(AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
                                    false);
    do_test_build_open_asset_record(AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
                                    true);
    do_test_build_open_asset_record(AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
                                    false);
    do_test_build_open_asset_record(AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
                                    true);
    do_test_build_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                                    false);
    do_test_build_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                                    true);
  }

  fn do_test_open_asset_record(record_type: AssetRecordType) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let asset_type = [1u8; 16];

    let inkeys = gen_key_pair_vec(2, &mut prng);
    let outkeys = gen_key_pair_vec(1, &mut prng);

    let input_templates = [AssetRecordTemplate::with_no_asset_tracking(10u64,
                                                                       asset_type,
                                                                       record_type,
                                                                       inkeys[0].get_pk()),
                           AssetRecordTemplate::with_no_asset_tracking(20u64,
                                                                       asset_type,
                                                                       record_type,
                                                                       inkeys[1].get_pk())];

    let output_templates = [AssetRecordTemplate::with_no_asset_tracking(30u64,
                                                                        asset_type,
                                                                        record_type,
                                                                        outkeys[0].get_pk())];

    let (xfr_note, _, _) = create_xfr(&mut prng,
                                      &input_templates,
                                      &output_templates,
                                      inkeys.iter().map(|x| x).collect_vec().as_slice());

    let secret_key = outkeys.get(0).unwrap().get_sk_ref();
    let open_ar = open_blind_asset_record(&xfr_note.body.outputs[0],
                                          &xfr_note.body.owners_memos[0],
                                          secret_key).unwrap();

    assert_eq!(&open_ar.blind_asset_record, &xfr_note.body.outputs[0]);
    assert_eq!(open_ar.amount, 30u64);
    assert_eq!(open_ar.asset_type, [1u8; 16]);

    let (confidential_amount, confidential_asset) = record_type.get_booleans();

    if confidential_amount {
      let (low, high) = u64_to_u32_pair(open_ar.amount);
      let commitment_low = pc_gens.commit(Scalar::from(low), open_ar.amount_blinds.0)
                                  .compress();
      let commitment_high = pc_gens.commit(Scalar::from(high), open_ar.amount_blinds.1)
                                   .compress();
      let derived_commitment = (commitment_low, commitment_high);
      assert_eq!(derived_commitment,
                 open_ar.blind_asset_record.amount.get_commitments().unwrap());
    }

    if confidential_asset {
      let derived_commitment =
        pc_gens.commit(Scalar::from(u8_bigendian_slice_to_u128(&open_ar.asset_type[..])),
                       open_ar.type_blind)
               .compress();
      assert_eq!(derived_commitment,
                 open_ar.blind_asset_record
                        .asset_type
                        .get_commitment()
                        .unwrap());
    }
  }

  #[test]
  fn test_open_asset_record() {
    do_test_open_asset_record(AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType);
    do_test_open_asset_record(AssetRecordType::NonConfidentialAmount_ConfidentialAssetType);
    do_test_open_asset_record(AssetRecordType::ConfidentialAmount_NonConfidentialAssetType);
    do_test_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType);
    do_test_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType);
  }

  fn build_and_open_blind_record(record_type: AssetRecordType, amt: u64, asset_type: AssetType) {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let keypair = XfrKeyPair::generate(&mut prng);
    let (pubkey, privkey) = (keypair.get_pk_ref(), keypair.get_sk_ref());
    let ar =
      AssetRecordTemplate::with_no_asset_tracking(amt, asset_type, record_type, pubkey.clone());

    let (blind_rec, _asset_tracer_memo, owner_memo) =
      build_blind_asset_record(&mut prng, &pc_gens, &ar, None);

    let open_rec = open_blind_asset_record(&blind_rec, &owner_memo, &privkey).unwrap();

    assert_eq!(*open_rec.get_amount(), amt);
    assert_eq!(*open_rec.get_asset_type(), asset_type);

    let oar_bytes = serde_json::to_string(&open_rec).unwrap();
    let oar_de: OpenAssetRecord = serde_json::from_str(oar_bytes.as_str()).unwrap();
    assert_eq!(open_rec, oar_de);
  }

  #[test]
  fn test_build_and_open_blind_record() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let asset_type: AssetType = prng.gen();
    let amt: u64 = prng.gen();

    build_and_open_blind_record(AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
                                amt,
                                asset_type);
    build_and_open_blind_record(AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
                                amt,
                                asset_type);
    build_and_open_blind_record(AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
                                amt,
                                asset_type);
    build_and_open_blind_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                                amt,
                                asset_type);
  }
}
