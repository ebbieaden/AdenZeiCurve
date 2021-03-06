use crate::basics::hash_functions::mimc::MiMCHash;
use ruc::{*, err::*};
use crate::bp_circuits::array_inclusion::array_membership;
use crate::bp_circuits::merkle_path::merkle_verify_mimc;
use crate::merkle_tree::binary_merkle_tree::{
  mt_build, mt_prove, MerkleRoot, MerkleTree, PathDirection,
};
use bulletproofs::r1cs::{Prover, R1CSProof, Variable, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use algebra::ristretto::{RistrettoScalar as Scalar, CompressedRistretto};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;
use algebra::groups::Scalar as _;

pub const THRESHOLD: usize = 10;

pub fn build_mt_whitelist(elements: &[Scalar]) -> Result<MerkleTree<Scalar>> {
  mt_build::<Scalar, MiMCHash>(elements).c(d!())
}

pub struct WhitelistProof {
  witness_commitments: Vec<CompressedRistretto>,
  proof: R1CSProof,
}

pub fn prove_mt_membership<R: CryptoRng + RngCore>(prng: &mut R,
                                                   mt: &MerkleTree<Scalar>,
                                                   index: usize,
                                                   elem: &CompressedRistretto,
                                                   blind: &Scalar)
                                                   -> Result<WhitelistProof> {
  let pc_gens = PedersenGens::default();

  let mut witness_commitments = vec![];

  let (s, path) = mt_prove(mt, index).c(d!())?;
  let mut prover_transcript = Transcript::new(b"MerkleTreePath");
  let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

  let (com_elem, var_elem) = prover.commit(s.0, blind.0);
  if CompressedRistretto(com_elem) != *elem {
    return Err(eg!(ZeiError::ParameterError));
  }
  let mut var_path = vec![];
  for (direction, sibling) in path.iter() {
    let (dir_com, dir_var) = match *direction {
      PathDirection::RIGHT => prover.commit(
        curve25519_dalek::scalar::Scalar::from(1u8),
        curve25519_dalek::scalar::Scalar::random(prng)),
      PathDirection::LEFT => prover.commit(
        curve25519_dalek::scalar::Scalar::from(0u8),
        curve25519_dalek::scalar::Scalar::random(prng)),
    };
    let (sibling_com, sibling_var) = prover.commit(sibling.0, curve25519_dalek::scalar::Scalar::random(prng));
    var_path.push((dir_var, sibling_var));
    witness_commitments.push(CompressedRistretto(dir_com));
    witness_commitments.push(CompressedRistretto(sibling_com));
  }

  let num_left_wires =
    merkle_verify_mimc(&mut prover,
                       var_elem,
                       &var_path[..],
                       mt.root.value,
                       Scalar::from_u64(mt.size as u64)).map_err(|_| ZeiError::WhitelistProveError).c(d!())?;
  let num_gens = num_left_wires.next_power_of_two();
  let bp_gens = BulletproofGens::new(num_gens, 1);
  let proof = prover.prove(&bp_gens).c(d!(ZeiError::WhitelistProveError))?;

  Ok(WhitelistProof { witness_commitments,
                      proof })
}
pub fn prove_array_membership(elements: &[Scalar],
                              index: usize,
                              elem: &CompressedRistretto,
                              blind: &Scalar)
                              -> Result<WhitelistProof> {
  let pc_gens = PedersenGens::default();
  let mut prover_transcript = Transcript::new(b"LinearInclusionProof");
  let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
  let (com_elem, var_elem) = prover.commit(elements[index].0, blind.0);
  assert_eq!(CompressedRistretto(com_elem), *elem);
  let left_wires = array_membership(&mut prover, &elements[..], var_elem);
  let bp_gens = BulletproofGens::new(left_wires.next_power_of_two(), 1);
  let proof = prover.prove(&bp_gens).c(d!(ZeiError::WhitelistProveError))?;

  Ok(WhitelistProof { witness_commitments: vec![],
                      proof })
}

pub fn verify_mt_membership(mt_root: &MerkleRoot<Scalar>,
                            elem_com: &CompressedRistretto,
                            proof: &WhitelistProof)
                            -> Result<()> {
  let pc_gens = PedersenGens::default();

  let mut verifier_transcript = Transcript::new(b"MerkleTreePath");
  let mut verifier = Verifier::new(&mut verifier_transcript);
  let elem_var = verifier.commit(elem_com.0);
  let mut path_var = vec![];
  let mut direction: Variable = Variable::One();
  let mut even = true;
  for e in proof.witness_commitments.iter() {
    if even {
      direction = verifier.commit(e.0);
    } else {
      let sibling = verifier.commit(e.0);
      path_var.push((direction, sibling));
    }
    even = !even;
  }
  let num_left_wires =
    merkle_verify_mimc(&mut verifier,
                       elem_var,
                       &path_var[..],
                       mt_root.value,
                       Scalar::from_u64(mt_root.size as u64))
    .c(d!(ZeiError::WhitelistVerificationError))?;

  let num_gens = num_left_wires.next_power_of_two();
  let bp_gens = BulletproofGens::new(num_gens, 1);
  verifier.verify(&proof.proof, &pc_gens, &bp_gens)
      .c(d!(ZeiError::WhitelistVerificationError))
}
pub fn verify_array_membership(elements: &[Scalar],
                               elem_com: &CompressedRistretto,
                               proof: &WhitelistProof)
                               -> Result<()> {
  let pc_gens = PedersenGens::default();
  let mut verifier_transcript = Transcript::new(b"LinearInclusionProof");
  let mut verifier = Verifier::new(&mut verifier_transcript);
  let elem_var = verifier.commit(elem_com.0);

  let num_left_wires = array_membership(&mut verifier, &elements[..], elem_var);
  let bp_gens = BulletproofGens::new(num_left_wires.next_power_of_two(), 1);
  verifier.verify(&proof.proof, &pc_gens, &bp_gens)
      .c(d!(ZeiError::WhitelistVerificationError))
}

#[cfg(test)]
mod test {
  use crate::whitelist::build_mt_whitelist;
  use bulletproofs::PedersenGens;
  use curve25519_dalek::scalar::Scalar;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_mt_membership() {
    let elements = [Scalar::from(1u8),
                    Scalar::from(2u8),
                    Scalar::from(3u8),
                    Scalar::from(4u8),
                    Scalar::from(5u8),
                    Scalar::from(6u8),
                    Scalar::from(7u8),
                    Scalar::from(8u8)];
    let mt = build_mt_whitelist(&elements).unwrap();

    let mut prng = ChaChaRng::from_seed([0u8; 32]);

    let pc_gens = PedersenGens::default();
    for index in &[0usize, 5, 7] {
      let blind = Scalar::random(&mut prng);
      let commitment = pc_gens.commit(elements[*index], blind).compress();
      let proof = super::prove_mt_membership(&mut prng, &mt, *index, &commitment, &blind).unwrap();

      assert!(super::verify_mt_membership(&mt.get_root(), &commitment, &proof).is_ok())
    }
  }

  #[test]
  fn test_array_membership() {
    let elements = [Scalar::from(1u8),
                    Scalar::from(2u8),
                    Scalar::from(3u8),
                    Scalar::from(4u8),
                    Scalar::from(5u8),
                    Scalar::from(6u8),
                    Scalar::from(7u8),
                    Scalar::from(8u8)];

    let mut prng = ChaChaRng::from_seed([0u8; 32]);

    let pc_gens = PedersenGens::default();
    for index in 0usize..elements.len() {
      let blind = Scalar::random(&mut prng);
      let commitment = pc_gens.commit(elements[index], blind).compress();
      let proof = super::prove_array_membership(&elements, index, &commitment, &blind).unwrap();

      assert!(super::verify_array_membership(&elements, &commitment, &proof).is_ok())
    }
  }
}
