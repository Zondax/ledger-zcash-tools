/*******************************************************************************
*   (c) 2022-2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use std::ops::{AddAssign, Neg};

use bellman::{
    gadgets::multipack,
    groth16::{create_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof},
};
use bls12_381::Bls12;
use ff::Field;
use group::Curve;
use group::GroupEncoding;
use pairing::Engine;
use rand::RngCore;
use rand_core::OsRng;
use redjubjub::{Binding, Randomizer, SigType, Signature, SigningKey, SpendAuth, VerificationKey};
use zcash_primitives::transaction::components::Amount;
use sapling_crypto::{
    circuit::{Output, OutputParameters, PreparedSpendVerifyingKey, Spend, SpendParameters, ValueCommitmentOpening}, constants::{
        SPENDING_KEY_GENERATOR,
        VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        VALUE_COMMITMENT_VALUE_GENERATOR,
    }, prover::{OutputProver, SpendProver}, value::{NoteValue, ValueCommitTrapdoor, ValueCommitment}, MerklePath, Note, PaymentAddress, Rseed
};
use crate::errors::ProverError;

fn compute_value_balance_hsm(value: Amount) -> Option<jubjub::ExtendedPoint> {
    // Compute the absolute value (failing if -i64::MAX is
    // the value)
    let abs = match i64::from(value).checked_abs() {
        Some(a) => a as u64,
        None => return None,
    };

    // Is it negative? We'll have to negate later if so.
    let is_negative = value.is_negative();

    // Compute it in the exponent
    let mut value_balance = VALUE_COMMITMENT_VALUE_GENERATOR * jubjub::Fr::from(abs);

    // Negate if necessary
    if is_negative {
        value_balance = -value_balance;
    }

    // Convert to unknown order point
    Some(value_balance.into())
}

/// A context object for creating the Sapling components of a Zcash transaction.
///
/// HSM compatible version of [`zcash_proofs::sapling::SaplingProvingContext`]
pub struct SaplingProvingContext {
    bsk: jubjub::   Fr,
    // (sum of the Spend value commitments) - (sum of the Output value commitments)
    cv_sum: jubjub::ExtendedPoint,
}

impl SaplingProvingContext {
    /// Construct a new context to be used with a single transaction.

    pub fn new() -> Self {
        SaplingProvingContext { bsk: jubjub::Fr::zero(), cv_sum: jubjub::ExtendedPoint::identity() }
    }

    /// Create the value commitment, re-randomized key, and proof for a Sapling
    /// SpendDescription, while accumulating its value commitment randomness
    /// inside the context for later use.
    pub fn spend_proof(
        &mut self,
        proof_generation_key: sapling_crypto::ProofGenerationKey,
        diversifier: sapling_crypto::Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath,
        proving_key: &SpendParameters,
        verifying_key: &PreparedSpendVerifyingKey,
        rcv: jubjub::Fr,
    ) -> Result<(Proof<Bls12>, jubjub::ExtendedPoint, VerificationKey<SpendAuth>), ProverError> {
        log::info!("spend_proof");

        
        // Initialize secure RNG
        let mut rng = OsRng;

        // We create the randomness of the value commitment
        // let mut buf = [0u8;64];
        //
        // rng.fill_bytes(&mut buf);
        //
        // let rcv = Fr::from_bytes_wide(&buf);
        //
        // Accumulate the value commitment randomness in the context
        {
            let mut tmp = rcv;
            tmp.add_assign(&self.bsk);

            // Update the context
            self.bsk = tmp;
        }

        let instance = SpendParameters::prepare_circuit(
            proof_generation_key,
            diversifier,
            rseed,
            NoteValue::from_raw(value),
            ar,
            rcv,
            anchor,
            merkle_path
        ).unwrap();


        // Create proof
        let proof = proving_key.create_proof(instance, &mut rng);

        // Try to verify the proof:

        // Construct the value commitment
        let rcv_bytes = rcv.to_bytes();

        let value_commitment = ValueCommitmentOpening {
            value: NoteValue::from_raw(value),
            randomness: jubjub::Scalar::from_bytes(&rcv_bytes).unwrap()
        };

        let cv = (VALUE_COMMITMENT_VALUE_GENERATOR
            * jubjub::Fr::from(value_commitment.value.inner()))
            + (VALUE_COMMITMENT_RANDOMNESS_GENERATOR * value_commitment.randomness).into();
        

        // Construct the viewing key
        let viewing_key = proof_generation_key.to_viewing_key();

        // Derive Verification Key
        let rk = viewing_key.rk(ar);
        
        // Construct the payment address with the viewing key / diversifier
        // let payment_address = viewing_key
        //     .to_payment_address(diversifier)
        //     .ok_or(ProverError::InvalidDiversifier)?;
        // // Let's compute the nullifier while we have the position
        // let note = Note::from_parts(payment_address, NoteValue::from_raw(value), rseed);

        // let nullifier = note.nf(&viewing_key.nk, merkle_path.position().into());

        
        // // Construct public input for circuit
        
        // let mut public_input = [bls12_381::Scalar::zero(); 7];
        // {
        //     let affine = rk.to_affine();
        //     let (u, v) = (affine.get_u(), affine.get_v());
        //     public_input[0] = u;
        //     public_input[1] = v;
        // }
        // {
        //     let affine = jubjub::ExtendedPoint::from(cv).to_affine();
        //     let (u, v) = (affine.get_u(), affine.get_v());
        //     public_input[2] = u;
        //     public_input[3] = v;
        // }
        // public_input[4] = anchor;
        
        // // Add the nullifier through multi-scalar packing
        // {
        //     let nullifier = multipack::bytes_to_bits_le(&nullifier.0);
        //     let nullifier = multipack::compute_multipacking(&nullifier);

        //     assert_eq!(nullifier.len(), 2);

        //     public_input[5] = nullifier[0];
        //     public_input[6] = nullifier[1];
        // }

        // // Verify the proof
        // verify_proof(verifying_key, &proof, &public_input[..]).map_err(|e| {
        //     log::error!("Proof verification failed with {}", e.to_string());
        //     ProverError::Verification(e)
        // })?;
        // This is a test function of ValueCommitmentOpening
        let cv = (VALUE_COMMITMENT_VALUE_GENERATOR
            * jubjub::Fr::from(value_commitment.value.inner()))
            + (VALUE_COMMITMENT_RANDOMNESS_GENERATOR * value_commitment.randomness)
            .into();

        let value_commitment: jubjub::ExtendedPoint = cv;

        // Accumulate the value commitment in the context
        self.cv_sum += value_commitment;

        Ok((proof, value_commitment, rk))
    }

    /// Create the value commitment and proof for a Sapling OutputDescription,
    /// while accumulating its value commitment randomness inside the context
    /// for later use.
    pub fn output_proof(
        &mut self,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
        proving_key: &OutputParameters,
        rcv: jubjub::Fr,
    ) -> Result<(Proof<Bls12>, jubjub::ExtendedPoint), ProverError> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // We construct ephemeral randomness for the value commitment. This
        // randomness is not given back to the caller, but the synthetic
        // blinding factor `bsk` is accumulated in the context.
        // let mut buf = [0u8;64];
        //
        // rng.fill_bytes(&mut buf);
        //
        // let rcv = Fr::from_bytes_wide(&buf);
        //
        // Accumulate the value commitment randomness in the context
        {
            let mut tmp = rcv.neg(); // Outputs subtract from the total.
            tmp.add_assign(&self.bsk);

            // Update the context
            self.bsk = tmp;
        }

        // Construct the value commitment for the proof instance
        let trapdoor = ValueCommitTrapdoor::from_bytes(rcv.to_bytes()).unwrap();
        let value_commitment = ValueCommitment::derive(NoteValue::from_raw(value), trapdoor);
        let value_commitment_opening = ValueCommitmentOpening {
            value: NoteValue::from_raw(value),
            randomness: rcv
        };

        // We now have a full witness for the output proof.
        let instance =  OutputParameters::prepare_circuit(
            esk,
            payment_address,
            rcm,
            NoteValue::from_raw(value),
            trapdoor
        );
        // Create proof
        let proof = proving_key.create_proof(instance, &mut rng);

        // Compute the actual value commitment
        let value_commitment: jubjub::ExtendedPoint = value_commitment.as_inner().clone();

        // Accumulate the value commitment in the context. We do this to check internal
        // consistency.
        self.cv_sum -= value_commitment; // Outputs subtract from the total.

        Ok((proof, value_commitment))
    }

    /// Create the bindingSig for a Sapling transaction. All calls to
    /// spend_proof() and output_proof() must be completed before calling
    /// this function.
    pub fn binding_sig (
        &self,
        value_balance: Amount,
        sig_hash: &[u8; 32],
    ) -> Result<Signature<Binding>, ProverError> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // Grab the current `bsk` from the context
        let bsk = SigningKey::new(self.bsk);

        // Grab the `bvk` using DerivePublic.
        let bvk = VerificationKey::<Binding>::from(bsk);

        // In order to check internal consistency, let's use the accumulated value
        // commitments (as the verifier would) and apply value_balance to compare
        // against our derived bvk.
        {
            // Compute value balance
            let value_balance = compute_value_balance_hsm(value_balance).ok_or(ProverError::InvalidBalance)?;

            // Subtract value_balance from cv_sum to get final bvk
            let final_bvk = self.cv_sum - value_balance;

            // The result should be the same, unless the provided valueBalance is wrong.
            if bvk != final_bvk {
                return Err(ProverError::InvalidBalance);
            }
        }

        // Construct signature message
        let mut data_to_be_signed = [0u8; 64];
        data_to_be_signed[0 .. 32].copy_from_slice(&bvk.to_bytes());
        data_to_be_signed[32 .. 64].copy_from_slice(&sig_hash[..]);

        // Sign
        Ok(bsk.sign(&mut rng, &data_to_be_signed))
    }
}

impl Default for SaplingProvingContext {
    fn default() -> Self {
        Self::new()
    }
}
