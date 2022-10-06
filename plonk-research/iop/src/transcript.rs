use crate::prover::ProofEvaluations;
use crate::snark::Vk;
use crate::to_bytes;
use ark_ec::{short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters};
use ark_ff::PrimeField;
use ark_poly_commit::kzg10::Commitment;
use merlin::Transcript as Script;

pub trait Transcript<F> {
    fn new(label: &'static str) -> Self;

    fn append_message(&mut self, label: &'static str, msg: &[u8]);

    fn append_vk_and_pi<E, P>(&mut self, vk: &Vk<E>, pi: &[E::Fr])
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWModelParameters<BaseField = F>,
    {
        self.append_message("field order", E::Fr::size_in_bits().to_le_bytes().as_ref());
        self.append_message("domain size", vk.domain_size.to_le_bytes().as_ref());
        self.append_message("input size", vk.pi_count.to_le_bytes().as_ref());
        for ipc in vk.identify_perm_commits.iter() {
            self.append_message("identify permutation commitments", &to_bytes!(ipc).unwrap());
        }

        for sc in vk.selector_commits.iter() {
            self.append_message("selector commitments", &to_bytes!(sc).unwrap());
        }

        for _pi in pi.iter() {
            self.append_message("public input", &to_bytes!(_pi).unwrap());
        }
    }

    fn append_commitments<E, P>(&mut self, label: &'static str, commits: &[Commitment<E>])
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWModelParameters<BaseField = F>,
    {
        for commit in commits.iter() {
            self.append_commitment(label, commit);
        }
    }

    fn append_commitment<E, P>(&mut self, label: &'static str, commit: &Commitment<E>)
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWModelParameters<BaseField = F>,
    {
        self.append_message(label, &to_bytes!(commit).unwrap());
    }

    fn append_proof_eval<E: PairingEngine>(&mut self, evals: &ProofEvaluations<E::Fr>) {
        for we in &evals.wire_evals {
            self.append_message("wire evaluations", &to_bytes!(we).unwrap())
        }
        for ipe in &evals.identify_perm_evals {
            self.append_message(
                "indentify permutation evaluations",
                &to_bytes!(ipe).unwrap(),
            )
        }
    }

    fn append_challenge<E>(&mut self, label: &'static str, challenge: &E::Fr)
    where
        E: PairingEngine<Fq = F>,
    {
        self.append_message(label, &to_bytes!(challenge).unwrap());
    }

    fn get_challenge<E>(&mut self, label: &'static str)
    where
        E: PairingEngine;
}

pub struct PlonkTranscript(Script);

impl<F> Transcript<F> for PlonkTranscript {
    fn new(label: &'static str) -> Self {
        Self(Script::new(label.as_bytes()))
    }

    fn append_message(&mut self, label: &'static str, msg: &[u8]) {
        self.0.append_message(label.as_bytes(), msg);
    }

    fn get_challenge<E>(&mut self, label: &'static str)
    where
        E: PairingEngine,
    {
        let mut buf = [0u8; 64];
        self.0.challenge_bytes(label.as_bytes(), &mut buf);
        let challenge = E::Fr::from_le_bytes_mod_order(&buf);
        self.0
            .append_message(label.as_bytes(), &to_bytes!(&challenge).unwrap());
    }
}
