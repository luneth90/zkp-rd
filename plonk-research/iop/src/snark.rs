use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::SWModelParameters;
use crate::prover::Prover;
use crate::transcript::Transcript;
use crate::transcript::PlonkTranscript;
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::{Commitment, UniversalParams, VerifierKey};
use ark_poly_commit::kzg10::{Powers, KZG10};
use constraint::arithmetization::Arithmetization;
use rand::{CryptoRng, RngCore};
use std::borrow::Cow;
use std::marker::PhantomData;

pub trait Snark<E: PairingEngine> {
    type Srs;

    type Proof;

    type Pk;

    type Vk;

    fn setup<R: RngCore + CryptoRng>(degree: usize, rng: &mut R) -> Self::Srs;

    fn preprocess<A: Arithmetization<E::Fr>>(srs: &Self::Srs, arith: &A) -> (Self::Pk, Self::Vk);

    fn prove<C, R>(circuit: &C, rng: &mut R, pk: &Self::Pk) -> Self::Proof;

    fn verify(vk: &Self::Vk, proof: &Self::Proof, pi: &[E::Fr]) -> bool;
}

#[derive(Default, Clone, Debug, )]
pub struct Challenge<F: Field>{
    pub(crate) tau:F,
    pub(crate) alpha:F,
    pub(crate) beta:F,
    pub(crate) gamma:F,
    pub(crate) zeta:F,
    pub(crate) u:F,
    pub(crate) v:F,
}

#[derive(Default, Clone, Debug, )]
pub struct Oracle<F:Field>{
    pub(crate) wire_polys: Vec<DensePolynomial<F>>,
    pub(crate) pi_poly: DensePolynomial<F>,
    pub(crate) prod_perm_poly: DensePolynomial<F>,
    
}

pub struct Srs<E: PairingEngine>(pub UniversalParams<E>);

pub struct Ck<E: PairingEngine>(pub Vec<E::G1Affine>);

pub struct Pk<E: PairingEngine> {
    identify_perm_polys: Vec<DensePolynomial<E::Fr>>,

    selector_polys: Vec<DensePolynomial<E::Fr>>,

    ck: Ck<E>,

    vk: Vk<E>,
}

#[derive(Clone)]
pub struct Vk<E: PairingEngine> {
    pub(crate) pi_count: usize,

    pub(crate) domain_size: usize,

    pub(crate) identify_perm_commits: Vec<Commitment<E>>,

    pub(crate) selector_commits: Vec<Commitment<E>>,

    vk: VerifierKey<E>,
}

pub struct Proof<E: PairingEngine> {
    wire_poly_commits: Vec<Commitment<E>>,

    prod_perm_poly_commit: Commitment<E>,
}

pub struct BatchProof<E: PairingEngine> {
    wire_poly_commits_vec: Vec<Vec<Commitment<E>>>,

    prod_perm_poly_commit_vec: Vec<Commitment<E>>,
}


pub struct PlonkSnark<E: PairingEngine>(PhantomData<E>);
impl<E,F,P> PlonkSnark<E>
where
    E: PairingEngine<Fq = F,G1Affine = GroupAffine<P>>,
    F: Field,
    P: SWModelParameters<BaseField = F>,
{
    fn generate_ck_and_vk(srs: &UniversalParams<E>, degree: usize) -> (Powers<E>, VerifierKey<E>) 
    {
        let powers_of_g = srs.powers_of_g[..degree].to_vec();
        let powers_of_gamma_g = vec![];

        let powers = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };

        let vk = VerifierKey {
            g: srs.powers_of_g[0],
            gamma_g: E::G1Affine::default(),
            h: srs.h,
            beta_h: srs.beta_h,
            prepared_h: srs.prepared_h.clone(),
            prepared_beta_h: srs.prepared_beta_h.clone(),
        };
        (powers, vk)
    }

    fn batch_prove_iop<C, R,T>(arith: &[&C], rng: R, pk: &[&Pk<E>]) -> (BatchProof<E>, Vec<Oracle<E::Fr>>, Challenge<E::Fr>)
    where
        C: Arithmetization<E::Fr>,
        R: CryptoRng + RngCore,
        T: Transcript<F>,
    {
        let domain_size = arith[0].domain_size();
        let mut transcript = T::new("plonk transcript");
        for (pk,a) in pk.iter().zip(arith.iter()){
            transcript.append_vk_and_pi(&pk.vk,&a.circuit().pi_value());
        }
        let mut challenge = Challenge::default();
        let mut oracles = vec![Oracle::default();arith.len()];
        let prover: Prover<E>= Prover::new(domain_size);

        //round 1
        let mut wire_poly_commits_vec = vec![];
        let mut prod_perm_poly_commit_vec= vec![];
        (BatchProof{ wire_poly_commits_vec, prod_perm_poly_commit_vec},oracles,challenge)

    }
}

impl<E,F,P> Snark<E> for PlonkSnark<E>
where
    E: PairingEngine<Fq = F,G1Affine = GroupAffine<P>>,
    F: Field,
    P: SWModelParameters<BaseField = F>,
{
    type Srs = Srs<E>;

    type Proof = Proof<E>;

    type Pk = Pk<E>;

    type Vk = Vk<E>;

    fn setup<R: RngCore + CryptoRng>(degree: usize, rng: &mut R) -> Self::Srs {
        let srs = KZG10::<E, DensePolynomial<E::Fr>>::setup(degree, false, rng).unwrap();
        Srs(srs)
    }

    fn preprocess<A: Arithmetization<<E as PairingEngine>::Fr>>(
        srs: &Self::Srs,
        arith: &A,
    ) -> (Self::Pk, Self::Vk) {
        let domain_size = arith.domain_size();
        let srs_size = domain_size + 2;
        let pi_count = arith.pi_count();
        let selector_polys = arith.generate_selector_polys();
        let identify_perm_polys = arith.generate_identify_perm_polys();

        let (powers, ok) = PlonkSnark::generate_ck_and_vk(&srs.0, srs_size);
        let selector_commits: Vec<Commitment<E>> = selector_polys
            .iter()
            .map(|poly| {
                let (commit, _) = KZG10::commit(&powers, poly, None, None).unwrap();
                commit
            })
            .collect();
        let identify_perm_commits: Vec<Commitment<E>> = identify_perm_polys
            .iter()
            .map(|poly| {
                let (commit, _) = KZG10::commit(&powers, poly, None, None).unwrap();
                commit
            })
            .collect();
        let vk = Vk {
            pi_count,
            domain_size,
            identify_perm_commits,
            selector_commits,
            vk: ok,
        };
        let ck = Ck(powers.powers_of_g.to_vec());
        let pk = Pk {
            identify_perm_polys,
            selector_polys,
            ck,
            vk: vk.clone(),
        };
        (pk, vk)
    }

    fn prove<C, R>(circuit: &C, rng: &mut R, pk: &Self::Pk) -> Self::Proof {
        Proof {
            wire_poly_commits: todo!(),
            prod_perm_poly_commit: todo!(),
        }
    }

    fn verify(vk: &Self::Vk, proof: &Self::Proof, pi: &[<E as PairingEngine>::Fr]) -> bool {
        true
    }
}
