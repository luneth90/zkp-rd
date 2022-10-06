use std::borrow::Cow;
use ark_poly_commit::kzg10::Commitment;
use rand::RngCore;
use rand::CryptoRng;
use constraint::arithmetization::Arithmetization;
use crate::snark::Ck;
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{Radix2EvaluationDomain, EvaluationDomain};
use ark_poly_commit::kzg10::{Powers, KZG10};

pub struct Prover<E: PairingEngine> {
    domain: Radix2EvaluationDomain<E::Fr>,
}

pub struct ProofEvaluations<F: Field> {
    pub(crate) wire_evals: Vec<F>,
    pub(crate) identify_perm_evals: Vec<F>,
}

impl<E> Prover<E>
where E: PairingEngine,
{
    pub(crate) fn new(domain_size: usize) -> Self {
        let domain = Radix2EvaluationDomain::<E::Fr>::new(domain_size).unwrap(); 
        Self{domain}
    }

    fn commit_polynomials(ck: &Ck<E>, polys: &[DensePolynomial<E::Fr>]) -> Vec<Commitment<E>>{

        let mut commits = vec![];
        for poly in polys.iter(){
            commits.push(Self::commit_polynomial(ck, poly));
        }
        commits
    }

    fn commit_polynomial(ck: &Ck<E>, poly: &DensePolynomial<E::Fr>) -> Commitment<E>{
        let powers = Powers {
            powers_of_g: Cow::Owned(ck.0.clone()),
            powers_of_gamma_g: Cow::Owned(vec![]),
        };
        let (commit,_) = KZG10::commit(&powers, poly, None, None).unwrap();
        commit
    }

    pub(crate) fn round1<A: Arithmetization<E::Fr>, R: CryptoRng + RngCore>(&self,rng: &R, ck: &Ck<E>, a: &A) -> (Vec<Commitment<E>>, Vec<DensePolynomial<E::Fr>>,DensePolynomial<E::Fr>){

        let wire_polys = a.generate_wire_polys();
        let wire_poly_commits = Self::commit_polynomials(&ck,&wire_polys);
        todo!()


    }

}
