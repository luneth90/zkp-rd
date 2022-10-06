use crate::circuit::Circuit;
use crate::circuit::PlonkCircuit;
use crate::circuit::WIRE_COUNT;
use ark_ff::{FftField, Field};
use ark_poly::UVPolynomial;
use ark_poly::{domain::Radix2EvaluationDomain, univariate::DensePolynomial, EvaluationDomain};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub trait Arithmetization<F: Field> {
    fn domain_size(&self) -> usize;
    fn pi_count(&self) -> usize;
    fn circuit(&self) -> &dyn Circuit<F>;
    fn generate_pi_poly(&self) -> DensePolynomial<F>;
    fn generate_selector_polys(&self) -> Vec<DensePolynomial<F>>;
    fn generate_wire_polys(&self) -> Vec<DensePolynomial<F>>;
    fn generate_identify_perm_polys(&self) -> Vec<DensePolynomial<F>>;
    fn generate_prod_perm_poly(&self) -> DensePolynomial<F>;
}

pub struct PlonkArithmetization<'a, F: FftField> {
    pub circuit: &'a PlonkCircuit<F>,

    eval_domain: Radix2EvaluationDomain<F>,

    //used to compute copy constraint poly
    //original identify
    encode_identify_orig: Vec<F>,
    //identify after permutation
    encode_identify_perm: Vec<F>,
}

impl<'a, F> PlonkArithmetization<'a, F>
where
    F: FftField,
{
    pub fn new(circuit: &'a PlonkCircuit<F>) -> Self {
        Self {
            circuit,
            eval_domain: Radix2EvaluationDomain::new(circuit.gate_count()).unwrap(),
            encode_identify_orig: vec![],
            encode_identify_perm: vec![],
        }
    }

    pub fn generate_left_coset_repr(&self) -> Vec<F> {
        let sg_order = self.eval_domain.size();
        let mut k_reprs: Vec<F> = vec![];
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        for i in 0..WIRE_COUNT {
            if i == 0 {
                k_reprs.push(F::one());
            } else {
                let mut r_k_repr = F::rand(&mut rng);
                //check r_k_repr must different from other left coset reperset,
                //if left coset aH == bH, then a^-1 * b belongs to H,
                //because H is a cycle subgroup with order r,so (a^-1 * b) ^ r = 1
                while k_reprs.iter().any(|k_repr| {
                    (r_k_repr.inverse().unwrap() * k_repr).pow([sg_order as u64]) == F::one()
                }) {
                    r_k_repr = F::rand(&mut rng);
                }
                k_reprs.push(r_k_repr);
            }
        }
        k_reprs
    }

    pub fn init_encode_identify(&mut self) {
        //Array contains k, represents a left coset(eg.kH,H is a cycle subgroup)
        let k_repr: Vec<F> = self.generate_left_coset_repr();
        let cycle_sg: Vec<F> = self.eval_domain.elements().collect();
        for &g in cycle_sg.iter() {
            for &k in k_repr.iter() {
                self.encode_identify_orig.push(k * g);
            }
        }

        //var array, var_id => [(gate_id,wire_id)...]
        let mut var_vec = vec![vec![]; self.circuit.var_count()];
        //row gate id
        for (gate_id, gate_vars) in self.circuit.var_table.iter().enumerate() {
            //cloumn wire id
            for (wire_id, &wire_var) in gate_vars.iter().enumerate() {
                var_vec[wire_var].push((gate_id, wire_id));
            }
        }
        self.encode_identify_perm = vec![F::zero(); self.circuit.gate_count() * WIRE_COUNT];

        for vars in var_vec.iter_mut() {
            //vars contain same value var with the position(gate_id,wire_id) of var_table
            //push first var to last
            if !vars.is_empty() {
                vars.push(vars[0]);
                for window in vars.windows(2) {
                    self.encode_identify_perm[window[0].0 * WIRE_COUNT + window[0].1] =
                        self.encode_identify_orig[window[1].0 * WIRE_COUNT + window[1].1];
                }
                //pop last var
                vars.pop();
            }
        }
    }
}

impl<'a, F> Arithmetization<F> for PlonkArithmetization<'a, F>
where
    F: FftField,
{
    fn domain_size(&self) -> usize {
        self.eval_domain.size()
    }

    fn pi_count(&self) -> usize {
        self.circuit.pi_count()
    }

    fn circuit(&self) -> &dyn Circuit<F> {
        self.circuit
    }

    fn generate_pi_poly(&self) -> DensePolynomial<F> {
        let evals = self.circuit.pi_value();
        DensePolynomial::from_coefficients_vec(self.eval_domain.ifft(&evals))
    }

    fn generate_selector_polys(&self) -> Vec<DensePolynomial<F>> {
        let selector_polys = vec![];
        selector_polys
    }

    fn generate_wire_polys(&self) -> Vec<DensePolynomial<F>> {
        let mut evals_vec = vec![vec![];WIRE_COUNT];
        for gate in self.circuit.var_table.iter(){
            for i in 0..WIRE_COUNT {
                evals_vec[i].push(self.circuit.witness(gate[i])); 
            }
        }
        let wire_polys = evals_vec.iter().map(|evals|DensePolynomial::from_coefficients_vec(self.eval_domain.ifft(evals))).collect();
        wire_polys
    }

    fn generate_identify_perm_polys(&self) -> Vec<DensePolynomial<F>> {
        let mut identify_perm_polys: Vec<DensePolynomial<F>> = vec![];
        for wire_id in 0..WIRE_COUNT {
            let mut evals = vec![];
            for gate_id in 0..self.circuit.gate_count() {
                evals.push(self.encode_identify_perm[gate_id * WIRE_COUNT + wire_id]);
            }
            // FFT interpolation
            let poly = DensePolynomial::from_coefficients_vec(self.eval_domain.ifft(&evals[..]));
            identify_perm_polys.push(poly);
        }
        identify_perm_polys
    }

    fn generate_prod_perm_poly(&self) -> DensePolynomial<F> {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        let beta = F::rand(&mut rng);
        let gamma = F::rand(&mut rng);
        let mut evals: Vec<F> = vec![];
        let mut eval = F::one();
        for gate_id in 0..self.circuit.gate_count() {
            let mut prod_orig = F::one();
            let mut prod_perm = F::one();

            for wire_id in 0..WIRE_COUNT {
                let var_id = self.circuit.var_table[gate_id][wire_id];
                let val = self.circuit.witness(var_id);
                let identify_orig = self.encode_identify_orig[gate_id * WIRE_COUNT + wire_id];
                prod_orig *= val + beta * identify_orig + gamma;
                let identify_perm = self.encode_identify_perm[gate_id * WIRE_COUNT + wire_id];
                prod_perm *= val + beta * identify_perm + gamma;
            }
            eval *= prod_orig / prod_perm;
            evals.push(eval);
        }
        // FFT interpolation
        let prod_perm_poly =
            DensePolynomial::from_coefficients_vec(self.eval_domain.ifft(&evals));
        prod_perm_poly
    }
}

#[cfg(test)]

pub mod test {
    use crate::arithmetization::PlonkArithmetization;
    use crate::circuit::{Circuit, PlonkCircuit};
    use ark_bls12_381::Fq as Fq381;
    use ark_poly::UVPolynomial;
    use ark_poly::{univariate::DensePolynomial, EvaluationDomain};

    #[test]
    fn test_ifft_usage() {
        let circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let mut arith = PlonkArithmetization::new(&circuit);
        arith.init_encode_identify();
        assert_eq!(arith.circuit.gate_count(), 2);
        let evals = [Fq381::from(5u32), Fq381::from(2u32)];
        let poly = DensePolynomial::from_coefficients_vec(arith.eval_domain.ifft(&evals));
        let poly_evals = poly.evaluate_over_domain(arith.eval_domain);
        assert_eq!(evals[0], poly_evals[0]);
        for (e, pe) in evals.iter().zip(poly_evals.evals.iter()) {
            assert_eq!(e, pe);
        }
    }
}
