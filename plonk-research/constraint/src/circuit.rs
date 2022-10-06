use std::vec;

pub(crate) use crate::gate::arithmetic::*;
use crate::gate::*;
use ark_ff::Field;

pub type VarId = usize;
pub type GateId = usize;
pub type WireId = usize;

//Ultra plonk circuit has six wires
pub const WIRE_COUNT: usize = 6;
pub const INPUT1: usize = 0;
pub const INPUT2: usize = 1;
pub const INPUT3: usize = 2;
pub const INPUT4: usize = 3;
//The wire includes general output, constant, public input var
pub const OUTPUT: usize = 4;
pub const CUSTOM: usize = 5;

pub trait Circuit<F: Field> {
    fn var_count(&self) -> usize;

    fn gate_count(&self) -> usize;

    fn pi_count(&self) -> usize;

    fn pi_value(&self) -> Vec<F>;

    fn create_var(&mut self, val: F, is_pi: bool) -> VarId;

    fn witness(&self, id: VarId) -> F;

    fn check_circuit(&self, pi: &[F]) -> bool;

    fn add(&mut self, a: VarId, b: VarId) -> VarId;

    fn add_gate(&mut self, a: VarId, b: VarId, c: VarId);

    fn sub(&mut self, a: VarId, b: VarId) -> VarId;

    fn sub_gate(&mut self, a: VarId, b: VarId, c: VarId);

    fn mul(&mut self, a: VarId, b: VarId) -> VarId;

    fn mul_gate(&mut self, a: VarId, b: VarId, c: VarId);

    fn equal_gate(&mut self, a: VarId, b: VarId);

    fn const_gate(&mut self, a: VarId, val: F);

    fn pi_gate(&mut self, a: VarId);
}

pub struct PlonkCircuit<F: Field> {
    var_count: usize,

    witness: Vec<F>,

    pi_vars: Vec<VarId>,

    gates: Vec<Box<dyn Gate<F>>>,

    pi_gates: Vec<GateId>,

    //All vars store as a table, row is GateId, cloumn is WireId
    //Each row is a gate constraint
    pub(crate) var_table: Vec<[VarId; WIRE_COUNT]>,
}

impl<F> PlonkCircuit<F>
where
    F: Field,
{
    pub fn new() -> Self {
        let mut circuit = Self {
            var_count: 0,
            witness: vec![],
            pi_vars: vec![],
            pi_gates: vec![],
            gates: vec![],
            var_table: vec![],
        };
        let zero = circuit.create_var(F::zero(), false);
        let one = circuit.create_var(F::one(), false);
        circuit.const_gate(zero, F::zero());
        circuit.const_gate(one, F::one());
        circuit
    }
    fn create_gate(&mut self, gate_var: &[VarId; WIRE_COUNT], gate: Box<dyn Gate<F>>) {
        self.var_table.push(*gate_var);
        self.gates.push(gate);
    }

    fn check_gate(&self, id: GateId, pi: F) -> bool {
        let gate_val: Vec<F> = self.var_table[id]
            .iter()
            .map(|var| self.witness(*var))
            .collect();
        let q_lc = self.gates[id].q_lc();
        let q_mul = self.gates[id].q_mul();
        let q_o = self.gates[id].q_o();
        let q_c = self.gates[id].q_c();
        let output = pi
            + q_lc[INPUT1] * gate_val[INPUT1]
            + q_lc[INPUT2] * gate_val[INPUT2]
            + q_lc[INPUT3] * gate_val[INPUT3]
            + q_lc[INPUT4] * gate_val[INPUT4]
            + q_mul[INPUT1] * gate_val[INPUT1] * gate_val[INPUT2]
            + q_mul[INPUT2] * gate_val[INPUT3] * gate_val[INPUT4]
            + q_c;
        output == q_o * gate_val[OUTPUT]
    }

    fn is_pi_gate(&self, id: GateId) -> bool {
        self.gates[id].as_any().is::<PIGate>()
    }
}

impl<F> Circuit<F> for PlonkCircuit<F>
where
    F: Field,
{
    fn var_count(&self) -> usize {
        self.var_count
    }

    fn gate_count(&self) -> usize {
        self.gates.len()
    }

    fn pi_count(&self) -> usize {
        self.pi_vars.len()
    }

    fn pi_value(&self) -> Vec<F> {
        self.pi_vars.iter().map(|&id|self.witness(id)).collect()
    }

    fn witness(&self, id: VarId) -> F {
        self.witness[id]
    }

    fn create_var(&mut self, val: F, is_pi: bool) -> VarId {
        self.witness.push(val);
        let var_id = self.var_count;
        self.var_count += 1;
        if is_pi {
            self.pi_vars.push(var_id);
            self.pi_gate(var_id);
            let gate_id = self.gate_count() - 1;
            self.pi_gates.push(gate_id);
        }
        var_id
    }

    fn add_gate(&mut self, a: VarId, b: VarId, c: VarId) {
        let gate_var = &[a, b, 0, 0, c, 0];
        self.create_gate(gate_var, Box::new(AddGate));
    }

    fn add(&mut self, a: VarId, b: VarId) -> VarId {
        let val = self.witness(a) + self.witness(b);
        let c = self.create_var(val, false);
        self.add_gate(a, b, c);
        c
    }

    fn equal_gate(&mut self, a: VarId, b: VarId) {
        let gate_var = &[a, b, 0, 0, 0, 0];
        self.create_gate(gate_var, Box::new(EqualGate));
    }

    fn sub_gate(&mut self, a: VarId, b: VarId, c: VarId) {
        let gate_var = &[a, b, 0, 0, c, 0];
        self.create_gate(gate_var, Box::new(SubGate));
    }

    fn sub(&mut self, a: VarId, b: VarId) -> VarId {
        let val = self.witness(a) - self.witness(b);
        let c = self.create_var(val, false);
        self.sub_gate(a, b, c);
        c
    }

    fn mul_gate(&mut self, a: VarId, b: VarId, c: VarId) {
        let gate_var = &[a, b, 0, 0, c, 0];
        self.create_gate(gate_var, Box::new(MulGate));
    }

    fn mul(&mut self, a: VarId, b: VarId) -> VarId {
        let val = self.witness(a) * self.witness(b);
        let c = self.create_var(val, false);
        self.mul_gate(a, b, c);
        c
    }

    fn const_gate(&mut self, a: VarId, val: F) {
        let gate_var = &[0, 0, 0, 0, a, 0];
        self.create_gate(gate_var, Box::new(ConstGate(val)));
    }

    fn pi_gate(&mut self, a: VarId) {
        let gate_var = &[0, 0, 0, 0, a, 0];
        self.create_gate(gate_var, Box::new(PIGate));
    }

    fn check_circuit(&self, pub_input: &[F]) -> bool {
        //check public input gate
        for (index, id) in self.pi_gates.iter().enumerate() {
            let pi = pub_input[index];
            if !self.check_gate(*id, pi) {
                return false;
            }
        }
        //check other gate
        for id in 0..self.gate_count() {
            if !self.is_pi_gate(id) {
                if !self.check_gate(id, F::zero()) {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]

pub mod test {
    use crate::circuit::*;
    use ark_bls12_381::Fq as Fq381;

    #[test]
    fn test_add_gate() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let a = circuit.create_var(Fq381::from(2u32), false);
        let b = circuit.create_var(Fq381::from(3u32), false);
        let c = circuit.create_var(Fq381::from(5u32), false);
        circuit.add_gate(a, b, c);
        assert!(circuit.check_circuit(&[]));
    }
    #[test]
    fn test_sub_gate() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let a = circuit.create_var(Fq381::from(3u32), false);
        let b = circuit.create_var(Fq381::from(2u32), false);
        let c = circuit.create_var(Fq381::from(1u32), false);
        circuit.sub_gate(a, b, c);
        assert!(circuit.check_circuit(&[]));
    }
    #[test]
    fn test_mul_gate() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let a = circuit.create_var(Fq381::from(2u32), false);
        let b = circuit.create_var(Fq381::from(3u32), false);
        let c = circuit.create_var(Fq381::from(6u32), false);
        circuit.mul_gate(a, b, c);
        assert!(circuit.check_circuit(&[]));
    }
    #[test]
    fn test_equal_gate() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let a = circuit.create_var(Fq381::from(6u32), false);
        let b = circuit.create_var(Fq381::from(6u32), false);
        circuit.equal_gate(a, b);
        assert!(circuit.check_circuit(&[]));
    }
    #[test]
    fn test_const_gate() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let val = Fq381::from(3u32);
        let a = circuit.create_var(val, false);
        circuit.const_gate(a, val);
        assert!(circuit.check_circuit(&[]));
    }
    #[test]
    fn test_pi_gate() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let val = Fq381::from(3u32);
        circuit.create_var(val, true);
        assert!(circuit.check_circuit(&[val]));
    }

    #[test]
    fn test_add() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let a = circuit.create_var(Fq381::from(6u32), false);
        let b = circuit.create_var(Fq381::from(6u32), false);
        circuit.add(a, b);
        assert!(circuit.check_circuit(&[]));
    }
    #[test]
    fn test_sub() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let a = circuit.create_var(Fq381::from(6u32), false);
        let b = circuit.create_var(Fq381::from(2u32), false);
        circuit.sub(a, b);
        assert!(circuit.check_circuit(&[]));
    }
    #[test]
    fn test_mul() {
        let mut circuit: PlonkCircuit<Fq381> = PlonkCircuit::new();
        let a = circuit.create_var(Fq381::from(6u32), false);
        let b = circuit.create_var(Fq381::from(6u32), false);
        circuit.mul(a, b);
        assert!(circuit.check_circuit(&[]));
    }
}
