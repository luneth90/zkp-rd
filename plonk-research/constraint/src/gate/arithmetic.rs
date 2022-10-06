pub use crate::gate::*;
use ark_ff::Field;

pub struct AddGate;

impl<F> Gate<F> for AddGate
where
    F: Field,
{
    fn name(&self) -> &str {
        "Addition Gate"
    }

    fn q_o(&self) -> F {
        F::one()
    }

    fn q_lc(&self) -> [F; INPUT_COUNT] {
        [F::one(), F::one(), F::zero(), F::zero()]
    }
}

pub struct PIGate;

impl<F> Gate<F> for PIGate
where
    F: Field,
{
    fn name(&self) -> &str {
        "IO Gate"
    }

    fn q_o(&self) -> F {
        F::one()
    }
}
pub struct ConstGate<F: Field>(pub F);

impl<F> Gate<F> for ConstGate<F>
where
    F: Field,
{
    fn name(&self) -> &str {
        "Constant Gate"
    }

    fn q_c(&self) -> F {
        self.0
    }

    fn q_o(&self) -> F {
        F::one()
    }
}
pub struct EqualGate;

impl<F> Gate<F> for EqualGate
where
    F: Field,
{
    fn name(&self) -> &str {
        "Equal Gate"
    }

    fn q_lc(&self) -> [F; INPUT_COUNT] {
        [F::one(), -F::one(), F::zero(), F::zero()]
    }

    fn q_o(&self) -> F {
        F::one()
    }
}
pub struct MulGate;

impl<F> Gate<F> for MulGate
where
    F: Field,
{
    fn name(&self) -> &str {
        "Mul Gate"
    }

    fn q_mul(&self) -> [F; MUL_SELECTOR_COUNT] {
        [F::one(), F::zero()]
    }

    fn q_o(&self) -> F {
        F::one()
    }
}
pub struct SubGate;

impl<F> Gate<F> for SubGate
where
    F: Field,
{
    fn name(&self) -> &str {
        "Sub Gate"
    }

    fn q_lc(&self) -> [F; INPUT_COUNT] {
        [F::one(), -F::one(), F::zero(), F::zero()]
    }

    fn q_o(&self) -> F {
        F::one()
    }
}
