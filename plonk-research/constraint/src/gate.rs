use ark_ff::Field;
use downcast_rs::Downcast;

pub mod arithmetic;

pub const INPUT_COUNT: usize = 4;

pub const MUL_SELECTOR_COUNT: usize = 2;

pub trait Gate<F: Field>: Downcast {
    fn name(&self) -> &str;

    fn q_lc(&self) -> [F; INPUT_COUNT] {
        [F::zero(); INPUT_COUNT]
    }

    fn q_mul(&self) -> [F; MUL_SELECTOR_COUNT] {
        [F::zero(); MUL_SELECTOR_COUNT]
    }

    fn q_o(&self) -> F {
        F::zero()
    }

    fn q_c(&self) -> F {
        F::zero()
    }
}
