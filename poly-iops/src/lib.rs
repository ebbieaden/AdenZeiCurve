#![deny(warnings)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::upper_case_acronyms)]

#[macro_use]
extern crate serde_derive;

pub mod commitments;
pub mod ioputils;
pub mod plonk;
pub mod polynomials;
