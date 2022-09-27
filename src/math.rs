use auto_ops::{impl_op_ex, impl_op_ex_commutative};
use std::ops::Index;

use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

/// Represents a polynomial with coefficients in the scalar field of the curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    /// The coefficients of our polynomial, from 0..size-1.
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Generate a random polynomial with a certain number of coefficients.
    pub fn random(rng: &mut impl CryptoRngCore, size: usize) -> Self {
        let coefficients = (0..size)
            .map(|_| Scalar::generate_biased(&mut *rng))
            .collect();
        Self { coefficients }
    }

    /// Extend a constant to a random polynomial of a certain size.
    ///
    /// This is useful if you want the polynomial to have a certain value, but
    /// otherwise be random.
    pub fn extend_random(rng: &mut impl CryptoRngCore, size: usize, constant: &Scalar) -> Self {
        let mut coefficients = Vec::with_capacity(size);
        coefficients.push(*constant);
        for _ in 1..size {
            coefficients.push(Scalar::generate_biased(&mut *rng));
        }
        Self { coefficients }
    }

    /// Modify this polynomial by adding another polynomial.
    pub fn add_mut(&mut self, other: &Self) {
        let new_len = self.coefficients.len().max(other.coefficients.len());
        self.coefficients.resize(new_len, Scalar::ZERO);
        self.coefficients
            .iter_mut()
            .zip(other.coefficients.iter())
            .for_each(|(a, b)| *a += b);
    }

    /// Return the addition of this polynomial with another.
    pub fn add(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.add_mut(other);
        out
    }

    /// Scale this polynomial in place by a field element.
    pub fn scale_mut(&mut self, scale: &Scalar) {
        self.coefficients.iter_mut().for_each(|a| *a *= scale);
    }

    /// Return the result of scaling this polynomial by a field element.
    pub fn scale(&self, scale: &Scalar) -> Self {
        let mut out = self.clone();
        out.scale_mut(scale);
        out
    }

    /// Evaluate this polynomial at a specific point.
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        let mut out = Scalar::ZERO;
        for c in self.coefficients.iter().rev() {
            out = out * x + c;
        }
        out
    }

    /// Evaluate this polynomial at several points.
    pub fn evaluate_many(&self, xs: &[Scalar]) -> EvaluationTable {
        let evaluations = xs.iter().map(|x| self.evaluate(x)).collect();
        EvaluationTable { evaluations }
    }
}

impl Index<usize> for Polynomial {
    type Output = Scalar;

    fn index(&self, i: usize) -> &Self::Output {
        &self.coefficients[i]
    }
}

impl_op_ex!(+ |f: &Polynomial, g: &Polynomial| -> Polynomial { f.add(g) });
impl_op_ex!(+= |f: &mut Polynomial, g: &Polynomial| { f.add_mut(g) });
impl_op_ex_commutative!(*|f: &Polynomial, s: &Scalar| -> Polynomial { f.scale(s) });
impl_op_ex!(*= |f: &mut Polynomial, s: &Scalar| { f.scale_mut(s) });

/// Represents the evaluation of a polynomial at certain points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationTable {
    pub evaluations: Vec<Scalar>,
}

impl EvaluationTable {
    pub fn commit(&self) -> EvaluationCommitment {
        let evaluations = self
            .evaluations
            .iter()
            .map(|x| AffinePoint::GENERATOR * x)
            .collect();
        EvaluationCommitment { evaluations }
    }
}

/// Represents a commitment to the evaluations of a polynomial at certain points.
///
/// This is basically an evaluation table, except that each evaluation is multiplied
/// by the generator of the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationCommitment {
    pub evaluations: Vec<ProjectivePoint>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_addition() {
        let mut f = Polynomial {
            coefficients: vec![Scalar::from(1u32), Scalar::from(2u32)],
        };
        let g = Polynomial {
            coefficients: vec![Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)],
        };
        let h = Polynomial {
            coefficients: vec![Scalar::from(2u32), Scalar::from(4u32), Scalar::from(3u32)],
        };
        assert_eq!(&f + &g, h);
        f += &g;
        assert_eq!(f, h);
    }

    #[test]
    fn test_scaling() {
        let s = Scalar::from(2u32);
        let mut f = Polynomial {
            coefficients: vec![Scalar::from(1u32), Scalar::from(2u32)],
        };
        let h = Polynomial {
            coefficients: vec![Scalar::from(2u32), Scalar::from(4u32)],
        };
        assert_eq!(s * &f, h);
        f *= s;
        assert_eq!(f, h);
    }

    #[test]
    fn test_evaluation() {
        let f = Polynomial {
            coefficients: vec![Scalar::from(1u32), Scalar::from(2u32)],
        };
        assert_eq!(f.evaluate(&Scalar::from(1u32)), Scalar::from(3u32));
        assert_eq!(f.evaluate(&Scalar::from(2u32)), Scalar::from(5u32));
    }
}
