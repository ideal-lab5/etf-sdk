use sha2::Digest;

use ark_ff::{Field, PrimeField, Zero, One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::{AffineRepr, CurveGroup};
use ark_bls12_381::{Fr, G1Affine};
use ark_std::vec::Vec;

use alloc::borrow::ToOwned;

use w3f_bls::EngineBLS;

/// sha256 hasher
pub fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b);
    hasher.finalize().to_vec()
}

// TODO: can do this in place instead
pub fn cross_product_32(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut o = a.to_owned();
    for (i, ri) in o.iter_mut().enumerate().take(32) {
        *ri ^= b[i];
    }
    o.to_vec()
}

pub fn cross_product<const N: usize>(a: &[u8;N], b: &[u8;N]) -> [u8;N] {
    let mut o = a.to_owned();
    for (i, ri) in o.iter_mut().enumerate().take(N) {
        *ri ^= b[i];
    }
    o
}

/// {0, 1}^* -> G1
pub fn hash_to_g1(b: &[u8]) -> G1Affine {
    let mut nonce = 0u32;
    loop {
        let c = [b, &nonce.to_be_bytes()].concat();
        match G1Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => {
                return v.mul_by_cofactor_to_group().into_affine();
            }
            None => nonce += 1,
        }
    }
}

/// a map from G -> {0, 1}^{32}
pub fn h2<G: CanonicalSerialize>(g: G) -> Vec<u8> {
    // let mut out = Vec::with_capacity(g.compressed_size());
    let mut out = Vec::new();
    // TODO: handle error => return empty
    // else return [u8;32] 
    g.serialize_compressed(&mut out).unwrap();
    sha256(&out)
}

// Q: Should add add a const to the signature so I can enforce sized inputs?
// right now this works with any size slices
/// H_3: {0,1}^n x {0, 1}^m -> Z_p
pub fn h3(a: & [u8], b: &[u8]) -> Fr {
    let mut input = Vec::new();
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    let hash = sha256(&input);
    Fr::from_be_bytes_mod_order(&hash)
}


// Should add a const to the signature so I can enforce sized inputs?
// right now this works with any size slices
/// H_3: {0,1}^n x {0, 1}^m -> Z_p
pub fn h3_new<E: EngineBLS>(a: & [u8], b: &[u8]) 
    -> E::Scalar {
    let mut input = Vec::new();
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    let hash = sha256(&input);
    E::Scalar::from_be_bytes_mod_order(&hash)
}

/// H_4: {0, 1}^n -> {0, 1}^n
pub fn h4(a: &[u8]) -> Vec<u8> {
    let o = sha256(a);
    o[..a.len()].to_vec()
}

// TODO: proper error handling
/// a helper function to deserialize arkworks elements from bytes
pub fn convert_from_bytes<E: CanonicalDeserialize, const N: usize>(
    bytes: &[u8; N],
) -> Option<E> {
	E::deserialize_compressed(&bytes[..]).ok()
}

// should it be an error instead?
/// a helper function to serialize arkworks elements to bytes
pub fn convert_to_bytes<E: CanonicalSerialize, const N: usize>(k: E) -> [u8;N] {
	let mut out = Vec::with_capacity(k.compressed_size());
	k.serialize_compressed(&mut out).unwrap_or(());
	let o: [u8; N] = out.try_into().unwrap_or([0;N]);
	o
}

/// interpolate a polynomial from the input and evaluate it at 0
/// P(X) = sum_{i = 0} ^n y_i * (\prod_{j=0}^n [j != i] (x-xj/xi - xj))
///
/// * `evalulation`: a vec of (x, f(x)) pairs
///
pub fn interpolate<C: CurveGroup>(
    points: Vec<(C::ScalarField, C::ScalarField)>
) -> C::ScalarField {
    let n = points.len();
    // Calculate the Lagrange basis polynomials evaluated at 0
    let mut lagrange_at_zero: Vec<C::ScalarField> = Vec::with_capacity(n);
    for i in 0..n {
        // build \prod_{j=0}^n [j != i] (x-xj/xi - xj)
        let mut basis_value = C::ScalarField::one();
        for j in 0..n {
            if j != i {
                let denominator = points[i].0 - points[j].0;
                // Check if the denominator is zero before taking the inverse
                if denominator.is_zero() {
                    // Handle the case when the denominator is zero (or very close to zero)
                    return C::ScalarField::zero();
                }
                let numerator = C::ScalarField::zero() - points[j].0;
                // Use the precomputed inverse
                basis_value *= numerator * denominator.inverse().unwrap();
            }
        }
        lagrange_at_zero.push(basis_value);
    }

    // Interpolate the value at 0
    // compute  sum_{i = 0} ^n (y_i * sum... )
    let mut interpolated_value = C::ScalarField::zero();
    for i in 0..n {
        interpolated_value += points[i].1 * lagrange_at_zero[i];
    }

    interpolated_value
}

#[cfg(test)]
mod test {
    
    #[test]
    fn utils_can_calc_sha256() {
        let actual = crate::utils::sha256(b"test");
        let expected = vec![159, 134, 208, 129, 136, 76, 125, 101, 154, 47, 234, 160, 197, 90, 208, 21, 163, 191, 79, 27, 43, 11, 130, 44, 209, 93, 108, 21, 176, 240, 10, 8];
        assert_eq!(actual, expected);
    }
}
