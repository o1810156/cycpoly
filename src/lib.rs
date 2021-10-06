#[macro_use]
extern crate anyhow;

use rand::Rng;
use std::cmp::{Eq, PartialEq};
use std::fmt::{self, Display};
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

#[derive(Debug, Clone, Copy)]
pub struct CycleInt3(i64, i64); // i.0 * 1 + i.1 * ζ

impl Display for CycleInt3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let plus = if self.1 >= 0 { "+" } else { "" };
        write!(f, "{}{}{}ζ", self.0, plus, self.1)
    }
}

impl CycleInt3 {
    fn add_(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }

    fn sub_(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }

    // a * 1 + b * ζ + c * ζ^2 = a + bζ + c(-1-ζ) = a-c + (b-c)ζ
    fn mul_(self, rhs: Self) -> Self {
        let a = self.0 * rhs.0;
        let b = self.0 * rhs.1 + self.1 * rhs.0;
        let c = self.1 * rhs.1;
        Self(a - c, b - c)
    }
}

impl PartialEq for CycleInt3 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl Eq for CycleInt3 {}

impl Add for CycleInt3 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.add_(rhs)
    }
}

impl AddAssign for CycleInt3 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_(rhs);
    }
}

impl Sub for CycleInt3 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.sub_(rhs)
    }
}

impl SubAssign for CycleInt3 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_(rhs);
    }
}

impl Mul for CycleInt3 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        self.mul_(rhs)
    }
}

impl MulAssign for CycleInt3 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul_(rhs);
    }
}

impl CycleInt3 {
    pub fn fit(self, mod_: i64) -> Self {
        let a = self.0 % mod_;
        let b = self.1 % mod_;
        let a = if a >= 0 { a } else { a + mod_ };
        let b = if b >= 0 { b } else { b + mod_ };

        Self(a, b)
    }

    pub fn fit_center(self, mod_: i64) -> Self {
        let f = self.fit(mod_);
        let m2 = mod_ / 2;

        let a = if f.0 <= m2 { f.0 } else { f.0 - mod_ };
        let b = if f.1 <= m2 { f.1 } else { f.1 - mod_ };

        CycleInt3(a, b)
    }

    pub fn random_gen<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self(rng.gen(), rng.gen())
    }
}

pub mod hasher {
    use crate::CycleInt3;
    use anyhow::Result;
    use std::convert::TryInto;

    fn make_zs<const M: usize>(message: &[usize]) -> Result<[CycleInt3; M]> {
        message
            .chunks(2)
            .map(|m| {
                if m[0] < 2 && m[1] < 2 {
                    Ok(CycleInt3(m[0] as i64, m[1] as i64))
                } else {
                    Err(anyhow!("Invalid message."))
                }
            })
            .collect::<Result<Vec<CycleInt3>>>()?
            .try_into()
            .map_err(|_| anyhow!("Invalid size"))
    }

    pub fn hash<const M: usize, const P: i64>(
        seed: [CycleInt3; M],
        message: &[usize],
    ) -> Result<CycleInt3> {
        let zs: [CycleInt3; M] = make_zs(message)?;
        let mut sum = CycleInt3(0, 0);
        for i in 0..M {
            sum += seed[i] * zs[i];
        }
        Ok(sum.fit(P))
    }
}

// 準同型暗号
// Homomorphic encryption

pub mod homoenc {
    use crate::CycleInt3;
    use anyhow::Result;
    use rand_distr::{Distribution, Normal};
    use std::cmp::{Eq, PartialEq};

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct SecKey {
        pub s: CycleInt3,
    }
    #[derive(Debug, Clone, Copy)]
    pub struct PubKey {
        pub a: CycleInt3,
        pub b: CycleInt3,
        pub sigma: f64,
    }
    impl PartialEq for PubKey {
        fn eq(&self, other: &Self) -> bool {
            self.a == other.a && self.b == other.b
        }
    }
    impl Eq for PubKey {}
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct Cipher {
        pub c0: CycleInt3,
        pub c1: CycleInt3,
    }

    impl Cipher {
        pub fn add(self, rhs: Self, q: i64) -> Self {
            assert!(q > 0 && q % 2 == 1);

            let c0 = (self.c0 + rhs.c0).fit_center(q);
            let c1 = (self.c1 + rhs.c1).fit_center(q);
            Self { c0, c1 }
        }

        fn get_delta(t: CycleInt3, q: i64) -> CycleInt3 {
            assert!(q > 0 && q % 2 == 1);

            let a = t.0 % q;
            let a = if a % 2 == 0 {
                a
            } else {
                if a > 0 {
                    a - q
                } else {
                    a + q
                }
            };
            let b = t.1 % q;
            let b = if b % 2 == 0 {
                b
            } else {
                if b > 0 {
                    b - q
                } else {
                    b + q
                }
            };

            CycleInt3(a, b)
        }

        pub fn mul(self, rhs: Self, q: i64, q2: i64, a: CycleInt3, b: CycleInt3) -> Self {
            assert!(q > 0 && q % 2 == 1);
            assert!(q2 > 0 && q2 % 2 == 1);

            let d0 = (self.c0 * rhs.c0).fit_center(q);
            let d1 = (self.c1 * rhs.c0 + self.c0 * rhs.c1).fit_center(q);
            let d2 = (CycleInt3(-1, -1) * self.c1 * rhs.c1).fit_center(q);

            let dd0 = (CycleInt3(q2 * d0.0, q2 * d0.1) + b * d2).fit_center(q * q2);
            let dd1 = (CycleInt3(q2 * d1.0, q2 * d1.1) + a * d2).fit_center(q * q2);

            let delta0 = Self::get_delta(dd0, q2);
            let ddd0 = dd0 - delta0;
            let c0 = CycleInt3(ddd0.0 / q2, ddd0.1 / q2).fit_center(q);

            let delta1 = Self::get_delta(dd1, q2);
            let ddd1 = dd1 - delta1;
            let c1 = CycleInt3(ddd1.0 / q2, ddd1.1 / q2).fit_center(q);

            Cipher { c0, c1 }
        }

        pub fn prepare_boost_b(
            p: i64,
            qp: i64,
            s: CycleInt3,
            a: CycleInt3,
            e2: CycleInt3,
        ) -> CycleInt3 {
            let s2 = s * s;
            let ps2 = CycleInt3(s2.0 * p, s2.1 * p);
            let b = (a * s - ps2 + e2).fit_center(qp);

            b
        }
    }

    pub fn keygen(q: i64, sigma: f64) -> Result<(SecKey, PubKey)> {
        if q <= 0 || q % 2 != 1 {
            return Err(anyhow!("Invalid q: {}", q));
        }

        let mut rng = rand::thread_rng();
        let s = CycleInt3::random_gen(&mut rng).fit(2);
        let a = CycleInt3::random_gen(&mut rng).fit_center(q);
        let normal = Normal::new(0f64, sigma)?;
        let (ec0, ec1) = (
            normal.sample(&mut rng).round() as i64,
            normal.sample(&mut rng).round() as i64,
        );
        let e2 = CycleInt3(2 * ec0, 2 * ec1);

        keygen_sub(q, s, a, e2, sigma)
    }

    pub fn keygen_sub(
        q: i64,
        s: CycleInt3,
        a: CycleInt3,
        e2: CycleInt3,
        sigma: f64,
    ) -> Result<(SecKey, PubKey)> {
        let b = (a * s + e2).fit_center(q);

        Ok((SecKey { s }, PubKey { a, b, sigma }))
    }

    pub fn enc(q: i64, p: PubKey, message: &[usize]) -> Result<Cipher> {
        if q <= 0 || q % 2 != 1 {
            return Err(anyhow!("Invalid q: {}", q));
        }

        if message.len() != 2 {
            return Err(anyhow!("Invalid message: size {}", message.len()));
        }

        for &m in message {
            if m >= 2 {
                return Err(anyhow!("Invalid message: include not binary item {}", m));
            }
        }

        let mut rng = rand::thread_rng();
        let m = CycleInt3(message[0] as i64, message[1] as i64);
        let v = CycleInt3::random_gen(&mut rng).fit(2);
        let normal = Normal::new(0f64, p.sigma)?;
        let (ec0, ec1) = (
            normal.sample(&mut rng).round() as i64,
            normal.sample(&mut rng).round() as i64,
        );
        let e0 = CycleInt3(2 * ec0, 2 * ec1);
        let (ec0, ec1) = (
            normal.sample(&mut rng).round() as i64,
            normal.sample(&mut rng).round() as i64,
        );
        let e1 = CycleInt3(2 * ec0, 2 * ec1);

        let c0 = (p.b * v + e0 + m).fit_center(q);
        let c1 = (p.a * v + e1).fit_center(q);

        Ok(Cipher { c0, c1 })
    }

    pub fn dec(q: i64, s: SecKey, c: Cipher) -> Result<[usize; 2]> {
        if q <= 0 || q % 2 != 1 {
            return Err(anyhow!("Invalid q: {}", q));
        }

        let m = (c.c0 - s.s * c.c1).fit_center(q).fit(2);

        Ok([m.0 as usize, m.1 as usize])
    }
}

#[cfg(test)]
mod tests {
    use crate::CycleInt3 as C;
    use crate::*;

    #[test]
    fn cycleint3_test() {
        let a = C(2, 5);
        let b = C(1, -7);
        assert_eq!(a + b, C(3, -2));
        assert_eq!(a * b, C(37, 26));
    }

    #[test]
    fn hash_test() {
        let seed: [C; 6] = [C(2, 3), C(4, 1), C(1, 3), C(1, 0), C(3, 2), C(2, 2)];
        let message: [usize; 12] = [0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1];
        let res = hasher::hash::<6, 5>(seed, &message).unwrap();

        assert_eq!(C(0, 4), res);
    }

    #[test]
    fn homo_test() {
        let q = 65;
        let sigma = 2f64;
        let s = C(1, 1);
        let a = C(-19, -8);
        let e2 = C(2, -2);
        let (sk, pk) = homoenc::keygen_sub(q, s, a, e2, sigma).unwrap();

        assert_eq!(sk, homoenc::SecKey { s: C(1, 1) });
        assert_eq!(
            pk,
            homoenc::PubKey {
                a: C(-19, -8),
                b: C(-9, -21),
                sigma: 2f64,
            }
        );
        assert_eq!((pk.b - pk.a * sk.s).fit_center(q), C(2, -2));

        let message: [usize; 2] = [1, 1];

        let c = homoenc::enc(q, pk, &message).unwrap();
        let r = homoenc::dec(q, sk, c).unwrap();

        assert_eq!(r, message);
    }

    #[test]
    fn homo_test2() {
        let q = 65;
        let sigma = 2f64;
        let s = C(1, 1);
        let a = C(-19, -8);
        let e2 = C(2, -2);
        let (sk, pk) = homoenc::keygen_sub(q, s, a, e2, sigma).unwrap();

        let message0: [usize; 2] = [1, 1];

        let c0 = homoenc::enc(q, pk, &message0).unwrap();
        let r0 = homoenc::dec(q, sk, c0).unwrap();

        assert_eq!(r0, message0);

        let message1: [usize; 2] = [0, 1];

        let c1 = homoenc::enc(q, pk, &message1).unwrap();
        let r1 = homoenc::dec(q, sk, c1).unwrap();

        assert_eq!(r1, message1);

        let cc = c0.add(c1, q);
        let rr = homoenc::dec(q, sk, cc).unwrap();

        assert_eq!(rr, [1, 0]);
    }

    #[test]
    fn homo_test3() {
        let q = 65;
        let sigma = 2f64;
        let s = C(1, 1);
        let a = C(-19, -8);
        let e2 = C(2, -2);
        let (sk, pk) = homoenc::keygen_sub(q, s, a, e2, sigma).unwrap();

        let message0: [usize; 2] = [1, 1];

        let c0 = homoenc::enc(q, pk, &message0).unwrap();
        let r0 = homoenc::dec(q, sk, c0).unwrap();

        assert_eq!(r0, message0);

        let message1: [usize; 2] = [0, 1];

        let c1 = homoenc::enc(q, pk, &message1).unwrap();
        let r1 = homoenc::dec(q, sk, c1).unwrap();

        assert_eq!(r1, message1);

        let q2 = 67;
        let a2 = C(2116, 1119);
        let e22 = C(2, -2);
        let b2 = homoenc::Cipher::prepare_boost_b(q2, q * q2, s, a2, e22);

        assert_eq!(b2, C(999, 2047));

        let cc = c0.mul(c1, q, q2, a2, b2);
        let rr = homoenc::dec(q, sk, cc).unwrap();

        assert_eq!(rr, [1, 0]);
    }
}
