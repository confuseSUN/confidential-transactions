use super::{BlindPair, KeyPair};
use ct_utils::hash::Hasher;
use ct_utils::{bytes_to_scalar, generator::BASEPOINT_G2, get_random_scalar, point_to_bytes};
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

#[derive(Debug, Clone)]
pub struct Account(pub KeyPair);

impl Account {
    pub fn get_public_key(&self) -> RistrettoPoint {
        self.0.public_key
    }

    pub fn get_private_key(&self) -> Scalar {
        self.0.private_key
    }

    pub fn new() -> Account {
        let private_key = get_random_scalar();
        let public_key = RistrettoPoint::multiscalar_mul(&[private_key], &[*BASEPOINT_G2]);

        Account(KeyPair {
            private_key,
            public_key,
        })
    }

    pub fn to_address(&self) -> Vec<u8> {
        let pubkey_bytes = point_to_bytes(&self.get_public_key());
        Hasher::sha_256(&pubkey_bytes)
    }

    //genetator one_time_account,and the ECDH algorithm is used to generate symmetric key
    pub fn gen_one_time_account(&self) -> (OneTimeAccount, BlindPair, Vec<u8>) {
        let r = get_random_scalar();
        let r_point = RistrettoPoint::multiscalar_mul(&[r], &[*BASEPOINT_G2]);

        let one_time_account = RistrettoPoint::multiscalar_mul(
            &[
                bytes_to_scalar(&point_to_bytes(&RistrettoPoint::multiscalar_mul(
                    &[r],
                    &[self.get_public_key()],
                )))
                .unwrap(),
            ],
            &[self.get_public_key()],
        );

        let symmetric_key = Hasher::sha_256(&point_to_bytes(&RistrettoPoint::multiscalar_mul(
            &[r],
            &[one_time_account],
        )));

        (
            OneTimeAccount(one_time_account),
            BlindPair(KeyPair {
                private_key: r,
                public_key: r_point,
            }),
            symmetric_key,
        )
    }
}

#[derive(Copy, Clone)]
pub struct OneTimeAccount(RistrettoPoint);

impl OneTimeAccount {
    pub fn get_point(&self) -> RistrettoPoint {
        self.0
    }

    // extract the private key from the one-time-address
    pub fn get_private_key(
        &self,
        account: &Account,
        blind_point: RistrettoPoint,
    ) -> Result<Scalar, &'static str> {
        let key = match bytes_to_scalar(&point_to_bytes(&RistrettoPoint::multiscalar_mul(
            &[account.get_private_key()],
            &[blind_point],
        ))) {
            Ok(v) => v * account.get_private_key(),
            Err(_) => return Err("parse err"),
        };

        let expect_point = RistrettoPoint::multiscalar_mul(&[key], &[*BASEPOINT_G2]);
        if expect_point == self.get_point() {
            return Ok(key);
        }

        Err("this one time account not belong to you")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_account_test() {
        let account = Account::new();
        let (one_time_account, blind_secret, _) = account.gen_one_time_account();
        let key = one_time_account
            .get_private_key(&account, blind_secret.get_blind_point())
            .unwrap();
        let expect_one_time_account = RistrettoPoint::multiscalar_mul(&[key], &[*BASEPOINT_G2]);
        assert_eq!(one_time_account.get_point(), expect_one_time_account);
    }
}
