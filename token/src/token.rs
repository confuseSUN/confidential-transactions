use ct_crypto::aes;
use ct_utils::read_integer;
use ct_utils::{
    bytes_to_scalar, generator::BASEPOINT_G1, generator::BASEPOINT_G2, get_random_scalar,
    scalar_to_bytes,
};
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

#[derive(PartialEq, Copy, Clone)]
pub struct Token(RistrettoPoint);

#[derive(Debug)]
pub struct TokenSecret {
    pub blind: Scalar,
    pub balance: u64,
}

impl Token {
    pub fn get_point(&self) -> RistrettoPoint {
        self.0
    }

    pub fn mint(balance: u64) -> (Token, TokenSecret) {
        let balance_scalar = Scalar::from(balance);
        let blind = get_random_scalar();
        let commitment = RistrettoPoint::multiscalar_mul(
            &[balance_scalar, blind],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );
        (Token(commitment), TokenSecret { blind, balance })
    }
}

#[derive(Clone)]
pub struct EncryptoTokenSecret {
    pub balance_crypto: Vec<u8>,
    pub blind_crypto: Vec<u8>,
}

impl TokenSecret {
    //user symmetric key to encrypt balance and blind
    pub fn encrypt(&self, symmetric_key: &Vec<u8>) -> Result<EncryptoTokenSecret, &'static str> {
        let balance_crypto =
            match aes::encrypt(&self.balance.to_ne_bytes().to_vec(), &symmetric_key) {
                Ok(v) => v,
                Err(_) => return Err("encrypt err"),
            };

        let blind_crypto =
            match aes::encrypt(&scalar_to_bytes(&self.blind).to_vec(), &symmetric_key) {
                Ok(v) => v,
                Err(_) => return Err("encrypt err"),
            };

        Ok(EncryptoTokenSecret {
            balance_crypto,
            blind_crypto,
        })
    }
}

impl EncryptoTokenSecret {
    pub fn decrypt(&self, symmetric_key: &Vec<u8>) -> Result<TokenSecret, &'static str> {
        let balance = match aes::decrypt(&self.balance_crypto, &symmetric_key) {
            Ok(v) => read_integer::<u64>(&v),
            Err(_) => return Err("decrypt err1"),
        };

        let blind = match aes::decrypt(&self.blind_crypto, &symmetric_key) {
            Ok(v) => match bytes_to_scalar(&v) {
                Ok(v) => v,
                Err(_) => return Err("decrypt err2"),
            },
            Err(_) => return Err("decrypt err3"),
        };

        Ok(TokenSecret { blind, balance })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn mint_test() {
        let (_, input_secret) = Token::mint(100);
        let key: Vec<u8> = "abcdefghijklmnopqrstuvwxyzabcdef".as_bytes().to_vec();
        let encry_input_secret = input_secret.encrypt(&key).unwrap();
        let expect_secrt = encry_input_secret.decrypt(&key).unwrap();
        assert_eq!(expect_secrt.balance, input_secret.balance);
        assert_eq!(expect_secrt.blind, input_secret.blind);
    }
}

// pub fn convert(pack_data: &[u8]) -> u64 {
//     let ptr: *const u8 = pack_data.as_ptr();
//     let ptr: *const u64 = ptr as *const u64;
//     unsafe { *ptr }
// }
