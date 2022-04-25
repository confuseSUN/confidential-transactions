use super::{account::Account, account::OneTimeAccount};
use ct_crypto::signature::{self, SignMsg};
use ct_token::prove::{NonnegativeProof, SumProof};
use ct_token::token::{EncryptoTokenSecret, Token, TokenSecret};
use ct_utils::hash::Hasher;
use ct_utils::point_to_bytes;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

#[derive(Clone)]
pub struct ConfidentialTransaction {
    pub one_time_account: OneTimeAccount,
    pub blind_point: RistrettoPoint,
    pub token: Token,
    pub nonnegative_proof: NonnegativeProof,
    pub encrypto_token_secret: EncryptoTokenSecret,
}

impl ConfidentialTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes1 = point_to_bytes(&self.one_time_account.get_point());
        let mut bytes2 = point_to_bytes(&self.blind_point);
        let mut bytes3 = point_to_bytes(&self.token.get_point());
        bytes1.append(&mut bytes2);
        bytes1.append(&mut bytes3);
        bytes1
    }

    //the ECDH algorithm is used to generate symmetric key
    //then use symmetric key to decrypt "encrypto_token_secret"
    pub fn decrypt_token_secrt(&self, key: Scalar) -> Result<TokenSecret, &'static str> {
        let symmetric_key = Hasher::sha_256(&point_to_bytes(&RistrettoPoint::multiscalar_mul(
            &[key],
            &[self.blind_point],
        )));

        self.encrypto_token_secret.decrypt(&symmetric_key)
    }

    pub fn transfer(
        &self,
        from: &Account,
        to: &Account,
        amount: u64,
    ) -> Result<SignTx, &'static str> {
        let key = self
            .one_time_account
            .get_private_key(from, self.blind_point)?;
        let input_token_secrt = self.decrypt_token_secrt(key)?;

        let (output1_one_time_account, output1_blind_pair, output1_symmetric_key) =
            from.gen_one_time_account();
        let (output2_one_time_account, output2_blind_pair, output2_symmetric_key) =
            to.gen_one_time_account();

        let (output1_token, output1_token_secret) = Token::mint(input_token_secrt.balance - amount);
        let (output2_token, output2_token_secret) = Token::mint(amount);

        let output1_crypt_secret = output1_token_secret.encrypt(&output1_symmetric_key)?;
        let output2_crypt_secret = output2_token_secret.encrypt(&output2_symmetric_key)?;

        let output1_onnegative_proof = NonnegativeProof::new(&output1_token_secret);
        let output2_onnegative_proof = NonnegativeProof::new(&output2_token_secret);

        let output1_ct = ConfidentialTransaction {
            one_time_account: output1_one_time_account,
            blind_point: output1_blind_pair.get_blind_point(),
            token: output1_token,
            nonnegative_proof: output1_onnegative_proof,
            encrypto_token_secret: output1_crypt_secret,
        };

        let output2_ct = ConfidentialTransaction {
            one_time_account: output2_one_time_account,
            blind_point: output2_blind_pair.get_blind_point(),
            token: output2_token,
            nonnegative_proof: output2_onnegative_proof,
            encrypto_token_secret: output2_crypt_secret,
        };

        let outputs = vec![output1_ct, output2_ct];
        let mut outputs_bytes = outputs.iter().map(|x| x.to_bytes()).flatten().collect();
        let sign_msg = signature::sign(key, &mut outputs_bytes);

        let sum_proof = SumProof::new_sum_proof(
            &input_token_secrt,
            &output1_token_secret,
            &output2_token_secret,
        );

        let sign_tx = SignTx {
            input: self.clone(),
            outputs: outputs,
            sign_msg: sign_msg,
            sum_proof: sum_proof,
        };

        Ok(sign_tx)
    }
}

pub struct SignTx {
    pub input: ConfidentialTransaction,
    pub outputs: Vec<ConfidentialTransaction>,
    pub sign_msg: SignMsg,
    pub sum_proof: SumProof,
}

impl SignTx {
    pub fn verify(&mut self) -> Result<bool, &'static str> {
        //verify signature
        let mut outputs_bytes = self
            .outputs
            .iter()
            .map(|x| x.to_bytes())
            .flatten()
            .collect();
        if !signature::verify(
            self.input.one_time_account.get_point(),
            &self.sign_msg,
            &mut outputs_bytes,
        ) {
            return Ok(false);
        }

        //verify nonnegative proof
        if !self
            .outputs
            .iter_mut()
            .all(|x| x.nonnegative_proof.verify(&x.token))
        {
            return Ok(false);
        }

        //verify sum proof
        self.sum_proof.verify_sum_proof(
            &self.input.token,
            &self.outputs[0].token,
            &self.outputs[1].token,
        )
    }
}
