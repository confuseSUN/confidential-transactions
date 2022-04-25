use ct_mlsag::{material::KeyPair, mlsag::Mlsag, signature::Signarute};
use ct_token::{
    prove::NonnegativeProof,
    token::{EncryptoTokenSecret, Token, TokenSecret},
};
use ct_utils::generator::BASEPOINT_G2;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::{
    account::{Account, OneTimeAccount},
    confidential_transaction::ConfidentialTransaction,
    BlindPair,
};

type TransferAmount = u64;

pub struct RingCT {
    pub ownership_account: Account,
    pub input_tx: Vec<ConfidentialTransaction>,
    pub output_account: Vec<(Account, TransferAmount)>,
    pub decoys: Vec<Vec<ConfidentialTransaction>>,
}

impl RingCT {
    pub fn transfer(&self) -> RingSignature {
        let input_token_secrt = self.decrypt_input_token_secrt();
        assert!(
            input_token_secrt.iter().map(|x| x.balance).sum::<u64>()
                == self.output_account.iter().map(|(_, x)| x).sum()
        );
        assert!(self.decoys.iter().all(|x| x.len() == self.input_tx.len()));

        let output_one_time_account = self.generate_one_time_account();
        let output_token = self.token_mint();
        let encry_token_secrets = Self::encry_token_secret(&output_one_time_account, &output_token);
        let nonnegative_proofs = Self::generate_nonnegative_proof(&output_token);
        let output_cts = Self::get_output_cts(
            &output_one_time_account,
            &output_token,
            &encry_token_secrets,
            &nonnegative_proofs,
        );
        let sign_msg: Vec<u8> = output_cts.iter().map(|x| x.to_bytes()).flatten().collect();

        let mut mlasg = Mlsag::default();
        mlasg.add_signer(self.compute_signer_keypairs(&input_token_secrt, &output_token));
        for x in &self.decoys {
            mlasg.add_decopys(Self::compute_decoys_keypairs(&x, &output_token))
        }
        let signarute = mlasg.sign(&sign_msg);

        let mut inputs = self.decoys.clone();
        inputs.push(self.input_tx.clone());
        RingSignature {
            sig: signarute,
            outputs: output_cts,
            inputs: inputs,
        }
    }
}

impl RingCT {
    fn decrypt_input_token_secrt(&self) -> Vec<TokenSecret> {
        self.input_tx
            .iter()
            .map(|x| {
                let key = x
                    .one_time_account
                    .get_private_key(&self.ownership_account, x.blind_point)
                    .unwrap();
                x.decrypt_token_secrt(key).unwrap()
            })
            .collect()
    }

    fn generate_one_time_account(&self) -> Vec<(OneTimeAccount, BlindPair, Vec<u8>)> {
        self.output_account
            .iter()
            .map(|(x, _)| x.gen_one_time_account())
            .collect()
    }

    fn token_mint(&self) -> Vec<(Token, TokenSecret)> {
        self.output_account
            .iter()
            .map(|(_, x)| Token::mint(*x))
            .collect()
    }

    fn encry_token_secret(
        a: &Vec<(OneTimeAccount, BlindPair, Vec<u8>)>,
        b: &Vec<(Token, TokenSecret)>,
    ) -> Vec<EncryptoTokenSecret> {
        a.iter()
            .zip(b.iter())
            .map(|((_, _, key), (_, token_secret))| token_secret.encrypt(key).unwrap())
            .collect()
    }

    fn generate_nonnegative_proof(a: &Vec<(Token, TokenSecret)>) -> Vec<NonnegativeProof> {
        a.iter().map(|(_, x)| NonnegativeProof::new(x)).collect()
    }

    fn compute_signer_keypairs(
        &self,
        input_token_secrt: &Vec<TokenSecret>,
        output_token: &Vec<(Token, TokenSecret)>,
    ) -> Vec<KeyPair> {
        let mut key_pairs: Vec<KeyPair> = self
            .input_tx
            .iter()
            .map(|x| {
                let private_key = x
                    .one_time_account
                    .get_private_key(&self.ownership_account, x.blind_point)
                    .unwrap();
                KeyPair {
                    private_key: private_key,
                    public_key: x.one_time_account.get_point(),
                }
            })
            .collect();

        let z: Scalar = input_token_secrt.iter().map(|x| x.blind).sum::<Scalar>()
            - output_token.iter().map(|(_, x)| x.blind).sum::<Scalar>();

        key_pairs.push(KeyPair {
            private_key: z,
            public_key: z * (*BASEPOINT_G2),
        });

        key_pairs
    }

    fn compute_decoys_keypairs(
        decoy: &Vec<ConfidentialTransaction>,
        output_token: &Vec<(Token, TokenSecret)>,
    ) -> Vec<KeyPair> {
        let mut key_pairs: Vec<KeyPair> = decoy
            .iter()
            .map(|x| KeyPair {
                private_key: Scalar::default(),
                public_key: x.one_time_account.get_point(),
            })
            .collect();

        let output_token_sum = output_token
            .iter()
            .map(|(x, _)| x.get_point())
            .sum::<RistrettoPoint>();

        key_pairs.push(KeyPair {
            public_key: decoy
                .iter()
                .map(|x| x.token.get_point())
                .sum::<RistrettoPoint>()
                - output_token_sum,
            private_key: Scalar::default(),
        });
        key_pairs
    }

    fn get_output_cts(
        output_one_time_account: &Vec<(OneTimeAccount, BlindPair, Vec<u8>)>,
        output_token: &Vec<(Token, TokenSecret)>,
        encry_token_secrets: &Vec<EncryptoTokenSecret>,
        nonnegative_proofs: &Vec<NonnegativeProof>,
    ) -> Vec<ConfidentialTransaction> {
        output_one_time_account
            .iter()
            .zip(output_token.iter())
            .zip(encry_token_secrets.iter())
            .zip(nonnegative_proofs.iter())
            .map(
                |((((onetime_account, blind_pair, _), (token, _)), encry), nonnegative_proof)| {
                    ConfidentialTransaction {
                        one_time_account: *onetime_account,
                        blind_point: blind_pair.get_blind_point(),
                        token: *token,
                        nonnegative_proof: nonnegative_proof.clone(),
                        encrypto_token_secret: encry.clone(),
                    }
                },
            )
            .collect()
    }
}

pub struct RingSignature {
    sig: Signarute,
    outputs: Vec<ConfidentialTransaction>,
    inputs: Vec<Vec<ConfidentialTransaction>>,
}

impl RingSignature {
    pub fn verify(&mut self) -> bool {
        //verify signature
        let sign_msg: Vec<u8> = self
            .outputs
            .iter()
            .map(|x| x.to_bytes())
            .flatten()
            .collect();
        if !self.sig.verify(&sign_msg) {
            return false;
        }

        println!("验证环签名, 正确!");

        //verify nonnegative proof
        if !self
            .outputs
            .iter_mut()
            .all(|x| x.nonnegative_proof.verify(&x.token))
        {
            return false;
        }

        println!("验证非负证明, 正确!");

        //verify sum proof
        let output_token_sum = self.compute_output_token_sum();
        if !self
            .inputs
            .iter()
            .zip(self.sig.public_keys.iter())
            .all(|(x, y)| {
                x.iter()
                    .map(|x| x.token.get_point())
                    .sum::<RistrettoPoint>()
                    == output_token_sum + y[y.len() - 1]
            })
        {
            return false;
        }

        println!("验证输入= 输出, 正确!");

        //todo 验证key_images是否出现在历史交易中。

        true
    }

    fn compute_output_token_sum(&self) -> RistrettoPoint {
        self.outputs.iter().map(|x| x.token.get_point()).sum()
    }
}
