use super::token::*;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use ct_utils::{
    generator::BASEPOINT_G1, generator::BASEPOINT_G2, get_random_scalar,
    point_to_bytes, transcript::TranscriptProtocol,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use merlin::Transcript;

pub struct SumProof {
    theta_a: Scalar,
    theta_b: Scalar,
    theta_1: Scalar,
    theta_2: Scalar,
    theta_3: Scalar,
}

impl SumProof {
    pub fn new_sum_proof(
        input: &TokenSecret,
        output1: &TokenSecret,
        output2: &TokenSecret,
    ) -> SumProof {
        Self::prove_sum_relationship(
            output1.balance,
            output2.balance,
            &output1.blind,
            &output2.blind,
            &input.blind,
        )
    }

    fn prove_sum_relationship(
        c1_value: u64,
        c2_value: u64,
        c1_blinding: &Scalar,
        c2_blinding: &Scalar,
        c3_blinding: &Scalar,
    ) -> SumProof {
        let alpha = get_random_scalar();
        let beta = get_random_scalar();
        let r1 = get_random_scalar();
        let r2 = get_random_scalar();

        let ca = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value), *c1_blinding],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );
        let cb = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c2_value), *c2_blinding],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );
        let c = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value + c2_value), *c3_blinding],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        let mut transcript = Transcript::new(b"sum_proof");
        transcript.append_message(b"",&point_to_bytes(&ca));
        transcript.append_message(b"", &point_to_bytes(&cb));
        transcript.append_message(b"", &point_to_bytes(&c));
        let x = transcript.challenge_scalar(b"");

        let theta_a = alpha - Scalar::from(c1_value) * x;
        let theta_b = beta - Scalar::from(c2_value) * x;
        let theta_1 = r1 - c1_blinding * x;
        let theta_2 = r2 - c2_blinding * x;
        let theta_3 = r1 + r2 - c3_blinding * x;

        SumProof {
            theta_a,
            theta_b,
            theta_1,
            theta_2,
            theta_3,
        }
    }

    pub fn verify_sum_proof(
        &self,
        input: &Token,
        output1: &Token,
        output2: &Token,
    ) -> Result<bool, &'static str> {
        self.verify_sum_relationship(
            &output1.get_point(),
            &output2.get_point(),
            &input.get_point(),
        )
    }

    fn verify_sum_relationship(
        &self,
        c1_point: &RistrettoPoint,
        c2_point: &RistrettoPoint,
        c3_point: &RistrettoPoint,
    ) -> Result<bool, &'static str> {
        let mut transcript = Transcript::new(b"sum_proof");
        transcript.append_message(b"",&point_to_bytes(&c1_point));
        transcript.append_message(b"", &point_to_bytes(&c2_point));
        transcript.append_message(b"", &point_to_bytes(&c3_point));
        let x = transcript.challenge_scalar(b"");

        let left = RistrettoPoint::multiscalar_mul(
            &[self.theta_a + self.theta_b, self.theta_3],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        ) + RistrettoPoint::multiscalar_mul(&[x], &[*c3_point]);

        let d1 = RistrettoPoint::multiscalar_mul(
            &[self.theta_a, self.theta_1],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        ) + RistrettoPoint::multiscalar_mul(&[x], &[*c1_point]);

        let d2 = RistrettoPoint::multiscalar_mul(
            &[self.theta_b, self.theta_2],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        ) + RistrettoPoint::multiscalar_mul(&[x], &[*c2_point]);
        let right = d1 + d2;

        Ok(left == right)
    }
}

#[derive(Clone)]
pub struct NonnegativeProof {
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
    proof: RangeProof,
}

impl NonnegativeProof {
    const LABEL: &'static [u8] = b"nonnegative proof";

    //use bulletproof algorithms to generate nonnegative proof
    pub fn new(secret: &TokenSecret) -> NonnegativeProof {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let mut transcript = Transcript::new(Self::LABEL);
        let (proof, _) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            secret.balance,
            &secret.blind,
            32,
        )
        .expect("generate nonnegative proof error");

        NonnegativeProof {
            pc_gens,
            bp_gens,
            proof,
        }
    }

    //verify nonnegative proof
    pub fn verify(&mut self, token: &Token) -> bool {
        let mut transcript = Transcript::new(Self::LABEL);
        self.proof
            .verify_single(
                &self.bp_gens,
                &self.pc_gens,
                &mut transcript,
                &token.get_point().compress(),
                32,
            )
            .is_ok()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn sum_proof_test() {
        let (input, input_secret) = Token::mint(100);
        let (output1, output_secret_1) = Token::mint(90);
        let (output2, output_secret_2) = Token::mint(10);

        let proof = SumProof::new_sum_proof(&input_secret, &output_secret_1, &output_secret_2);
        let verify = proof.verify_sum_proof(&input, &output1, &output2);
        assert_eq!(true, verify.unwrap());

        let (output2, output_secret_2) = Token::mint(110);
        let proof = SumProof::new_sum_proof(&input_secret, &output_secret_1, &output_secret_2);
        let verify = proof.verify_sum_proof(&input, &output1, &output2);
        assert_eq!(false, verify.unwrap())
    }

    #[test]
    fn nonnegative_proof_test() {
        let (token, secret) = Token::mint(20);

        let pc_gens = PedersenGens::default();
        let commitment = pc_gens.commit(Scalar::from(20u64), secret.blind);
        assert_eq!(token.get_point(), commitment);

        let mut proof = NonnegativeProof::new(&secret);
        let verify = proof.verify(&token);
        assert!(verify)
    }
}
