use ct_utils::{
    generator::BASEPOINT_G2, get_random_scalar, point_to_bytes,
    transcript::TranscriptProtocol,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use merlin::Transcript;

pub struct SignMsg {
    blind_point: RistrettoPoint,
    private_key_blind: Scalar,
}

pub fn sign(private_key: Scalar, msg: &mut Vec<u8>) -> SignMsg {
    let public_key = RistrettoPoint::multiscalar_mul(&[private_key], &[*BASEPOINT_G2]);
    let blind = get_random_scalar();
    let blind_point = RistrettoPoint::multiscalar_mul(&[blind], &[*BASEPOINT_G2]);

    let mut transcript = Transcript::new(b"ct_sign");
    transcript.append_message(b"public_key", &point_to_bytes(&public_key));
    transcript.append_message(b"blind_point", &point_to_bytes(&blind_point));
    transcript.append_message(b"msg", &msg);
    let h = transcript.challenge_scalar(b"");
    let private_key_blind = blind - h * private_key;
    SignMsg {
        blind_point,
        private_key_blind,
    }
}

pub fn verify(public_key: RistrettoPoint, sign: &SignMsg, msg: &mut Vec<u8>) -> bool {
    let mut transcript = Transcript::new(b"ct_sign");
    transcript.append_message(b"public_key", &point_to_bytes(&public_key));
    transcript.append_message(b"blind_point", &point_to_bytes(&sign.blind_point));
    transcript.append_message(b"msg", &msg);
    let h = transcript.challenge_scalar(b"");

    let expect_blind_point =
        RistrettoPoint::multiscalar_mul(&[h, sign.private_key_blind], &[public_key, *BASEPOINT_G2]);
    expect_blind_point == sign.blind_point
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sign_verify_test() {
        let msg = vec![1, 2, 3, 4, 5, 6];
        let key = get_random_scalar();
        let key_point = RistrettoPoint::multiscalar_mul(&[key], &[*BASEPOINT_G2]);

        let sign_msg = sign(key, &mut msg.to_vec());
        let verify_result = verify(key_point, &sign_msg, &mut msg.to_vec());
        assert_eq!(true, verify_result);

        let key_point = RistrettoPoint::multiscalar_mul(&[get_random_scalar()], &[*BASEPOINT_G2]);
        let verify_result = verify(key_point, &sign_msg, &mut msg.to_vec());
        assert_eq!(false, verify_result);
    }
}
