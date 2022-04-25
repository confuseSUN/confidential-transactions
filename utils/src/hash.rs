use sha3::{Digest, Sha3_256};
pub struct Hasher {}

impl Hasher {
    pub fn sha_256<T: AsRef<[u8]> + ?Sized>(data: &T) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha_256_test() {
        let bytes = "example bytestring!";
        let result = Hasher::sha_256(bytes);
        let r = vec![
            152, 185, 148, 237, 204, 0, 101, 13, 162, 124, 114, 165, 29, 198, 179, 241, 44, 176,
            105, 181, 53, 221, 238, 76, 129, 94, 197, 124, 152, 133, 189, 36,
        ];
        assert_eq!(result, r);
    }
}
