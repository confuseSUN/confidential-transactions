use crate::{
    material::{KeyPair, Material},
    signature::Signarute,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

#[derive(Default)]
pub struct Mlsag {
    pub decoys: Vec<Material>,
    pub signer: Material,
}

impl Mlsag {
    pub fn add_signer(&mut self, key_pairs: Vec<KeyPair>) {
        self.signer = Material::new_signer(key_pairs)
    }

    pub fn add_decopys(&mut self, key_pairs: Vec<KeyPair>) {
        self.decoys.push(Material::new_decoys(key_pairs))
    }

    pub fn sign(&self, msg: &[u8]) -> Signarute {
        let member_size = self.decoys.len() + 1;
        let key_images = self.compute_key_images();
        let mut c_pai = self.compute_signer_challenge(msg);

        let mut c_vec = Vec::with_capacity(member_size);
        c_vec.push(c_pai);
        for decoy in self.decoys.iter() {
            c_pai = decoy.compute_decoy_challenge(msg, &c_pai, &key_images);
            c_vec.push(c_pai);
        }

        let mut s_vec = Vec::with_capacity(member_size);
        let mut public_key_vec: Vec<Vec<RistrettoPoint>> = Vec::with_capacity(member_size);
        for s in self.decoys.iter() {
            s_vec.push(s.s_vec.clone());
            public_key_vec.push(s.key_pairs.iter().map(|x| x.public_key).collect());
        }
        s_vec.push(self.compute_signer_s_vec(&c_pai));
        public_key_vec.push(self.signer.key_pairs.iter().map(|x| x.public_key).collect());

        Signarute {
            public_keys: public_key_vec,
            key_images: key_images,
            c: c_vec[0],
            s: s_vec,
        }
    }
}

impl Mlsag {
    fn compute_key_images(&self) -> Vec<RistrettoPoint> {
        self.signer.compute_key_images()
    }

    fn compute_signer_challenge(&self, msg: &[u8]) -> Scalar {
        self.signer.compute_signer_challenge(msg)
    }

    pub fn compute_signer_s_vec(&self, c_pai: &Scalar) -> Vec<Scalar> {
        self.signer.compute_signer_s_vec(c_pai)
    }
}
