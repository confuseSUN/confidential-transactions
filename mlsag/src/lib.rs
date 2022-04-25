use ct_utils::get_random_scalar;
use curve25519_dalek::scalar::Scalar;

pub mod material;
pub mod mlsag;
pub mod signature;

pub fn get_random_scalars(size: usize) -> Vec<Scalar> {
    let mut scalars: Vec<Scalar> = Vec::with_capacity(size);
    for _ in 0..size {
        scalars.push(get_random_scalar());
    }
    scalars
}

#[cfg(test)]
mod tests {
    use crate::{
        get_random_scalars,
        material::{KeyPair, Material},
        mlsag::Mlsag,
    };
    use ct_utils::generator::BASEPOINT_G2;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn mlsag_test() {
        let decoy_size = 5;
        let key_size = 3;
        let msg = b"hello world";

        let singer_material = generator_singer_material(key_size);
        let decoys_material = generator_decoys_material(decoy_size, key_size);
        let mlsag = Mlsag {
            signer: singer_material,
            decoys: decoys_material,
        };
        let sig = mlsag.sign(msg);
        assert!(sig.verify(msg))
    }

    fn generator_singer_material(size: usize) -> Material {
        let scalars = get_random_scalars(size);
        let key_pairs = scalars
            .into_iter()
            .map(|x| KeyPair {
                private_key: x,
                public_key: x * (*BASEPOINT_G2),
            })
            .collect();
        Material::new_signer(key_pairs)
    }

    fn generator_decoys_material(decoy_size: usize, key_size: usize) -> Vec<Material> {
        let mut decoys_material = Vec::with_capacity(decoy_size);
        for _ in 0..decoy_size {
            let scalars = get_random_scalars(key_size);
            let key_pairs = scalars
                .into_iter()
                .map(|x| KeyPair {
                    private_key: Scalar::default(),
                    public_key: x * (*BASEPOINT_G2),
                })
                .collect();
            decoys_material.push(Material::new_decoys(key_pairs));
        }
        decoys_material
    }
}
