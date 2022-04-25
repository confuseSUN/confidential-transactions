#[macro_use]
extern crate lazy_static;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::OsRng;
use std::convert::TryInto;

pub mod generator;
pub mod hash;
pub mod transcript;
use crate::hash::Hasher;

pub trait ReadInteger<T> {
    fn from_le_bytes(data: &[u8]) -> T;
    fn from_be_bytes(data: &[u8]) -> T;
}

macro_rules! impl_read_integer {
    ($($t:ty),+) => {
        $(impl ReadInteger<$t> for $t {
            fn from_le_bytes(data: &[u8]) -> $t {
                <$t>::from_le_bytes(data.try_into().unwrap())
            }
            fn from_be_bytes(data: &[u8]) -> $t {
                <$t>::from_be_bytes(data.try_into().unwrap())
            }
        })+
    }
}

impl_read_integer!(u8, i16, i32, u32, i64, u64);

pub fn read_integer<T: ReadInteger<T>>(data: &[u8]) -> T {
    T::from_le_bytes(&data[..std::mem::size_of::<T>()])
}

pub fn bytes_to_point(point: &[u8]) -> Result<RistrettoPoint, &'static str> {
    let point_value = match CompressedRistretto::from_slice(&point).decompress() {
        Some(v) => v,
        None => {
            return Err("bytes_to_point err");
        }
    };
    Ok(point_value)
}

pub fn point_to_bytes(point: &RistrettoPoint) -> Vec<u8> {
    point.compress().to_bytes().to_vec()
}

pub fn scalar_to_bytes(input: &Scalar) -> Vec<u8> {
    input.as_bytes().to_vec()
}

pub fn bytes_to_scalar(input: &[u8]) -> Result<Scalar, &'static str> {
    let get_num_u8 = to_bytes32_slice(&input)?;
    let scalar_num = Scalar::from_bits(*get_num_u8);
    Ok(scalar_num)
}

fn to_bytes32_slice(barry: &[u8]) -> Result<&[u8; 32], &'static str> {
    let pop_u8 = match barry.try_into() {
        Ok(v) => v,
        Err(_) => return Err("bytes_to_scalar err"),
    };
    Ok(pop_u8)
}

pub fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Scalar {
    let mut array = [0; 32];
    array.clone_from_slice(&Hasher::sha_256(input));
    Scalar::from_bytes_mod_order(array)
}

pub fn get_random_scalar() -> Scalar {
    Scalar::random(&mut OsRng)
}

#[test]
fn test() {
    let data = 100000u64;
    let data = data.to_ne_bytes().to_vec();
    println!("{}", read_integer::<u64>(&data))
}
