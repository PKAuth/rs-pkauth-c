#![deny(warnings)]

extern crate pkauth;
extern crate ring;

use pkauth::{serialize_psf, deserialize_psf, EncodePSF, DecodePSF, AlgorithmId, ToAlgorithm};
use pkauth::sym::enc as se;
use ring::rand::{SystemRandom};

#[no_mangle]
pub extern fn rs_systemrandom() -> SystemRandom {
    SystemRandom::new()
}

#[no_mangle]
pub extern fn rs_se_aesgcm256() -> se::Algorithm {
    se::Algorithm::SEAesGcm256
}

#[no_mangle]
pub extern fn rs_se_gen( rng : &SystemRandom, alg : &se::Algorithm) -> Option<se::Key> {
    se::gen( rng, alg).ok()
}

#[no_mangle]
pub extern fn rs_se_encrypt( rng : &SystemRandom, key : &se::Key, message : &Vec<u8>) -> Option<Vec<u8>> {
    se::encrypt_content_bs( rng, key, message.clone()).ok()
}

#[no_mangle]
pub extern fn rs_se_decrypt( key : &se::Key, c : &Vec<u8>) -> Option<Vec<u8>> {
    se::decrypt_content_bs( key, c).ok()
}

#[no_mangle]
pub extern fn rs_se_encode_key( key : &se::Key) -> String {
    serialize_psf( &EncodePSF::encode_psf( key))
}

#[no_mangle]
pub extern fn rs_se_decode_key( alg : &se::Algorithm, encoded : String) -> Option<se::Key> {
    if let Some( encoded) = deserialize_psf( encoded).ok() {
        DecodePSF::decode_psf( alg, &encoded).ok()
    }
    else {
       None
    }
}

#[no_mangle]
pub extern fn rs_se_derive_key( alg : &se::Algorithm, salt : &Vec<u8>, password : &Vec<u8>) -> se::Key {
    se::derive_key( alg, salt, password)
}

#[no_mangle]
pub extern fn rs_se_key_algorithm_identifier( key : &se::Key) -> String {
    AlgorithmId::to_algorithm_id( &ToAlgorithm::to_algorithm( key)).to_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
