#![deny(warnings)]

extern crate pkauth;
extern crate publicsuffix;
extern crate ring;
extern crate staticpublicsuffix;

use pkauth::{AlgorithmId, ToAlgorithm};
use pkauth::internal::{serialize_psf, deserialize_psf};
use pkauth::sym::enc as se;
use publicsuffix::Host;
use ring::rand::{SystemRandom};
use staticpublicsuffix::STATIC_SUFFIX_LIST;

#[no_mangle]
pub extern fn rs_extract_domain( url : String) -> Option<String> {
    let d = &STATIC_SUFFIX_LIST.parse_url( url).ok()?;
    match d {
        &Host::Ip(_) => {
            None
        }
        &Host::Domain( ref d) => {
            d.root().map(|d| d.to_string())
        }
    }
}

#[no_mangle]
// pub extern fn rs_free<T>( o : T) {
pub extern fn rs_free_system_random( _ : SystemRandom) {
}

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
    serialize_psf( key)
}

#[no_mangle]
pub extern fn rs_se_decode_key( alg : &se::Algorithm, encoded : String) -> Option<se::Key> {
    deserialize_psf( alg, &encoded).ok()
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
