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
// use std::any::Any;
use std::ptr::null_mut;

fn to_c<T>( o : T) -> *mut T {
    Box::into_raw( Box::new( o))
}

// #[no_mangle]
// pub unsafe extern fn free_c( o : *mut Any) {
// pub unsafe extern fn free_c<T>( o : *mut T) {
#[inline]
unsafe fn free_c<T>( o : *mut T) {
    Box::from_raw( o);
}

fn option_to_ptr<T>( o : Option<T>) -> *mut T {
    match o {
        None => {
            null_mut()
        }
        Some( o) => {
            to_c( o)
        }
    }
}

#[no_mangle]
pub unsafe extern fn rs_free_systemrandom( o : *mut SystemRandom) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_se_algorithm( o : *mut se::Algorithm) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_se_key( o : *mut se::Key) {
    free_c( o)
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_extract_domain( url : String) -> *mut String { // Option<String> {
    let d = &STATIC_SUFFIX_LIST.parse_url( url).ok();
    let d = d.and_then(|d| match d {
        Host::Ip(_) => {
            None
        }
        Host::Domain( ref d) => {
            d.root().map(|d| d.to_string())
        }
    });
    option_to_ptr( d)
}

#[no_mangle]
pub extern fn rs_systemrandom() -> *mut SystemRandom {
    to_c( SystemRandom::new())
}

#[no_mangle]
pub extern fn rs_se_aesgcm256() -> *mut se::Algorithm {
    to_c( se::Algorithm::SEAesGcm256)
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
