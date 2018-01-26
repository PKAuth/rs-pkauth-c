#![deny(warnings)]

extern crate pkauth;
extern crate publicsuffix;
extern crate ring;
extern crate serde;
extern crate serde_json;
extern crate staticpublicsuffix;

use pkauth::{AlgorithmId, ToAlgorithm, PKAJ};
use pkauth::internal::{deserialize_psf};
use pkauth::sym::enc as se;
use publicsuffix::Host;
use ring::rand::{SystemRandom};
use staticpublicsuffix::STATIC_SUFFIX_LIST;
use serde::ser::Serialize;
// use std::any::Any;
use std::ffi::{CString};
use std::os::raw::c_char;
use std::ptr::null_mut;

#[inline]
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

/// Returns null if None.
#[inline]
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

/// Returns null if None.
#[inline]
fn to_cstring( s : String) -> *mut c_char {
    match CString::new( s) {
        Err(_) => {
            null_mut()
        }
        Ok( s) => {
            s.into_raw()
        }
    }
}

/// Returns null if None.
#[inline]
fn to_json_cstring<T : Serialize>( o : &T) -> *mut c_char {
    match serde_json::to_string( o) {
        Err(_) => {
            null_mut()
        }
        Ok( s) => {
            to_cstring( s)
        }
    }
}

#[no_mangle]
pub unsafe extern fn rs_free_cstring( o : *mut c_char) {
    CString::from_raw( o);
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_extract_domain( url : String) -> *mut String { // Option<String> {
    let d = (&STATIC_SUFFIX_LIST).parse_url( url).ok();
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
/// Returns null if None.
pub extern fn rs_se_gen( rng : &SystemRandom, alg : &se::Algorithm) -> *mut se::Key {
    let key = se::gen( rng, alg).ok();
    option_to_ptr( key)
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
/// Returns null if None.
pub extern fn rs_se_encode_key( key : &se::Key) -> *mut c_char {
    to_json_cstring( &PKAJ{pkaj: key})
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
