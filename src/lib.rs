#![deny(warnings)]

extern crate pkauth;
extern crate publicsuffix;
extern crate ring;
extern crate serde;
extern crate serde_json;
extern crate staticpublicsuffix;

// mod stable_ptr;

use pkauth::{AlgorithmId, ToAlgorithm, PKAJ};
use pkauth::sym::enc as se;
use publicsuffix::Host;
use ring::rand::{SystemRandom};
use staticpublicsuffix::STATIC_SUFFIX_LIST;
use serde::de::Deserialize;
use serde::ser::Serialize;
// use std::any::Any;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use std::ptr::{null_mut, write};
use std::slice;

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

fn borrow_cstr<'a>( s : *const c_char) -> Option<&'a str> {
    unsafe {
        CStr::from_ptr( s).to_str().ok()
    }
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
#[no_mangle]
pub unsafe extern fn rs_free_vec_u8( o : *mut Vec<u8>) {
    free_c( o)
}

/// Returns null if None.
#[inline]
fn to_cstring<T : Into<Vec<u8>>>( s : T) -> *mut c_char {
    match CString::new( s) {
        Err(_) => {
            null_mut()
        }
        Ok( s) => {
            s.into_raw()
        }
    }
}

#[no_mangle]
pub unsafe extern fn rs_free_cstring( o : *mut c_char) {
    CString::from_raw( o);
}

#[inline]
fn option_to_cstring<T : Into<Vec<u8>>>( s : Option<T>) -> *mut c_char {
    match s {
        None => {
            null_mut()
        }
        Some( s) => {
            to_cstring( s)
        }
    }
}

/// Returns null if None.
#[inline]
fn to_json_cstring<T : Serialize>( o : &T) -> *mut c_char {
    option_to_cstring( serde_json::to_string( o).ok())
}

#[inline]
fn from_json_cstr<'a, T : Deserialize<'a>>( s : *const c_char) -> Option<T> {
    borrow_cstr( s).and_then(|s| serde_json::from_str(s).ok())
}

#[no_mangle]
pub unsafe extern fn to_vec( arr : *const u8, len : usize) -> *mut Vec<u8> {
    let s = slice::from_raw_parts( arr, len);
    to_c( s.to_vec())
}

#[no_mangle]
pub unsafe extern fn from_vec( v : &Vec<u8>, len : *mut usize) -> *const u8 {
    // Write length of vector.
    write( len, v.len());
    
    // Return reference to vector.
    v.as_slice().as_ptr()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_extract_domain( url : *const c_char) -> *mut c_char { // Option<String> {
    let url = borrow_cstr( url);
    let d = url.and_then(|url| (&STATIC_SUFFIX_LIST).parse_url( url).ok());
    let d = d.and_then(|d| match d {
        Host::Ip(_) => {
            None
        }
        Host::Domain( d) => {
            d.root()
        }
    });

    option_to_cstring( d)
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
pub extern fn rs_se_encrypt( rng : &SystemRandom, key : &se::Key, message : &Vec<u8>) -> *mut Vec<u8> {
    option_to_ptr( se::encrypt_content_bs( rng, key, message.clone()).ok())
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_se_decrypt( key : &se::Key, c : &Vec<u8>) -> *mut Vec<u8> {
    option_to_ptr( se::decrypt_content_bs( key, c).ok())
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_se_encode_key( key : &se::Key) -> *mut c_char {
    to_json_cstring( &PKAJ{pkaj: key})
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_se_decode_key( encoded : *const c_char) -> *mut se::Key {
    let o : Option<PKAJ<se::Key>> = from_json_cstr( encoded);
    option_to_ptr( o.map(|o| o.pkaj))
}

#[no_mangle]
pub extern fn rs_se_derive_key( alg : &se::Algorithm, salt : &Vec<u8>, password : &Vec<u8>) -> *mut se::Key {
    to_c( se::derive_key( alg, salt, password))
}

#[no_mangle]
pub extern fn rs_se_key_algorithm_identifier( key : &se::Key) -> *mut c_char {
    to_cstring( AlgorithmId::to_algorithm_id( &ToAlgorithm::to_algorithm( key)).to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
