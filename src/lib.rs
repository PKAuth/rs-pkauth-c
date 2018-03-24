// #![deny(warnings)]

extern crate base64;
// extern crate pkauth;
extern crate publicsuffix;
// extern crate ring;
extern crate serde;
extern crate serde_json;
extern crate staticpublicsuffix;

// mod stable_ptr;

// use pkauth::{AlgorithmId, ToAlgorithm, PKAJ, ToIdentifier, ToPublicKey};
// use pkauth::sym::enc as se;
// use pkauth::asym::auth as aa;
// use pkauth::asym::enc as ae;
// use publicsuffix::Host;
// use ring::rand::{SystemRandom};
// use staticpublicsuffix::STATIC_SUFFIX_LIST;
use serde::de::Deserialize;
use serde::ser::Serialize;
// use std::any::Any;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use std::ptr::{null_mut}; //, write};
// use std::slice;

#[no_mangle]
pub extern fn div11( x : i32) -> i32 {
    x / 11
}

pub enum Key {}
pub enum PublicKey {}
pub enum PrivateKey {}
pub enum Algorithm {}
pub enum SystemRandom {}

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
pub unsafe extern fn rs_free_se_algorithm( o : *mut Algorithm) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_se_key( o : *mut Key) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_ae_algorithm( o : *mut Algorithm) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_aa_algorithm( o : *mut Algorithm) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_aa_private_key( o : *mut PrivateKey) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_aa_public_key( o : *mut PublicKey) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_ae_private_key( o : *mut PrivateKey) {
    free_c( o)
}

#[no_mangle]
pub unsafe extern fn rs_free_ae_public_key( o : *mut PublicKey) {
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
pub unsafe extern fn rs_to_vec( arr : *const u8, len : usize) -> *mut Vec<u8> {
    // let s = slice::from_raw_parts( arr, len);
    // to_c( s.to_vec())
    unimplemented!()
}

#[no_mangle]
pub unsafe extern fn rs_from_vec( v : &Vec<u8>, len : *mut usize) -> *const u8 {
    // // Write length of vector.
    // write( len, v.len());
    // 
    // // Return reference to vector.
    // v.as_slice().as_ptr()
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_extract_domain( url : *const c_char) -> *mut c_char { // Option<String> {
    // let url = borrow_cstr( url);
    // let d = url.and_then(|url| (&STATIC_SUFFIX_LIST).parse_url( url).ok());
    // let d = d.map(|d| match d {
    //     Host::Ip(_) => {
    //         null_mut()
    //     }
    //     Host::Domain( d) => {
    //         option_to_cstring( d.root())
    //     }
    // });

    // d.unwrap_or( null_mut())
    unimplemented!()
}

#[no_mangle]
pub unsafe extern fn rs_encode_base64url( v : &Vec<u8>) -> *mut c_char {
    // let b = base64::encode_config( &v, base64::URL_SAFE);
    // to_cstring( b)
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub unsafe extern fn rs_decode_base64url( b : *const c_char) -> *mut Vec<u8> {
    // let v = borrow_cstr( b).and_then(|b| base64::decode_config( &b, base64::URL_SAFE).ok());
    // option_to_ptr( v)
    unimplemented!()
}

#[no_mangle]
pub extern fn rs_systemrandom() -> *mut SystemRandom {
    unimplemented!()
    // to_c( SystemRandom::new())
}

// Sym enc functions.

#[no_mangle]
pub extern fn rs_se_aesgcm256() -> *mut Algorithm {
    // to_c( Algorithm::SEAesGcm256)
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_se_gen( rng : &SystemRandom, alg : &Algorithm) -> *mut Key {
    // let key = gen( rng, alg).ok();
    // option_to_ptr( key)
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_se_encrypt( rng : &SystemRandom, key : &Key, message : &Vec<u8>) -> *mut Vec<u8> {
    // option_to_ptr( encrypt_content_bs( rng, key, message.clone()).ok())
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_se_decrypt( key : &Key, c : &Vec<u8>) -> *mut Vec<u8> {
    // option_to_ptr( decrypt_content_bs( key, c).ok())
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_se_encode_key( key : &Key) -> *mut c_char {
    // to_json_cstring( &PKAJ{pkaj: key})
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_se_decode_key( encoded : *const c_char) -> *mut Key {
    // let o : Option<PKAJ<Key>> = from_json_cstr( encoded);
    // option_to_ptr( o.map(|o| o.pkaj))
    unimplemented!()
}

#[no_mangle]
pub extern fn rs_se_derive_key( alg : &Algorithm, salt : &Vec<u8>, password : &Vec<u8>) -> *mut Key {
    // to_c( derive_key( alg, salt, password))
    unimplemented!()
}

#[no_mangle]
pub extern fn rs_se_key_algorithm_identifier( key : &Key) -> *mut c_char {
    // let s = to_cstring( AlgorithmId::to_algorithm_id( &ToAlgorithm::to_algorithm( key)).to_owned());
    // assert!( !s.is_null());
    // s
    unimplemented!()
}

// Asym auth functions.
#[no_mangle]
pub extern fn rs_aa_ed25519() -> *mut Algorithm {
    // to_c( Algorithm::AAEd25519)
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_aa_gen( rng : &SystemRandom, alg : &Algorithm) -> *mut PrivateKey {
    // option_to_ptr( gen( rng, alg).ok())
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_aa_encode_private_key( key : &PrivateKey) -> *mut c_char {
    // to_json_cstring( &PKAJ{pkaj: key})
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_aa_decode_private_key( encoded : *const c_char) -> *mut PrivateKey {
    // let o : Option<PKAJ<PrivateKey>> = from_json_cstr( encoded);
    // option_to_ptr( o.map(|o| o.pkaj))
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_aa_encode_public_key( key : &PublicKey) -> *mut c_char {
    // to_json_cstring( &PKAJ{pkaj: key})
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_aa_decode_public_key( encoded : *const c_char) -> *mut PublicKey {
    // let o : Option<PKAJ<PublicKey>> = from_json_cstr( encoded);
    // option_to_ptr( o.map(|o| o.pkaj))
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_aa_sign( key : &PrivateKey, content : &Vec<u8>) -> *mut Vec<u8> {
    // Copy content before signing to be safe.
    // option_to_ptr( sign_content_bs( key, content.to_owned()).ok())
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_aa_verify( key : &PublicKey, sig : &Vec<u8>) -> *mut Vec<u8> {
    // Copy content before verifying to be safe.
    // option_to_ptr( verify_content_bs( key, sig.to_owned()).ok())
    unimplemented!()
}

#[no_mangle]
pub extern fn rs_aa_public_key_to_identifier( key : &PublicKey) -> *mut c_char {
    // let s = to_cstring( ToIdentifier::to_identifier( key));
    // assert!( !s.is_null());
    // s
    unimplemented!()
}

#[no_mangle]
pub extern fn rs_aa_private_key_to_identifier( key : &PrivateKey) -> *mut c_char {
    // let s = to_cstring( ToIdentifier::to_identifier( key));
    // assert!( !s.is_null());
    // s
    unimplemented!()
}

#[no_mangle]
pub extern fn rs_aa_private_key_to_public_key( key : &PrivateKey) -> *mut PublicKey {
    // to_c( ToPublicKey::to_public_key( key))
    unimplemented!()
}

#[no_mangle]
pub extern fn rs_aa_public_key_equal( k1 : &PublicKey, k2 : &PublicKey) -> bool {
    // k1 == k2
    unimplemented!()
}

// Asym enc functions.

#[no_mangle]
pub extern fn rs_ae_private_key_to_public_key( key : &PrivateKey) -> *mut PublicKey {
    // to_c( ToPublicKey::to_public_key( key))
    unimplemented!()
}

#[no_mangle]
pub extern fn rs_ae_x25519() -> *mut Algorithm {
    // to_c( Algorithm::AEX25519)
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_ae_gen( rng : &SystemRandom, alg : &Algorithm) -> *mut PrivateKey {
    // option_to_ptr( gen( rng, alg))
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_ae_encode_public_key( key : &PublicKey) -> *mut c_char {
    // to_json_cstring( &PKAJ{pkaj: key})
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_ae_decode_public_key( encoded : *const c_char) -> *mut PublicKey {
    // let o : Option<PKAJ<PublicKey>> = from_json_cstr( encoded);
    // option_to_ptr( o.map(|o| o.pkaj))
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_ae_encode_private_key( key : &PrivateKey) -> *mut c_char {
    // to_json_cstring( &PKAJ{pkaj: key})
    unimplemented!()
}

#[no_mangle]
/// Returns null if None.
pub extern fn rs_ae_decode_private_key( encoded : *const c_char) -> *mut PrivateKey {
    // let o : Option<PKAJ<PrivateKey>> = from_json_cstr( encoded);
    // option_to_ptr( o.map(|o| o.pkaj))
    unimplemented!()
}

