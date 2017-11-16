
extern crate pkauth;
extern crate ring;

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
    let k = se::gen( rng, alg);
    k.ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
