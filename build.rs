extern crate cbindgen;

fn main() {
    cbindgen::Builder::new()
      .with_crate(".")
      .generate()
      .expect("Unable to generate bindings")
      .write_to_file("target/pkauth.h");


//     cheddar::Cheddar::new().expect("could not read manifest")
//         .run_build("target/include/libpkauth_c.h");
}
