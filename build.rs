extern crate cbindgen;

use cbindgen::*;

fn main() {
    Builder::new()
      .with_crate(".")
      .with_language( Language::C)
      .with_parse_deps( true)
      .with_parse_include(&["ring","pkauth"])
      .with_documentation( false)
      // .with_std_types( true)
      .generate()
      .expect("Unable to generate bindings")
      .write_to_file("target/pkauth.h");


//     cheddar::Cheddar::new().expect("could not read manifest")
//         .run_build("target/include/libpkauth_c.h");
}
