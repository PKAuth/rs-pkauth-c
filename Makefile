IOS="../pkauth-ios-client/PKAuth/"

build-ios: src/lib.rs
	cargo lipo --release

deploy-ios:
	sed -i '' "s/typedef uint8_t PublicKey\[PUBLIC_KEY_LEN\];/typedef struct PublicKey PublicKey;/" target/pkauth_c.h && cp ./target/universal/release/libpkauth_c.a $(IOS) && cp target/pkauth_c.h $(IOS)


