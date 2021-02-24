extern crate cc;

fn main() {
    #[cfg(not(feature="have_libsodium"))]
    let sources = ["sss/sss.c", "sss/hazmat.c", "sss/randombytes.c", "sss/tweetnacl.c"];
    #[cfg(feature="have_libsodium")]
    let sources = ["sss/sss.c", "sss/hazmat.c", "sss/tweetnacl.c"];
    let  mut builder = cc::Build::new();
    builder.files(sources.iter());
    #[cfg(not(target_os = "windows"))]
    builder.flag("-Wno-sign-compare"); // Suppress sign warnings in tweetnacl.c
    builder.compile("libsss.a");
}
