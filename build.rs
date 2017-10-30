extern crate cc;

fn main() {
    let sources = ["sss/sss.c", "sss/hazmat.c", "sss/randombytes.c", "sss/tweetnacl.c"];
    cc::Build::new()
        .files(sources.iter())
        .flag("-Wno-sign-compare") // Suppress sign warnings in tweetnacl.c
        .compile("libsss.a");
}
