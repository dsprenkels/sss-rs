extern crate gcc;

fn main() {
    let sources = ["sss/sss.c", "sss/hazmat.c", "sss/randombytes.c", "sss/tweetnacl.c"];
    gcc::compile_library("libsss.a", &sources);
}
