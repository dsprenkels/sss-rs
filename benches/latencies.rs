#![feature(test)]

extern crate shamirsecretsharing;
extern crate test;

use test::Bencher;

use shamirsecretsharing as sss;

#[bench]
fn create_shares_54(b: &mut Bencher) {
    let data = vec![42; sss::DATA_SIZE];
    let count = 5;
    let threshold = 4;
    b.iter(|| {
        sss::create_shares(&data, count, threshold).unwrap();
    });
}

#[bench]
fn combine_shares_4(b: &mut Bencher) {
    let data = vec![42; sss::DATA_SIZE];
    let threshold = 4;
    let shares = sss::create_shares(&data, threshold, threshold).unwrap();
    b.iter(|| {
        sss::combine_shares(&shares).unwrap();
    });
}
#[bench]
fn create_keyshares_54(b: &mut Bencher) {
    let key = vec![42; sss::hazmat::KEY_SIZE];
    let count = 5;
    let threshold = 4;
    b.iter(|| {
        sss::hazmat::create_keyshares(&key, count, threshold).unwrap();
    });
}

#[bench]
fn combine_keyshares_4(b: &mut Bencher) {
    let key = vec![42; sss::hazmat::KEY_SIZE];
    let threshold = 4;
    let shares = sss::hazmat::create_keyshares(&key, threshold, threshold).unwrap();
    b.iter(|| {
        sss::hazmat::combine_keyshares(&shares).unwrap();
    });
}
