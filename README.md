# Shamir secret sharing in Rust

[![Build Status](https://travis-ci.org/dsprenkels/sss-rs.svg?branch=master)](https://travis-ci.org/dsprenkels/sss-rs)
[![Coverage Status](https://coveralls.io/repos/github/dsprenkels/sss-rs/badge.svg?branch=master)](https://coveralls.io/github/dsprenkels/sss-rs?branch=master)
[![Docs](https://docs.rs/shamirsecretsharing/badge.svg)](https://docs.rs/shamirsecretsharing)

`sss-rs` contains Rust bindings for my [Shamir secret sharing library][sss].
This library allows users to split secret data into a number of different
shares. With the possession of some or all of these shares, the original secret
can be restored. ([Looking for the command line interface?][cli])

An example use case is a beer brewery which has a vault which contains their
precious super secret recipe. The 5 board members of this brewery do not trust
all the others well enough that they won't secretly break into the vault and
sell the recipe to a competitor. So they split the code into 5 shares, and
allow 4 shares to restore the original code. Now they are sure that the
majority of the staff will know when the vault is opened, but they can still
open the vault when one of the staff members is abroad or sick at home.

## Installation

```toml
[dependencies]
shamirsecretsharing = "0.1"
```

## Usage

Secrets are always supplied as `&[u8]` slices with a length of 64 items. Shares
are generated from a piece of secret data using the `create_shares` function and
shares can be afterwards be combined using `combine_shares`.

Shares are always 113 bytes long. Both `create_shares` and `combine_shares`
return a `Result<_, SSSError>` type. Errors will _only_ happen when invalid
parameters are supplied. When given valid parameters, these function will always
return `Ok(_)`. In the case of invalid parameters the error will be able to tell
you what went wrong.

```rust
use shamirsecretsharing::*;

// Create a some shares over the secret data `[42, 42, 42, ...]`
let data = vec![42; DATA_SIZE];
let count = 5;
let treshold = 4;
let mut shares = create_shares(&data, count, treshold).unwrap();

// Lose a share (for demonstrational purposes)
shares.remove(3);

// We still have 4 shares, so we should still be able to restore the secret
let restored = combine_shares(&shares).unwrap();
assert_eq!(restored, Some(data));

// If we lose another share the secret is lost
shares.remove(0);
let restored2 = combine_shares(&shares).unwrap();
assert_eq!(restored2, None);
```

## Changelog

### Version 0.1.1

- Remove an unintended side channel which allows a participating attacker with
  access to a accurate timing channel to iteratively guess shares during the
  execution of `combine_shares`.

### Version 0.1.5

- This library used to link to my `sss` library that was written in C.  From
  this version, the complete library is written only in Rust.
- The `have_libsodium` feature flag is deprecated.
- The minimum required rustc version is now 1.44.0.

### Version 0.1.7

- Use `crypto-secretbox` crate instead of `xsalsa20poly1305`
  ([#12](https://github.com/dsprenkels/sss-rs/pull/12)).

## Questions

Feel free to [open an issue](https://github.com/dsprenkels/sss-rs/issues/new)
or send me an email on my Github associated e-mail address.


[sss]: https://github.com/dsprenkels/sss
[cli]: https://github.com/dsprenkels/sss-cli
