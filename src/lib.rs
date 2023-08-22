/*!
This crate provides bindings to my [Shamir secret sharing library][sss].

The main functions to use are [`create_shares`] and [`combine_shares`].

*The [`hazmat`] module is for experts.* The functions in the `hazmat` module miss some security
guarantees, so do not use them unless you really know what you are doing.

Encapsulated in the `SSSResult`, [`combine_shares`] will return an `Option<_>` which will be
`Some(data)` if the data could be restored. If the data could not be restored, [`combine_shares`]
will return `Ok(None)`. This means that could mean either of:

1. More shares were needed to reach the treshold.
2. Shares of different sets (corresponding to different secrets) were supplied or some of the
   shares were tampered with.

[`hazmat`]: hazmat/index.html
[`create_shares`]: fn.create_shares.html
[`combine_shares`]: fn.combine_shares.html

# Example

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

This library supports can generate sets with at most `count` and a `treshold` shares.

[sss]: https://github.com/dsprenkels/sss
*/

#![warn(missing_docs)]

extern crate rand;
extern crate crypto_secretbox;
use hazmat::{KEYSHARE_SIZE, KEY_SIZE};
use std::error;
use std::fmt;
use crypto_secretbox::{
    aead::{Aead, KeyInit},
    XSalsa20Poly1305,
};

/// Custom error types for errors originating from this crate
#[derive(Debug, PartialEq, Eq)]
pub enum SSSError {
    /// The `n` parameter was invalid
    InvalidN(u8),
    /// The `k` parameter was invalid
    InvalidK(u8),
    /// There was a (key)share that had an invalid length
    BadShareLen((usize, usize)),
    /// The input supplied to a function had an incorrect length
    BadInputLen(usize),
}

/// The size of the input data to `create_shares`
pub const DATA_SIZE: usize = 64;
/// Regular share size from shares produced by `create_shares`
pub const SHARE_SIZE: usize = 113;

impl fmt::Display for SSSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SSSError::*;
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            InvalidN(n) => write!(f, "Error: invalid share count ({})", n),
            InvalidK(k) => write!(f, "Error: invalid treshold ({})", k),
            BadShareLen((i, x)) => write!(f, "Error: share {} has bad length ({})", i, x),
            BadInputLen(x) => write!(f, "Error: bad input length ({})", x),
        }
    }
}

impl error::Error for SSSError {
    fn description(&self) -> &str {
        use SSSError::*;
        match *self {
            InvalidN(_) => "invalid n",
            InvalidK(_) => "invalid k",
            BadShareLen(_) => "bad share length",
            BadInputLen(_) => "bad input length",
        }
    }
}

type SSSResult<T> = Result<T, SSSError>;

/// Check the parameters `n` and `k` and return `Ok(())` if they were valid
fn check_nk(n: u8, k: u8) -> SSSResult<()> {
    if n < 1 {
        return Err(SSSError::InvalidN(n));
    }
    if k < 1 || k > n {
        return Err(SSSError::InvalidK(k));
    }
    Ok(())
}

/// Check `data` and return `Ok(())` if its length is correct for being shared with
/// `create_shares`
fn check_data_len(data: &[u8]) -> SSSResult<()> {
    if data.len() != DATA_SIZE {
        Err(SSSError::BadInputLen(data.len()))
    } else {
        Ok(())
    }
}

/**
Create a set of shares

- `data` must be a `&[u8]` slice of length `DATA_SIZE` (64)
- `n` is the number of shares that is to be generated
- `k` is the treshold value of how many shares are needed to restore the secret

The value that is returned is a newly allocated vector of vectors. Each of these vectors will
contain `SHARE_SIZE` `u8` items.

# Example
```
use shamirsecretsharing::*;

// Create a some shares over the secret data `[42, 42, 42, ...]`
let data = vec![42; DATA_SIZE];
let count = 5;
let treshold = 4;
let shares = create_shares(&data, count, treshold);
match shares {
    Ok(shares) => println!("Created some shares: {:?}", shares),
    Err(err) => panic!("Oops! Something went wrong: {}", err),
}
```
*/
pub fn create_shares(data: &[u8], n: u8, k: u8) -> SSSResult<Vec<Vec<u8>>> {
    check_nk(n, k)?;
    check_data_len(data)?;

    let key = rand::random::<[u8; KEY_SIZE]>();
    let mut shares = hazmat::create_keyshares(&key, n, k)?;
    let cipher = XSalsa20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(&[0; XSalsa20Poly1305::NONCE_SIZE].into(), data)
        .expect("xsalsa20poly1305 encryption error");
    for share in shares.iter_mut() {
        share.extend_from_slice(&ciphertext);
    }
    Ok(shares)
}

/**
Combine a set of shares and return the original secret

`shares` must be a slice of share vectors.

The return type will be a `Result` which will only be `Err(err)` of the input shares were
malformed. When the input shares are of the correct length, this function will always return
`Ok(_)`.

Attempts at restoring a secret may fail. Then `combine_shares` will return `Ok(None)`. This only
cases in which this can happen are:

1. More shares were needed to reach the treshold.
2. Shares of different sets (corresponding to different secrets) were supplied or some of the
   shares were tampered with.

If the shares were correct---and a secret could be restored---this function will return
`Ok(Some(data))`, with `data` being a vector of `u8`s. This `data` will be the same length as When
it was shared, namely `DATA_SIZE` (64) bytes.

# Example

```rust
use shamirsecretsharing::*;

# let mut shares = create_shares(&vec![42; DATA_SIZE], 3, 3).unwrap();
// When `shares` contains a set of valid shares
let restored = combine_shares(&shares).unwrap();
let data = restored.expect("`shares` did not contain a valid set of shares");
println!("Restored some data: {:?}", data);

# // Remove a share s.t. the treshold is not reached
# shares.pop();
// When `shares` contains an invalid set of shares
let restored = combine_shares(&shares).unwrap();
assert_eq!(restored, None);
```
*/
pub fn combine_shares(shares: &[Vec<u8>]) -> SSSResult<Option<Vec<u8>>> {
    for (i, share) in shares.iter().enumerate() {
        if share.len() != SHARE_SIZE {
            return Err(SSSError::BadShareLen((i, share.len())));
        }
    }

    let mut keyshares = Vec::with_capacity(shares.len());
    for share in shares.iter() {
        keyshares.push(share[..KEYSHARE_SIZE].to_owned());
    }
    let key_vec = hazmat::combine_keyshares(&keyshares)?;
    let mut key = [0; KEY_SIZE];
    key.copy_from_slice(&key_vec);
    let cipher = XSalsa20Poly1305::new(&key.into());
    for share in shares.iter() {
        let ciphertext = &share[KEYSHARE_SIZE..];
        let nonce = [0; XSalsa20Poly1305::NONCE_SIZE];
        if let Ok(plaintext) = cipher.decrypt(&nonce.into(), ciphertext) {
            return Ok(Some(plaintext));
        }
    }
    Ok(None)
}

pub mod hazmat {
    /*!
    Hazardous materials (key-sharing)

    This is the `hazmat` module. This stands for **hazardous materials**. This module is only to
    be used by experts, because it does not have all the straightforward guarantees that the
    normal API has. E.g. where the [normal API](../index.html) prevents tampering with the shares,
    this API does not do any integrity checks, etc. Only use this module when you are really sure
    that Shamir secret sharing is secure in your use case! _If you are not sure about this, you
    are probably lost ([go back](../index.html))._

    Example stuff that you will need to guarantee when using this API (not exhaustive):

    - All shared keys are uniformly random.
    - Keys produced by [`combine_keyshares`] are kept secret even if they did not manage to restore
      a secret.
    - _You_ will check the integrity of the restored secrets (or integrity is not a requirement).

    When your security model actually allows you to use the `hazmat` module, it can be a very
    powerful tool. In the normal API, the library wraps the secret data for the user in an AEAD
    `crypto_secretbox`. This guarantees the security items above. The `hazmat` module exposes the
    low level *key-sharing* API which allows you to bypass the AEAD wrapper leaving you with shares
    that are a lot shorter (useful for sharing bitcoin secret keys). You can also implement you own
    AEAD wrapper so that you can secret-share arbitrary long streams of data.

    ## Sharing data of arbitrary length

    [`create_shares`](../fn.create_shares.html) only shares buffers of exactly 64 bytes, which is
    of course quite limiting. However when using the keysharing module you can use an AEAD wrapper
    and share buffers of arbitrary length. I think an example is in place:

    ```
    extern crate chacha20_poly1305_aead;
    extern crate rand;
    extern crate shamirsecretsharing;

    use chacha20_poly1305_aead::{encrypt, decrypt};
    use shamirsecretsharing::hazmat::{create_keyshares, combine_keyshares};

    /// Stores an encrypted message with a message authentication tag
    struct CryptoSecretbox {
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
    }

    /// AEAD encrypt the message with `key`
    fn aead_wrap(key: &[u8], text: &[u8]) -> CryptoSecretbox {
        let nonce = vec![0; 12];
        let mut ciphertext = Vec::with_capacity(text.len());
        let tag = encrypt(&key, &nonce, &[], text, &mut ciphertext).unwrap().to_vec();
        CryptoSecretbox { ciphertext: ciphertext, tag: tag }
    }

    /// AEAD decrypt the message with `key`
    fn aead_unwrap(key: &[u8], boxed: CryptoSecretbox) -> Vec<u8> {
        let CryptoSecretbox { ciphertext: ciphertext, tag: tag } = boxed;
        let nonce = vec![0; 12];
        let mut text = Vec::with_capacity(ciphertext.len());
        decrypt(&key, &nonce, &[], &ciphertext, &tag, &mut text).unwrap();
        text
    }

    fn main() {
        let text = b"Snape kills Dumbledore!"; // Secret message
        let (boxed, keyshares) = {
            // Generate an ephemeral key
            let ref key = rand::random::<[u8; 32]>();

            // Encrypt the text using the key
            let boxed = aead_wrap(key, text);

            // Share the key using `create_keyshares`
            let keyshares = create_keyshares(key, 2, 2).unwrap();

            (boxed, keyshares)
        };

        let restored = {
            // Recover the key using `combine_keyshares`
            let key = combine_keyshares(&keyshares).unwrap();

            // Decrypt the secret message using the restored key
            aead_unwrap(&key, boxed)
        };

        assert_eq!(restored, text);
    }
    ```

    ## Sharing differently sized keys

    A keyshare is a string of 33 bytes. The first byte denotes the `x` coordinate in the Shamir
    secret sharing scheme. This `x`-coordinate can be viewed as the share "tag". The other 32
    bytes hold the actual data. Each byte of a keyshare corresponds to the same byte in the secret
    key. They are independent from one another.
    This makes it possible to share keys that are not necesarrily 32 bytes long, by truncating the
    shares. For example:

    ```
    use shamirsecretsharing::hazmat::*;

    fn pad<T: Default>(vec: &mut Vec<T>, desired_len: usize) {
        while vec.len() < desired_len {
            vec.push(Default::default());
        }
    }

    let short_key = [42; 16]; // `key` holds a 128 bit key (16 bytes)
    let mut key = [0; KEY_SIZE];
    &mut key[..16].copy_from_slice(&short_key);

    // Split the key into keyshares
    let mut keyshares = create_keyshares(&key, 3, 3).unwrap();

    // The keyshares are 33 bytes long, only store the first 17 bytes (1 + 16 for x and y's)
    for mut keyshare in &mut keyshares {
        keyshare.truncate(17);  // Truncate the last keyshare bytes
        pad(&mut keyshare, 33); // and put zeros in place
    }

    // Restore the key
    let restored = combine_keyshares(&keyshares).unwrap();
    assert_eq!(restored, key);
    ```
    The same trick is possible with keys that are longer than 32 bytes, to secret-share long keys
    in a streaming manner. But remember that the key must be uniformly random if you do not trust
    *all* the shareholders (which you probably don't otherwise you would not be using this crate).
    (In other words: Do not use this to share RSA keys, use an AEAD wrapper instead!)

    You might guess that this approach kills performance by a factor of 2, but this is not really
    true. Like a block cipher `sss` library performs all cryptographic computations in parrallel
    with block sizes of 32 bytes. Below 32 bytes we will still have to compute one block, so we
    cannot gain an additional speedup by secret-sharing less than 32 bytes of key material.

    I agree that with all this truncating and padding the code looks a bit messy, but I do not
    consider these kinds of tricks really considered mainstream anyway.

    [`create_keyshares`]: fn.create_keyshares.html
    [`combine_keyshares`]: fn.combine_keyshares.html
    */

    use super::*;

    /// The size of the input data to `create_keyshares`
    pub const KEY_SIZE: usize = 32;

    /// Keyshare size from shares produced by `create_keyshares`
    pub const KEYSHARE_SIZE: usize = 33;

    /// Check `key` and return `Ok(())` if its length is correct for being shared with
    /// `create_keyshares`
    fn check_key_len(key: &[u8]) -> SSSResult<()> {
        if key.len() != KEY_SIZE {
            Err(SSSError::BadInputLen(key.len()))
        } else {
            Ok(())
        }
    }

    /**
    Create a set of key shares

    - `key` must be a `&[u8]` slice of length `DATA_SIZE` (32)
    - `n` is the number of shares that is to be generated
    - `k` is the treshold value of how many shares are needed to restore the secret

    The value that is returned is a newly allocated vector of vectors. Each of these vectors will
    contain `KEYSHARE_SIZE` `u8` items.

    # Example
    ```
    use shamirsecretsharing::hazmat::*;

    # let key = [42; KEY_SIZE];
    // With a `key` vector containing a uniform key

    // Create a some key shares of the secret key
    let count = 5;
    let treshold = 4;
    let keyshares = create_keyshares(&key, count, treshold);
    match keyshares {
        Ok(keyshares) => println!("Created some keyshares: {:?}", keyshares),
        Err(err) => panic!("Oops! Something went wrong: {}", err),
    }
    ```
    */
    pub fn create_keyshares(key: &[u8], n: u8, k: u8) -> SSSResult<Vec<Vec<u8>>> {
        check_nk(n, k)?;
        check_key_len(key)?;

        let mut key_arr = [0; KEY_SIZE];
        key_arr.copy_from_slice(key);

        // Restore the keyshares into one buffer
        let mut keyshares = Vec::with_capacity(n.into());

        // Put the secret in the bottom part of the polynomial
        let poly0 = gf256::bitslice(&key_arr);

        // Randomly generate the other terms in the polynomial
        let mut poly = vec![gf256::Poly::default(); (k - 1).into()];
        for coeff in poly.iter_mut() {
            *coeff = rand::random();
        }

        for share_idx in 0..n {
            // x value is in 1..n
            let unbitsliced_x = share_idx + 1;
            let x = gf256::splat(unbitsliced_x);

            // Calculate y
            let mut y = poly0;
            let mut xpow = gf256::splat(1);
            for coeff_idx in 0..(k - 1).into() {
                xpow = gf256::mul(&xpow, &x);
                let tmp = gf256::mul(&xpow, &poly[coeff_idx]);
                y = gf256::add(&y, &tmp);
            }
            let y_unbitsliced = gf256::unbitslice(&y);
            let mut keyshare = vec![0; KEYSHARE_SIZE];
            keyshare[0] = unbitsliced_x;
            keyshare[1..].copy_from_slice(&y_unbitsliced);
            keyshares.push(keyshare);
        }
        Ok(keyshares)
    }

    /**
    Combine a set of key shares and return the original key

    `keyshares` must be a slice of keyshare vectors.

    The return type will be a `Result` which will only be `Err(err)` of the input key shares were
    malformed. When the input key shares are of the correct length, this function will always
    return `Ok(_)`.

    Restoring the secret will fail in the same cases as with `combine_shares`:

    1. More shares were needed to reach the treshold.
    2. Shares of different sets (corresponding to different keys) were supplied or some of the
       keyshares were tampered with.

    Opposed to `combine_shares`, this function will always return a restored key buffer. This
    restored key MAY be correct. The function just performs the cryptographic calculation, but
    does not know if restoration succeeded. However, **treat all output from this function as
    secret**. Even if combining the key shares failed, the returned buffer can tell an attacker
    information of the shares that were used to make it. The best way to secure this is by using
    a cryptographic integrity check to secure the integrity of the key.

    # Example

    ```rust
    use shamirsecretsharing::hazmat::*;

    # let mut key = [42; KEY_SIZE];
    # let mut keyshares = create_keyshares(&key, 3, 3).unwrap();
    // When `keyshares` contains a set of valid shares for `key`
    let restored = combine_keyshares(&keyshares).unwrap();
    assert_eq!(restored, key);

    # // Remove a key share s.t. the treshold is not reached
    # keyshares.pop();
    // When `keyshares` contains an invalid set of key shares
    let restored = combine_keyshares(&keyshares).unwrap();
    assert_ne!(restored, key);
    ```
    */
    pub fn combine_keyshares(keyshares: &[Vec<u8>]) -> SSSResult<Vec<u8>> {
        for (i, keyshare) in keyshares.iter().enumerate() {
            if keyshare.len() != KEYSHARE_SIZE {
                return Err(SSSError::BadShareLen((i, keyshare.len())));
            }
        }

        // Collect the x and y values.
        let k = keyshares.len();
        let mut xs = Vec::with_capacity(k);
        let mut ys = Vec::with_capacity(k);
        for keyshare in keyshares.iter() {
            xs.push(gf256::splat(keyshare[0]));
            let mut y_arr = [0; 32];
            y_arr.copy_from_slice(&keyshare[1..]);
            ys.push(gf256::bitslice(&y_arr));
        }

        let mut secret = gf256::Poly::default();
        for (idx1, (x1, y)) in Iterator::zip(xs.iter(), ys.iter()).enumerate() {
            let mut num = gf256::splat(1);
            let mut denom = gf256::splat(1);
            for (idx2, x2) in xs.iter().enumerate() {
                if idx1 == idx2 {
                    continue;
                }
                num = gf256::mul(&num, x2);
                let tmp = gf256::add(x1, x2);
                denom = gf256::mul(&denom, &tmp);
            }
            let denom_inv = gf256::inv(denom); // Inverted denominator
            let basis = gf256::mul(&num, &denom_inv); // Basis polynomial
            let scaled_coeff = gf256::mul(&basis, y);
            secret = gf256::add(&secret, &scaled_coeff);
        }
        let key = gf256::unbitslice(&secret);
        Ok(key.into())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        const KEY: [u8; KEY_SIZE] = [42; KEY_SIZE];

        #[test]
        fn test_create_keyshares_ok() {
            let keyshares = create_keyshares(&KEY, 5, 4).unwrap();
            assert_eq!(keyshares.len(), 5);
            for keyshare in keyshares {
                assert_eq!(keyshare.len(), KEYSHARE_SIZE);
            }
        }

        #[test]
        fn test_create_keyshares_err() {
            assert_eq!(create_keyshares(&KEY, 0, 0), Err(SSSError::InvalidN(0)));
            assert_eq!(create_keyshares(&KEY, 5, 0), Err(SSSError::InvalidK(0)));
            assert_eq!(create_keyshares(&KEY, 5, 6), Err(SSSError::InvalidK(6)));
            assert_eq!(create_keyshares(&[], 5, 3), Err(SSSError::BadInputLen(0)));
        }

        #[test]
        fn test_combine_keyshares_ok() {
            let mut keyshares = create_keyshares(&KEY, 5, 4).unwrap();
            assert_eq!(combine_keyshares(&keyshares).unwrap(), KEY);
            keyshares.pop();
            assert_eq!(combine_keyshares(&keyshares).unwrap(), KEY);
            keyshares.pop();
            assert_ne!(combine_keyshares(&keyshares).unwrap(), KEY);
            keyshares.pop();
            assert_ne!(combine_keyshares(&keyshares).unwrap(), KEY);
            keyshares.pop();
            assert_ne!(combine_keyshares(&keyshares).unwrap(), KEY);
            keyshares.pop();
            assert_ne!(combine_keyshares(&keyshares).unwrap(), KEY);
        }

        #[test]
        fn test_combine_keyshares_err() {
            let keyshares = vec![vec![]];
            assert_eq!(
                combine_keyshares(&keyshares),
                Err(SSSError::BadShareLen((0, 0)))
            );
        }
    }
}

mod gf256 {
    pub type Poly = [u32; 8];

    #[must_use]
    pub fn bitslice(x: &[u8; 32]) -> Poly {
        let mut r = [0u32; 8];
        for (arr_idx, cur) in x.iter().enumerate() {
            for bit_idx in 0..8 {
                r[bit_idx] |= ((*cur as u32 >> bit_idx) & 1) << arr_idx;
            }
        }
        r
    }

    #[must_use]
    pub fn unbitslice(x: &Poly) -> [u8; 32] {
        let mut r = [0; 32];
        for bit_idx in 0..8 {
            let cur = x[bit_idx] as u32;
            for (arr_idx, b) in r.iter_mut().enumerate() {
                *b |= (((cur >> arr_idx) & 1) as u8) << bit_idx;
            }
        }
        r
    }

    #[must_use]
    pub fn splat(x: u8) -> Poly {
        let mut r = Poly::default();
        for (idx, cur) in r.iter_mut().enumerate() {
            let bit = u32::from(x) >> idx & 0x1;
            let (expand, _) = 0_i32.overflowing_sub(bit as i32);
            *cur = expand as u32;
        }
        r
    }

    /// Add (XOR) `r` with `x` and store the result in `r`.
    #[must_use]
    pub fn add(x1: &Poly, x2: &Poly) -> Poly {
        let mut r = *x1;
        let iter = Iterator::zip(r.iter_mut(), x2.iter());
        for (acc, rhs) in iter {
            *acc ^= *rhs;
        }
        r
    }

    /// Safely multiply two bitsliced polynomials in GF(2^8) reduced by
    /// x^8 + x^4 + x^3 + x + 1. If you need to square a polynomial
    /// use `gf256::square` instead.
    #[must_use]
    pub fn mul(a: &Poly, b: &Poly) -> Poly {
        // This function implements Russian Peasant multiplication on two
        // bitsliced polynomials.
        //
        // I personally think that these kinds of long lists of operations
        // are often a bit ugly. A double for loop would be nicer and would
        // take up a lot less lines of code.
        // However, some compilers seem to fail in optimizing these kinds of
        // loops. So we will just have to do this by hand.
        //
        let mut a = *a;
        let mut r = [0; 8];

        r[0] = a[0] & b[0]; // add (assignment, because r is 0)
        r[1] = a[1] & b[0];
        r[2] = a[2] & b[0];
        r[3] = a[3] & b[0];
        r[4] = a[4] & b[0];
        r[5] = a[5] & b[0];
        r[6] = a[6] & b[0];
        r[7] = a[7] & b[0];
        a[0] ^= a[7]; // reduce
        a[2] ^= a[7];
        a[3] ^= a[7];

        r[0] ^= a[7] & b[1]; // add
        r[1] ^= a[0] & b[1];
        r[2] ^= a[1] & b[1];
        r[3] ^= a[2] & b[1];
        r[4] ^= a[3] & b[1];
        r[5] ^= a[4] & b[1];
        r[6] ^= a[5] & b[1];
        r[7] ^= a[6] & b[1];
        a[7] ^= a[6]; // reduce
        a[1] ^= a[6];
        a[2] ^= a[6];

        r[0] ^= a[6] & b[2]; // add
        r[1] ^= a[7] & b[2];
        r[2] ^= a[0] & b[2];
        r[3] ^= a[1] & b[2];
        r[4] ^= a[2] & b[2];
        r[5] ^= a[3] & b[2];
        r[6] ^= a[4] & b[2];
        r[7] ^= a[5] & b[2];
        a[6] ^= a[5]; // reduce
        a[0] ^= a[5];
        a[1] ^= a[5];

        r[0] ^= a[5] & b[3]; // add
        r[1] ^= a[6] & b[3];
        r[2] ^= a[7] & b[3];
        r[3] ^= a[0] & b[3];
        r[4] ^= a[1] & b[3];
        r[5] ^= a[2] & b[3];
        r[6] ^= a[3] & b[3];
        r[7] ^= a[4] & b[3];
        a[5] ^= a[4]; // reduce
        a[7] ^= a[4];
        a[0] ^= a[4];

        r[0] ^= a[4] & b[4]; // add
        r[1] ^= a[5] & b[4];
        r[2] ^= a[6] & b[4];
        r[3] ^= a[7] & b[4];
        r[4] ^= a[0] & b[4];
        r[5] ^= a[1] & b[4];
        r[6] ^= a[2] & b[4];
        r[7] ^= a[3] & b[4];
        a[4] ^= a[3]; // reduce
        a[6] ^= a[3];
        a[7] ^= a[3];

        r[0] ^= a[3] & b[5]; // add
        r[1] ^= a[4] & b[5];
        r[2] ^= a[5] & b[5];
        r[3] ^= a[6] & b[5];
        r[4] ^= a[7] & b[5];
        r[5] ^= a[0] & b[5];
        r[6] ^= a[1] & b[5];
        r[7] ^= a[2] & b[5];
        a[3] ^= a[2]; // reduce
        a[5] ^= a[2];
        a[6] ^= a[2];

        r[0] ^= a[2] & b[6]; // add
        r[1] ^= a[3] & b[6];
        r[2] ^= a[4] & b[6];
        r[3] ^= a[5] & b[6];
        r[4] ^= a[6] & b[6];
        r[5] ^= a[7] & b[6];
        r[6] ^= a[0] & b[6];
        r[7] ^= a[1] & b[6];
        a[2] ^= a[1]; // reduce
        a[4] ^= a[1];
        a[5] ^= a[1];

        r[0] ^= a[1] & b[7]; // add
        r[1] ^= a[2] & b[7];
        r[2] ^= a[3] & b[7];
        r[3] ^= a[4] & b[7];
        r[4] ^= a[5] & b[7];
        r[5] ^= a[6] & b[7];
        r[6] ^= a[7] & b[7];
        r[7] ^= a[0] & b[7];

        r
    }

    /// Square `x` in GF(2^8) and write the result to `r`.
    #[must_use]
    pub fn square(x: &Poly) -> Poly {
        let mut r = [0; 8];
        let r14;
        let r12;
        let mut r10;
        let mut r8;

        // Use the Freshman's Dream rule to square the polynomial.
        r14 = x[7];
        r12 = x[6];
        r10 = x[5];
        r8 = x[4];
        r[6] = x[3];
        r[4] = x[2];
        r[2] = x[1];
        r[0] = x[0];

        // Reduce with  x^8 + x^4 + x^3 + x + 1 until order is less than 8
        r[7] = r14; // r[7] was 0
        r[6] ^= r14;
        r10 ^= r14;
        // Skip, because r13 is always 0
        r[4] ^= r12;
        r[5] = r12; // r[5] was 0
        r[7] ^= r12;
        r8 ^= r12;
        // Skip, because r11 is always 0
        r[2] ^= r10;
        r[3] = r10; // r[3] was 0
        r[5] ^= r10;
        r[6] ^= r10;
        r[1] = r14; // r[1] was 0
        r[2] ^= r14; // Substitute r9 by r14 because they will always be equa
        r[4] ^= r14;
        r[5] ^= r14;
        r[0] ^= r8;
        r[1] ^= r8;
        r[3] ^= r8;
        r[4] ^= r8;

        r
    }

    /// Invert `x` in GF(2^8) and write the result to `r`
    #[must_use]
    pub fn inv(x: Poly) -> Poly {
        let v1 = square(&x); // v1 = x^2
        let v2 = square(&v1); // v2 = x^4
        let v3 = square(&v2); // v3 = x^8
        let v4 = mul(&v3, &x); // v4 = x^9
        let v5 = square(&v3); // v5 = x^16
        let v6 = mul(&v5, &v4); // v6 = x^25
        let v7 = square(&v6); // v7 = x^50
        let v8 = square(&v7); // v8 = x^100
        let v9 = square(&v8); // v9 = x^200
        let v10 = mul(&v7, &v9); // v10 = x^250
        let v11 = mul(&v10, &v2); // v11 = x^254
        v11
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    const DATA: &[u8] = &[42; DATA_SIZE];

    #[test]
    fn test_create_shares_ok() {
        let shares = create_shares(DATA, 5, 4).unwrap();
        assert_eq!(shares.len(), 5);
        for share in shares {
            assert_eq!(share.len(), SHARE_SIZE);
        }
    }

    #[test]
    fn test_create_shares_err() {
        assert_eq!(create_shares(DATA, 0, 0), Err(SSSError::InvalidN(0)));
        assert_eq!(create_shares(DATA, 5, 0), Err(SSSError::InvalidK(0)));
        assert_eq!(create_shares(DATA, 5, 6), Err(SSSError::InvalidK(6)));
        assert_eq!(create_shares(&[], 5, 3), Err(SSSError::BadInputLen(0)));
    }

    #[test]
    fn test_combine_shares_ok() {
        let mut shares = create_shares(DATA, 5, 4).unwrap();
        assert_eq!(combine_shares(&shares).unwrap().unwrap(), DATA);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap().unwrap(), DATA);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap(), None);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap(), None);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap(), None);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap(), None);
    }

    #[test]
    fn test_combine_shares_err() {
        let shares = vec![vec![]];
        assert_eq!(combine_shares(&shares), Err(SSSError::BadShareLen((0, 0))));
    }

    #[test]
    fn test_sss_error_display() {
        assert_eq!(
            format!("{}", SSSError::InvalidN(5)),
            "Error: invalid share count (5)"
        );
        assert_eq!(
            format!("{}", SSSError::InvalidK(3)),
            "Error: invalid treshold (3)"
        );
        assert_eq!(
            format!("{}", SSSError::BadShareLen((1, 2))),
            "Error: share 1 has bad length (2)"
        );
        assert_eq!(
            format!("{}", SSSError::BadInputLen(0)),
            "Error: bad input length (0)"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_sss_error_description() {
        assert_eq!(SSSError::InvalidN(5).description(), "invalid n");
        assert_eq!(SSSError::InvalidK(3).description(), "invalid k");
        assert_eq!(
            SSSError::BadShareLen((0, 0)).description(),
            "bad share length"
        );
        assert_eq!(SSSError::BadInputLen(0).description(), "bad input length");
    }

    #[test]
    fn test_splat() {
        let expected = [!0, 0, 0, 0, 0, 0, 0, 0];
        let actual = gf256::splat(1);
        assert_eq!(actual, expected);
    }
}
