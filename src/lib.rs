/*!
This crate provides bindings to my [Shamir secret sharing library][sss].

The main functions to use are `create_shares` and `combine_shares`.

*The `hazmat` module is for experts.* The functions in the `hazmat` module miss some security
guarantees, so do not use them unless you really know what you are doing.

Encapsulated in the `SSSResult`, `combine_shares` will return an `Option<_>` which will be
`Some(data)` if the data could be restored. If the data could not be restored, `combine_shares`
will return `Ok(None)`. This means that could mean either of:

1. More shares were needed to reach the treshold.
2. Shares of different sets (corresponding to different secrets) were supplied or some of the
   shares were tampered with.

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

extern crate libc;
#[link(name = "sss", kind = "static")]

use libc::{uint8_t, c_int};
use std::error;
use std::fmt;

/// Custom error types for errors originating from this crate
#[derive(Debug, PartialEq, Eq)]
pub enum SSSError {
    /// The `n` parameter was invalid
    InvalidN(u8),
    /// The `n` parameter was invalid
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


extern "C" {
    fn sss_create_shares(out: *mut uint8_t, data: *const uint8_t, n: uint8_t, k: uint8_t);
    fn sss_combine_shares(data: *mut uint8_t, shares: *const uint8_t, k: uint8_t) -> c_int;
}


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


/// Return a closure which groups elements into a new Vec `acc` in-place
///
/// This function is to be used in combination with `fold`. See `tests::group` for an example.
fn group<T>(group_size: usize) -> Box<Fn(Vec<Vec<T>>, T) -> Vec<Vec<T>>> {
    Box::new(move |mut acc, x| {
        if acc.last().map_or(false, |x| x.len() < group_size) {
            acc.last_mut().unwrap().push(x);
        } else {
            let mut new_group = Vec::with_capacity(group_size);
            new_group.push(x);
            acc.push(new_group);
        }
        acc
    })
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
    try!(check_nk(n, k));
    try!(check_data_len(data));

    // Restore the shares into one buffer
    let mut tmp = vec![0; SHARE_SIZE * (n as usize)];
    unsafe {
        sss_create_shares(tmp.as_mut_ptr(), data.as_ptr(), n, k);
    }

    // Put each share in a separate Vec
    Ok(tmp.into_iter()
           .fold(Vec::with_capacity(n as usize), &*group(SHARE_SIZE)))
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

    // Dedup the shares
    let mut shares = Vec::from(shares);
    shares.sort();
    shares.dedup();

    // Build a slice containing all the shares sequentially
    let mut tmp = Vec::with_capacity(SHARE_SIZE * shares.len());
    for share in &shares {
        tmp.extend(share.iter());
    }

    // Combine the shares
    let mut data = vec![0; DATA_SIZE];
    let ret =
        unsafe { sss_combine_shares(data.as_mut_ptr(), tmp.as_mut_ptr(), shares.len() as uint8_t) };

    match ret {
        0 => Ok(Some(data)),
        _ => Ok(None),
    }
}


pub mod hazmat {
    /*!
    Hazardous materials (key-sharing)

    This is the `hazmat` module. This stands for **hazardous materials**. This module is only to
    be used for experts, because it does not have all the straightforward guarantees that the
    normal API has. E.g. where the [normal API](../index.html) prevents tampering with the shares,
    this API does not do any integrity checks, etc. Only use this module when you are really sure
    that Shamir secret sharing is secure in your use case! _If you are not sure about this, you
    are probably lost ([go back](../index.html))._

    Example stuff that you will need to guarantee when using this API (not exhaustive):

    - All shared keys are uniformly random.
    - Keys produced by `combine_keyshares` are kept secret even if they did not manage to restore
      a secret.
    - _You_ will check the integrity of the restored secrets (or integrity is not a requirement).
    */

    use libc::uint8_t;
    use super::*;

    extern "C" {
        fn sss_create_keyshares(out: *mut uint8_t, key: *const uint8_t, n: uint8_t, k: uint8_t);
        fn sss_combine_keyshares(key: *mut uint8_t, shares: *const uint8_t, k: uint8_t);
    }

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

    # let key = vec![42; KEY_SIZE];
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
        try!(check_nk(n, k));
        try!(check_key_len(key));

        // Restore the keyshares into one buffer
        let mut tmp = vec![0; KEYSHARE_SIZE * (n as usize)];
        unsafe {
            sss_create_keyshares(tmp.as_mut_ptr(), key.as_ptr(), n, k);
        }

        // Put each share in a separate Vec
        Ok(tmp.into_iter()
               .fold(Vec::with_capacity(n as usize), &*group(KEYSHARE_SIZE)))
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

    # let mut key = vec![42; KEY_SIZE];
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

        // Build a slice containing all the keyshares sequentially
        let mut tmp = Vec::with_capacity(KEYSHARE_SIZE * keyshares.len());
        for keyshare in keyshares {
            tmp.extend(keyshare.iter());
        }

        // Combine the keyshares
        let mut key = vec![0; KEY_SIZE];
        unsafe {
            sss_combine_keyshares(key.as_mut_ptr(),
                                  tmp.as_mut_ptr(),
                                  keyshares.len() as uint8_t);
        };

        Ok(key)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        const KEY: &[u8] = &[42; KEY_SIZE];

        #[test]
        fn test_create_keyshares_ok() {
            let keyshares = create_keyshares(KEY, 5, 4).unwrap();
            assert_eq!(keyshares.len(), 5);
            for keyshare in keyshares {
                assert_eq!(keyshare.len(), KEYSHARE_SIZE);;
            }
        }

        #[test]
        fn test_combine_keyshares_ok() {
            let mut keyshares = create_keyshares(KEY, 5, 4).unwrap();
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
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    const DATA: &[u8] = &[42; DATA_SIZE];

    #[test]
    fn test_group() {
        let dna = vec!['C', 'T', 'G', 'G', 'A', 'A', 'C', 'A', 'G'];
        let expected = vec![vec!['C', 'T', 'G'], vec!['G', 'A', 'A'], vec!['C', 'A', 'G']];

        let triplets = dna.into_iter().fold(Vec::new(), &*group(3));
        assert_eq!(triplets, expected);
    }

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
    fn test_combine_shares_dedup() {
        let mut shares = create_shares(DATA, 5, 4).unwrap();
        let dup = shares[3].clone();
        shares.push(dup);
        assert_eq!(combine_shares(&shares).unwrap().unwrap(), DATA);
    }
}
