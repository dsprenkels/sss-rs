extern crate libc;
#[link(name = "sss", kind = "static")]

use libc::{uint8_t, c_int};
use std::error;
use std::fmt;


pub const DATA_SIZE: usize = 64;
pub const KEY_SIZE: usize = 32;
pub const SHARE_SIZE: usize = 113;
pub const KEYSHARE_SIZE: usize = 33;


#[derive(Debug, PartialEq, Eq)]
pub enum SSSError {
    InvalidN(u8),
    InvalidK(u8),
    BadShareLen((usize, usize)),
    BadDataLen(usize),
    BadKeyLen(usize),
}

impl fmt::Display for SSSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            SSSError::InvalidN(n) => write!(f, "Error: invalid share count ({})", n),
            SSSError::InvalidK(k) => write!(f, "Error: invalid treshold ({})", k),
            SSSError::BadShareLen((i, x)) => write!(f, "Error: share {} has bad length ({})", i, x),
            SSSError::BadDataLen(x) => write!(f, "Error: bad data length ({})", x),
            SSSError::BadKeyLen(x) => write!(f, "Error: bad key length ({})", x),
        }
    }
}

impl error::Error for SSSError {
    fn description(&self) -> &str {
        match *self {
            SSSError::InvalidN(_) => "invalid n",
            SSSError::InvalidK(_) => "invalid k",
            SSSError::BadShareLen(_) => "bad share length",
            SSSError::BadDataLen(_) => "bad data length",
            SSSError::BadKeyLen(_) => "bad key length",
        }
    }
}

extern {
    fn sss_create_shares(out: *mut uint8_t, data: *const uint8_t, n: uint8_t, k: uint8_t);
    fn sss_combine_shares(data: *mut uint8_t, shares: *const uint8_t, k: uint8_t) -> c_int;
    fn sss_create_keyshares(out: *mut uint8_t, key: *const uint8_t, n: uint8_t, k: uint8_t);
    fn sss_combine_keyshares(key: *mut uint8_t, shares: *const uint8_t, k: uint8_t);
}


fn check_nk(n: u8, k: u8) -> Result<(), SSSError> {
    if n < 1 {
        return Err(SSSError::InvalidN(n));
    }
    if k < 1 || k > n {
        return Err(SSSError::InvalidK(k));
    }
    Ok(())
}

fn check_data_len(data: &[u8]) -> Result<(), SSSError> {
    if data.len() != DATA_SIZE {
        Err(SSSError::BadDataLen(data.len()))
    } else {
        Ok(())
    }
}


fn check_key_len(key: &[u8]) -> Result<(), SSSError> {
    if key.len() != KEY_SIZE {
        Err(SSSError::BadKeyLen(key.len()))
    } else {
        Ok(())
    }
}


pub fn create_shares(data: &[u8], n: u8, k: u8) -> Result<Vec<Vec<u8>>, SSSError> {
    try!(check_nk(n, k));
    try!(check_data_len(data));

    // Restore the shares into one buffer
    let mut tmp = Vec::with_capacity(SHARE_SIZE * (n as usize));
    unsafe {
        sss_create_shares(tmp.as_mut_ptr(), data.as_ptr(), n, k);
        tmp.set_len(SHARE_SIZE * (n as usize)); // `sss_create_shares` has written to `tmp`
    }

    // This function groups the elements in `tmp` into a new Vec `acc` in-place.
    let group = |mut acc: Vec<Vec<_>>, x| {
        if acc.last().map_or(false, |x| x.len() < SHARE_SIZE) {
            acc.last_mut().unwrap().push(x);
        } else {
            let mut new_group = Vec::with_capacity(SHARE_SIZE);
            new_group.push(x);
            acc.push(new_group);
        }
        acc
    };

    // Put each share in a separate Vec
    Ok(tmp.into_iter().fold(Vec::with_capacity(n as usize), group))
}


pub fn combine_shares(shares: &Vec<Vec<u8>>) -> Result<Option<Vec<u8>>, SSSError> {
    for (i, share) in shares.iter().enumerate() {
        if share.len() != SHARE_SIZE {
            return Err(SSSError::BadShareLen((i, share.len())));
        }
    }

    // Build a slice containing all the shares sequentially
    let mut tmp = Vec::with_capacity(SHARE_SIZE * shares.len());
    for share in shares {
        tmp.extend(share.iter());
    }

    // Combine the shares
    let mut data = Vec::with_capacity(DATA_SIZE);
    let ret = unsafe {
        let ret = sss_combine_shares(data.as_mut_ptr(), tmp.as_mut_ptr(), shares.len() as uint8_t);
        data.set_len(DATA_SIZE);
        ret
    };

    match ret {
        0 => Ok(Some(data)),
        _ => Ok(None),
    }
}


pub fn create_keyshares(key: &[u8], n: u8, k: u8) -> Result<Vec<Vec<u8>>, SSSError> {
    try!(check_nk(n, k));
    try!(check_key_len(key));

    // Restore the keyshares into one buffer
    let mut tmp = Vec::with_capacity(KEYSHARE_SIZE * (n as usize));
    unsafe {
        sss_create_keyshares(tmp.as_mut_ptr(), key.as_ptr(), n, k);
        tmp.set_len(KEYSHARE_SIZE * (n as usize)); // `sss_create_shares` has written to `tmp`
    }

    // This function groups the elements in `tmp` into a new Vec `acc` in-place.
    let group = |mut acc: Vec<Vec<_>>, x| {
        if acc.last().map_or(false, |x| x.len() < KEYSHARE_SIZE) {
            acc.last_mut().unwrap().push(x);
        } else {
            let mut new_group = Vec::with_capacity(KEYSHARE_SIZE);
            new_group.push(x);
            acc.push(new_group);
        }
        acc
    };

    // Put each share in a separate Vec
    Ok(tmp.into_iter().fold(Vec::with_capacity(n as usize), group))
}


pub fn combine_keyshares(keyshares: &Vec<Vec<u8>>) -> Result<Vec<u8>, SSSError> {
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
    let mut key = Vec::with_capacity(KEY_SIZE);
    unsafe {
        sss_combine_keyshares(key.as_mut_ptr(), tmp.as_mut_ptr(), keyshares.len() as uint8_t);
        key.set_len(KEY_SIZE);
    };

    Ok(key)
}


#[cfg(test)]
mod tests {
    use super::*;
    const DATA: &[u8] = &[42; DATA_SIZE];
    const KEY: &[u8] = &[42; KEY_SIZE];

    #[test]
    fn create_shares_ok() {
        let shares = create_shares(DATA, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);
        for share in shares {
            assert_eq!(share.len(), SHARE_SIZE);
        }
    }

    #[test]
    fn create_shares_err() {
        assert_eq!(create_shares(DATA, 0, 0), Err(SSSError::InvalidN(0)));
        assert_eq!(create_shares(DATA, 5, 0), Err(SSSError::InvalidK(0)));
        assert_eq!(create_shares(DATA, 5, 6), Err(SSSError::InvalidK(6)));
    }

    #[test]
    fn combine_shares_ok() {
        let mut shares = create_shares(DATA, 5, 3).unwrap();
        assert_eq!(combine_shares(&shares).unwrap().unwrap(), DATA);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap().unwrap(), DATA);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap().unwrap(), DATA);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap(), None);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap(), None);
        shares.pop();
        assert_eq!(combine_shares(&shares).unwrap(), None);
    }

    #[test]
    fn combine_shares_err() {
        let shares = vec![vec![]];
        assert_eq!(combine_shares(&shares), Err(SSSError::BadShareLen((0, 0))));
    }

    #[test]
    fn create_keyshares_ok() {
        let keyshares = create_keyshares(KEY, 5, 3).unwrap();
        assert_eq!(keyshares.len(), 5);
        for keyshare in keyshares {
            assert_eq!(keyshare.len(), KEYSHARE_SIZE);;
        }
    }

    #[test]
    fn combine_keyshares_ok() {
        let mut keyshares = create_keyshares(KEY, 5, 3).unwrap();
        assert_eq!(combine_keyshares(&keyshares).unwrap(), KEY);
        keyshares.pop();
        assert_eq!(combine_keyshares(&keyshares).unwrap(), KEY);
        keyshares.pop();
        assert_eq!(combine_keyshares(&keyshares).unwrap(), KEY);
        keyshares.pop();
        assert_ne!(combine_keyshares(&keyshares).unwrap(), KEY);
        keyshares.pop();
        assert_ne!(combine_keyshares(&keyshares).unwrap(), KEY);
        keyshares.pop();
        assert_ne!(combine_keyshares(&keyshares).unwrap(), KEY);
    }
}
