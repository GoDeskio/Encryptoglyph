use encryptoglyph::shamir::{combine, split};
use encryptoglyph::Error;

#[test]
fn any_m_of_n_recovers() {
    let secret: Vec<u8> = (0..32u8).collect();
    let sh = split(&secret, 3, 5).unwrap();
    for a in 0..5 {
        for b in a + 1..5 {
            for c in b + 1..5 {
                let got = combine(&[&sh[a], &sh[b], &sh[c]]).unwrap();
                assert_eq!(&got[..], &secret[..]);
            }
        }
    }
}

#[test]
fn below_threshold_and_bad_input_rejected() {
    let sh = split(b"k", 3, 4).unwrap();
    assert_eq!(combine(&[&sh[0], &sh[1]]).unwrap_err(), Error::InvalidArgument);
    assert_eq!(combine(&[&sh[0], &sh[0], &sh[1]]).unwrap_err(), Error::InvalidArgument);
    assert_eq!(split(b"k", 1, 3).unwrap_err(), Error::InvalidArgument);
    assert_eq!(split(b"k", 4, 3).unwrap_err(), Error::InvalidArgument);
    assert_eq!(split(b"", 2, 3).unwrap_err(), Error::InvalidArgument);
    let other = split(b"kk", 3, 4).unwrap();
    assert_eq!(combine(&[&sh[0], &sh[1], &other[2]]).unwrap_err(), Error::InvalidArgument);
}

#[test]
fn two_shares_of_three_reveal_nothing_structural() {
    // Splitting the same secret twice gives unrelated shares (fresh randomness each time).
    let a = split(&[0u8; 16], 3, 3).unwrap();
    let b = split(&[0u8; 16], 3, 3).unwrap();
    assert_ne!(a[0], b[0]);
}
