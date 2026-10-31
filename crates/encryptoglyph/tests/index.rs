use encryptoglyph::index::*;

const K: &[u8] = &[9u8; 32];

#[test]
fn typed_equality_no_cross_type_collision() {
    let t = |v| eq_token(K, "t", "f", &v, 16);
    assert_ne!(t(IndexValue::Text("1")), t(IndexValue::Int(1)));
    assert_ne!(t(IndexValue::Int(1)), t(IndexValue::Date(1)));
    assert_ne!(t(IndexValue::Bool(true)), t(IndexValue::Int(1)));
    assert_eq!(
        t(IndexValue::Text(" Foo  Bar ")),
        t(IndexValue::Text("foo bar"))
    );
    assert_eq!(t(IndexValue::Int(42)), t(IndexValue::Int(42)));
    assert_eq!(t(IndexValue::Int(42)).len(), 16);
}

#[test]
fn equality_scoped_to_tenant_and_field() {
    let v = IndexValue::Int(5);
    let a = eq_token(K, "t1", "f", &v, 16);
    assert_ne!(a, eq_token(K, "t2", "f", &v, 16));
    assert_ne!(a, eq_token(K, "t1", "g", &v, 16));
    assert_ne!(
        eq_token(K, "ab", "c", &v, 16),
        eq_token(K, "a", "bc", &v, 16)
    );
}

#[test]
fn range_query_covers_matching_rows() {
    let q = range_query_tokens(K, "t", "amt", 5, 25, 10, 100).unwrap();
    for v in [-15i64, -1, 0, 9, 10, 19, 20, 25, 55, 99] {
        if (5..=25).contains(&v) {
            assert!(
                q.contains(&range_token(K, "t", "amt", v, 10).unwrap()),
                "{v}"
            );
        }
    }
    assert!(!q.contains(&range_token(K, "t", "amt", 55, 10).unwrap()));
    assert_eq!(q.len(), 3);
    assert_eq!(
        range_token(K, "t", "amt", -1, 10).unwrap(),
        range_token(K, "t", "amt", -10, 10).unwrap()
    );
}

#[test]
fn range_query_limits() {
    assert!(range_query_tokens(K, "t", "f", 0, 1_000_000, 1, 1000).is_err());
    assert!(range_query_tokens(K, "t", "f", 5, 1, 1, 10).is_err());
    assert!(range_token(K, "t", "f", 1, 0).is_err());
    assert!(range_query_tokens(K, "t", "f", i64::MIN, i64::MAX, 1, 10).is_err());
}

#[test]
fn width_is_bound_into_token() {
    assert_ne!(
        range_token(K, "t", "f", 0, 10).unwrap(),
        range_token(K, "t", "f", 0, 100).unwrap()
    );
}
