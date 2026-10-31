use encryptoglyph::tenancy::{Denied, Limits, Registry};

fn l(k: u32, r: u32, b: u32) -> Limits {
    Limits { max_keys: k, ops_per_sec: r, burst: b }
}

#[test]
fn hierarchy_quotas_and_rates() {
    let mut r = Registry::default();
    r.create("msp", l(3, 10, 4), 0).unwrap();
    r.create("msp/acme", l(2, 10, 2), 0).unwrap();
    r.create("msp/beta", l(2, 10, 4), 0).unwrap();
    assert!(r.create("msp/huge", l(9, 1, 1), 0).is_err());
    assert!(r.create("orphan/x", l(1, 1, 1), 0).is_err());
    assert!(r.create("bad path", l(1, 1, 1), 0).is_err());

    r.add_key("msp/acme").unwrap();
    r.add_key("msp/acme").unwrap();
    assert_eq!(r.add_key("msp/acme"), Err(Denied::KeyQuota("msp/acme".into())));
    r.add_key("msp/beta").unwrap();
    assert_eq!(r.add_key("msp/beta"), Err(Denied::KeyQuota("msp".into())));
    r.remove_key("msp/acme");
    r.add_key("msp/beta").unwrap();
    assert_eq!(r.usage("msp").unwrap().0, 3);

    r.charge_op("msp/acme", 0).unwrap();
    r.charge_op("msp/acme", 0).unwrap();
    assert_eq!(r.charge_op("msp/acme", 0), Err(Denied::RateLimited("msp/acme".into())));
    r.charge_op("msp/beta", 0).unwrap();
    r.charge_op("msp/beta", 0).unwrap();
    assert_eq!(r.charge_op("msp/beta", 0), Err(Denied::RateLimited("msp".into())));
    r.charge_op("msp/acme", 100).unwrap(); // 100 ms at 10 ops/s refills one token
    assert_eq!(r.charge_op("nope", 0), Err(Denied::NoNamespace));
}
