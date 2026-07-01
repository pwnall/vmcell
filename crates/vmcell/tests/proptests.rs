use proptest::prelude::*;
use vmcell::agent::ExecRequest;
use vmcell::agent::protocol::Message;
use vmcell::vmm::CidAllocator;

proptest! {
    #[test]
    fn test_cid_allocator_boundaries(seed in 1..=1000u32) {
        let alloc = CidAllocator::new();
        let cid1 = alloc.allocate().unwrap();
        assert!(cid1 >= 3);

        let mut active = vec![cid1];
        // Allocate up to 200 random CIDs
        let limit = (seed % 200) as usize;
        for _ in 0..limit {
            if let Ok(cid) = alloc.allocate() {
                assert!(cid >= 3);
                assert!(!active.contains(&cid));
                active.push(cid);
            }
        }

        // Because nothing was released during the allocation loop, the lowest-free
        // allocator hands out a contiguous ascending run, so `active` is sorted;
        // the first half are the LOWEST live CIDs.
        let half = active.len() / 2;
        let freed: Vec<u32> = active.iter().take(half).copied().collect();
        let held: Vec<u32> = active[half..].to_vec();

        // Release the first (lowest) half.
        for cid in &freed {
            alloc.release(*cid);
        }

        // TEST-3: reallocation must REUSE a previously freed value (not mint a
        // brand-new one while freed slots exist) and must never collide with a
        // still-live CID. A no-op `release()` leaves the set unchanged, so the
        // reallocated CID would be a fresh value NOT in `freed` -> the reuse
        // assert goes red.
        if !freed.is_empty() {
            let cid = alloc.allocate().expect("a freed CID must be reallocatable");
            prop_assert!(cid >= 3);
            prop_assert!(
                freed.contains(&cid),
                "reallocated CID {} was not one of the freed values {:?}",
                cid,
                freed
            );
            prop_assert!(
                !held.contains(&cid),
                "reallocated CID {} collided with a still-live CID",
                cid
            );
            alloc.release(cid);
        }

        // Release the remaining allocated CIDs (fresh local allocator, but keep
        // the set tidy).
        for cid in &held {
            alloc.release(*cid);
        }
    }

    #[test]
    fn test_postcard_protocol_roundtrip(argv in prop::collection::vec(".*", 0..10), exit_code in -100..100i32) {
        let req = ExecRequest::new(argv.clone());
        let msg_req = Message::Exec(req);
        let bytes_req = postcard::to_stdvec(&msg_req).unwrap();
        let decoded_req: Message = postcard::from_bytes(&bytes_req).unwrap();

        match decoded_req {
            Message::Exec(r) => assert_eq!(r.argv, argv),
            _ => panic!("Expected Exec"),
        }

        let msg_resp = Message::Exit(exit_code);
        let bytes_resp = postcard::to_stdvec(&msg_resp).unwrap();
        let decoded_resp: Message = postcard::from_bytes(&bytes_resp).unwrap();

        match decoded_resp {
            Message::Exit(o) => assert_eq!(o, exit_code),
            _ => panic!("Expected Exit"),
        }
    }

    #[test]
    fn test_proxy_config_equality(domains in prop::collection::vec(".*", 0..5)) {
        use vmcell::config::ProxyConfig;
        let mut p1 = ProxyConfig::default();
        p1.blocked_domains = domains.clone();

        let mut p2 = ProxyConfig::default();
        p2.blocked_domains = domains.clone();

        #[cfg(feature = "proxy")]
        {
            // Even with same contents, different Arc allocation means not equal for ProxyConfig
            assert_ne!(p1, p2);
            p2.doubles = p1.doubles.clone();
        }
        assert_eq!(p1, p2);

        let mut p3 = ProxyConfig::default();
        #[cfg(feature = "proxy")]
        { p3.doubles = p1.doubles.clone(); }
        p3.blocked_domains = vec!["blocked.com".to_string()];

        assert_ne!(p1, p3);
    }

    #[test]
    fn test_subnet_math(vmid in 0..=255u32) {
        if vmid == 0 || vmid == 255 {
            assert!(vmcell::net::ip_math(vmid).is_err());
        } else {
            let (host, guest, cidr) = vmcell::net::ip_math(vmid).unwrap();
            let octet = ((vmid % 254) + 1) as u8;
            assert_eq!(host.octets(), [10, 200, octet, 1]);
            assert_eq!(guest.octets(), [10, 200, octet, 2]);
            assert_eq!(cidr, format!("10.200.{}.2/30", octet));
        }
    }
}

// TEST-3: deterministic reuse + "wrap without colliding with live" for the CID
// allocator. Fills the whole guest range [3, 254], frees two BOUNDARY values
// (the lowest and highest), and asserts reallocation reuses exactly those freed
// values without ever handing back a still-live CID. Buggy impl guarded: a
// no-op `release()` leaves the range full, so the first post-release
// `allocate()` returns `Err` and the `.expect()` panics; an allocator that
// wrapped into a live CID fails the set-equality / non-collision asserts.
#[test]
fn cid_allocator_reuses_freed_and_wraps_without_colliding_with_live() {
    use std::collections::BTreeSet;

    let alloc = CidAllocator::new();

    // Fill the entire guest range [3, 254].
    let mut live: BTreeSet<u32> = BTreeSet::new();
    while let Ok(cid) = alloc.allocate() {
        assert!((3..=254).contains(&cid), "cid {cid} out of the guest range");
        assert!(
            live.insert(cid),
            "allocator handed out a duplicate CID {cid}"
        );
    }
    assert_eq!(live.len(), 252, "expected 252 guest CIDs (3..=254)");
    assert!(
        alloc.allocate().is_err(),
        "a full allocator must report exhaustion, not a reserved/duplicate CID"
    );

    // Free two BOUNDARY values (lowest and highest); keep the rest live.
    alloc.release(3);
    alloc.release(254);
    live.remove(&3);
    live.remove(&254);

    // Reallocation must reuse the freed values, never a still-live one.
    let a = alloc.allocate().expect("a freed CID must be reusable");
    let b = alloc
        .allocate()
        .expect("the second freed CID must be reusable");
    assert!(
        !live.contains(&a) && !live.contains(&b),
        "reused CID collided with a still-live one: {a}, {b}"
    );
    let reused: BTreeSet<u32> = [a, b].into_iter().collect();
    assert_eq!(
        reused,
        BTreeSet::from([3, 254]),
        "reallocation must reuse exactly the freed boundary CIDs, got {a} and {b}"
    );

    // Exhausted again once the freed slots are taken back.
    assert!(
        alloc.allocate().is_err(),
        "allocator must be full again after the freed slots are reused"
    );
}
