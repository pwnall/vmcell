use proptest::prelude::*;
use vmcell::steward::ExecRequest;
use vmcell::steward::protocol::Message;
use vmcell::vmm::{CidAllocator, MAX_GUEST_CID, MIN_GUEST_CID};

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

    // Samples the WHOLE vmid domain plus both refusal boundaries. The expected addresses are
    // recomputed from the two-dimensional map's definition (third octet × which /30 inside it),
    // never from a `.1`/`.2` literal, which only held while the map had one dimension.
    #[test]
    fn test_subnet_math(vmid in 0..=(vmcell::net::MAX_VMID + 1)) {
        if vmid == 0 || vmid > vmcell::net::MAX_VMID {
            assert!(vmcell::net::ip_math(vmid).is_err());
        } else {
            let (host, guest, cidr) = vmcell::net::ip_math(vmid).unwrap();
            let octet = ((vmid % 254) + 1) as u8;
            let base = (4 * ((vmid - 1) / 254)) as u8;
            assert_eq!(host.octets(), [10, 200, octet, base + 1]);
            assert_eq!(guest.octets(), [10, 200, octet, base + 2]);
            assert_eq!(cidr, format!("10.200.{octet}.{}/30", base + 2));
        }
    }
}

// TEST-3: deterministic reuse + "wrap without colliding with live" for the CID
// allocator. Fills the whole guest range, frees two BOUNDARY values
// (the lowest and highest), and asserts reallocation reuses exactly those freed
// values without ever handing back a still-live CID. Buggy impl guarded: a
// no-op `release()` leaves the range full, so the first post-release
// `allocate()` returns `Err` and the `.expect()` panics; an allocator that
// wrapped into a live CID fails the set-equality / non-collision asserts.
#[test]
fn cid_allocator_reuses_freed_and_wraps_without_colliding_with_live() {
    use std::collections::BTreeSet;

    let alloc = CidAllocator::new();

    // Fill the entire guest range.
    let mut live: BTreeSet<u32> = BTreeSet::new();
    while let Ok(cid) = alloc.allocate() {
        assert!(
            (MIN_GUEST_CID..=MAX_GUEST_CID).contains(&cid),
            "cid {cid} out of the guest range"
        );
        assert!(
            live.insert(cid),
            "allocator handed out a duplicate CID {cid}"
        );
    }
    // One guest CID per addressable vmid: the CID space must never be the narrower of the two, or
    // it — not the address map — is the ceiling on concurrent VMs per host (design §17,
    // Networking). `net::tests::the_vmid_ceiling_is_one_law_with_five_other_homes` is the roster.
    assert_eq!(
        live.len(),
        vmcell::net::MAX_VMID as usize,
        "expected one guest CID per addressable vmid"
    );
    assert!(
        alloc.allocate().is_err(),
        "a full allocator must report exhaustion, not a reserved/duplicate CID"
    );

    // Free two BOUNDARY values (lowest and highest); keep the rest live.
    alloc.release(MIN_GUEST_CID);
    alloc.release(MAX_GUEST_CID);
    live.remove(&MIN_GUEST_CID);
    live.remove(&MAX_GUEST_CID);

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
        BTreeSet::from([MIN_GUEST_CID, MAX_GUEST_CID]),
        "reallocation must reuse exactly the freed boundary CIDs, got {a} and {b}"
    );

    // Exhausted again once the freed slots are taken back.
    assert!(
        alloc.allocate().is_err(),
        "allocator must be full again after the freed slots are reused"
    );
}
