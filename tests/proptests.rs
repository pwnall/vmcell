use imp_testing::agent::ExecRequest;
use imp_testing::agent::protocol::Message;
use imp_testing::vmm::CidAllocator;
use proptest::prelude::*;

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

        // Release half of them
        for i in active.iter().take(active.len() / 2) {
            alloc.release(*i);
        }

        // Re-allocate
        if let Ok(cid) = alloc.allocate() {
            assert!(cid >= 3);
            assert!(!active[active.len()/2..].contains(&cid));
            active.push(cid);
        }

        // Release the remaining allocated CIDs to prevent leaking into the global allocator
        for i in active[active.len()/2..].iter() {
            alloc.release(*i);
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
        use imp_testing::config::ProxyConfig;
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
            assert!(imp_testing::net::ip_math(vmid).is_err());
        } else {
            let (host, guest, cidr) = imp_testing::net::ip_math(vmid).unwrap();
            let octet = ((vmid % 254) + 1) as u8;
            assert_eq!(host.octets(), [10, 200, octet, 1]);
            assert_eq!(guest.octets(), [10, 200, octet, 2]);
            assert_eq!(cidr, format!("10.200.{}.2/30", octet));
        }
    }
}
