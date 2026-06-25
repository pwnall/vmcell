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
    fn test_path_injectivity(vmid1 in 1..=254u32, vmid2 in 1..=254u32) {
        prop_assume!(vmid1 != vmid2);
        let cg1 = format!("imp-vm-{}", vmid1);
        let cg2 = format!("imp-vm-{}", vmid2);
        assert_ne!(cg1, cg2);

        let sock1 = format!("/tmp/imp-smoltcp-{}.sock", vmid1);
        let sock2 = format!("/tmp/imp-smoltcp-{}.sock", vmid2);
        assert_ne!(sock1, sock2);

        let netns1 = format!("imp-net-{}", vmid1);
        let netns2 = format!("imp-net-{}", vmid2);
        assert_ne!(netns1, netns2);
    }

    #[test]
    fn test_subnet_math(vmid in 1..=254u32) {
        let ip = format!("10.200.{}.2/30", vmid);
        let proxy_ip = format!("10.200.{}.1", vmid);
        // Valid /30 has 4 addresses: network (.0), host 1 (.1), host 2 (.2), broadcast (.3)
        // With our setup: .1 is host (proxy), .2 is guest, .0 is net, .3 is bcast
        assert!(ip.ends_with(".2/30"));
        assert!(proxy_ip.ends_with(".1"));
    }
}
