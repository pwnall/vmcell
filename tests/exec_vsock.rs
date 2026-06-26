use futures::{SinkExt, StreamExt};
use imp_testing::agent::AgentClient;
use imp_testing::agent::protocol::{ExecRequest, Message};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[tokio::test]
async fn test_exec_vsock_mock() {
    let tmp = std::env::temp_dir().join(format!("imp-test-vsock-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp).expect("Failed to bind UDS");

    let vsock_path = tmp.clone();

    // Spawn server to mock CloudHypervisor UDS vsock and the guest agent
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // 1. Read CONNECT <port>\n
        let mut resp = String::new();
        loop {
            let mut byte = [0; 1];
            let n = stream.read(&mut byte).await.unwrap();
            if n == 0 {
                break;
            }
            resp.push(byte[0] as char);
            if byte[0] == b'\n' {
                break;
            }
        }
        assert_eq!(resp, "CONNECT 5000\n");

        // 2. Send OK <port>\n
        stream.write_all(b"OK 5000\n").await.unwrap();

        // 3. Start framed protocol
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

        // 4. Send Ready
        let ready_msg = postcard::to_stdvec(&Message::Ready).unwrap();
        framed.send(ready_msg.into()).await.unwrap();

        // 5. Expect Exec
        let msg_bytes = framed.next().await.unwrap().unwrap();
        let msg: Message = postcard::from_bytes(&msg_bytes).unwrap();
        match msg {
            Message::Exec(req) => {
                assert_eq!(req.argv[0], "echo");
                assert_eq!(req.argv[1], "hello");
            }
            _ => panic!("Expected Exec message"),
        }

        // 6. Send Stdout
        let stdout_msg = postcard::to_stdvec(&Message::Stdout(b"hello\n".to_vec())).unwrap();
        framed.send(stdout_msg.into()).await.unwrap();

        // 7. Send Exit
        let exit_msg = postcard::to_stdvec(&Message::Exit(0)).unwrap();
        framed.send(exit_msg.into()).await.unwrap();
    });

    let mut client = AgentClient::connect(
        &vsock_path,
        5000,
        std::time::Duration::from_secs(2),
        &imp_testing::vmm::RealSerialLog {
            path: std::path::PathBuf::from("/dev/null"),
        },
    )
    .await
    .expect("Failed to connect");

    let outcome = client
        .exec(ExecRequest::new(vec!["echo".into(), "hello".into()]))
        .await
        .expect("Exec failed");

    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout, b"hello\n");

    server_task.await.unwrap();
    let _ = std::fs::remove_file(&tmp);
}

mod common;

vmm_matrix_test!(put_file, |vmm| {
    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    let cfg = imp_testing::config::VmConfig::builder(
        kernel,
        imp_testing::config::RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = imp_testing::TestVm::start(
        &vmm,
        cfg,
        cid_alloc,
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    let agent = vm
        .agent(None, &imp_testing::orchestrator::RealClock)
        .await
        .expect("Failed to connect to agent");

    agent
        .put_file("/tmp/hello.txt", b"hello world from test", None)
        .await
        .expect("put_file failed");

    let outcome = agent
        .exec(ExecRequest::new(vec![
            "cat".into(),
            "/tmp/hello.txt".into(),
        ]))
        .await
        .expect("Exec failed");

    assert_eq!(outcome.code, 0);
    assert_eq!(
        outcome.stdout, b"hello world from test",
        "Round-trip file contents must match"
    );

    vm.shutdown().await.expect("Shutdown failed");
});
