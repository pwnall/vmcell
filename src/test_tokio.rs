#[tokio::test]
async fn test() {
    let mut cmd = tokio::process::Command::new("ls");
    cmd.process_group(0);
}
