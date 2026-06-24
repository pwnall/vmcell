#[tokio::main]
async fn main() {
    let mut client = oci_client::Client::default();
    let auth = oci_client::secrets::RegistryAuth::Anonymous;
    let reference = oci_client::Reference::try_from("docker.io/library/debian:trixie-slim").unwrap();
    client.pull(&reference, &auth, vec![]).await;
}
