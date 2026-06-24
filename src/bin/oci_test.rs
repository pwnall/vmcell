use oci_client::{Client, Reference};

#[tokio::main]
async fn main() {
    let mut client = Client::default();
    let auth = oci_client::secrets::RegistryAuth::Anonymous;
    let reference = Reference::try_from("docker.io/library/debian:trixie-slim").unwrap();
    let image_data = client.pull(&reference, &auth, vec![]).await;
}
