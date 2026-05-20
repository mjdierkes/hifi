use std::error::Error;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    hifi::app::run(std::env::args().skip(1).collect()).await
}
