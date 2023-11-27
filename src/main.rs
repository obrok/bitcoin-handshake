use clap::builder::TypedValueParser as _;
use clap::Parser;

use crate::p2p::{BitcoinMessage, Connection, Error, Network, Ping};

mod p2p;

#[derive(Parser, Debug)]
struct Options {
    #[arg(
        long,
        default_value_t = Network::Testnet,
        value_parser = clap::builder::PossibleValuesParser::new(["testnet", "mainnet"])
            .map(|s| match s.as_str() {
                "testnet" => Network::Testnet,
                "mainnet" => Network::Mainnet,
                _ => unreachable!(),
            }),
    )]
    network: Network,
    #[arg(short, long, default_value = "bitcoind:18333")]
    url: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let options = Options::parse();
    let mut connection = Connection::new(options.url, options.network).await?;

    let nonce: u64 = rand::random();
    let message = BitcoinMessage::Ping(Ping { nonce });
    println!("Sending {:?}", message);
    connection.send(message).await?;

    loop {
        let message = connection.recv().await;
        if let Ok(BitcoinMessage::Pong(pong)) = message {
            println!("Received {:?}", pong);
            break;
        } else {
            println!("Received {:?}", message);
        }
    }

    Ok(())
}
