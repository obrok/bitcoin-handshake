use std::fmt::{Display, Formatter};
use std::{str::Utf8Error, vec};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::try_join;

const MAGIC_BYTES: usize = 4;
const NAME_BYTES: usize = 12;
const PAYLOAD_SIZE_BYTES: usize = 4;
const CHECKSUM_BYTES: usize = 4;
const HEADER_BYTES: usize = MAGIC_BYTES + NAME_BYTES + PAYLOAD_SIZE_BYTES + CHECKSUM_BYTES;
/// The size of the version message is constant because we're leaving empty most of the fields that are not strictly needed.
const VERSION_BYTES: usize = 86;

const SUPPORTED_VERSION: u32 = 70015;

/// The possible errors related to the p2p connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    IO(String),
    DecodeUTF8(Utf8Error),
    UnknownMessage(String),
    MagicMismatch,
    ChecksumMismatch,
    InvalidHandshake,
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IO(error.to_string())
    }
}

impl From<Utf8Error> for Error {
    fn from(error: Utf8Error) -> Self {
        Error::DecodeUTF8(error)
    }
}

#[derive(Debug)]
struct Header<'a> {
    magic: [u8; MAGIC_BYTES],
    name: &'a str,
    payload_size: usize,
    checksum: [u8; CHECKSUM_BYTES],
}

impl Header<'_> {
    fn verify_magic(&self, network: Network) -> Result<(), Error> {
        if self.magic != magic_string(network) {
            return Err(Error::MagicMismatch);
        }

        Ok(())
    }

    fn verify_checksum(&self, payload: &[u8]) -> Result<(), Error> {
        if self.checksum != checksum(payload) {
            return Err(Error::ChecksumMismatch);
        }

        Ok(())
    }
}

/// A P2P connection to a Bitcoin node.
#[derive(Debug)]
pub struct Connection {
    read: ReadHalf<TcpStream>,
    write: WriteHalf<TcpStream>,
    network: Network,
}

impl Connection {
    /// Connects to a Bitcoin node and performs the handshake.
    pub async fn new<S: AsRef<str>>(address: S, network: Network) -> Result<Self, Error> {
        let stream = TcpStream::connect(address.as_ref()).await?;
        let (mut read, mut write) = tokio::io::split(stream);

        let (_, version) = try_join!(
            do_send(
                &mut write,
                BitcoinMessage::Version(Version {
                    version: SUPPORTED_VERSION,
                }),
                network,
            ),
            do_recv(&mut read, network)
        )?;

        if !matches!(version, BitcoinMessage::Version(_)) {
            return Err(Error::InvalidHandshake);
        }

        let (_, verack) = try_join!(
            do_send(&mut write, BitcoinMessage::Verack(Verack {}), network),
            do_recv(&mut read, network)
        )?;

        if !matches!(verack, BitcoinMessage::Verack(_)) {
            return Err(Error::InvalidHandshake);
        }

        Ok(Connection {
            read,
            write,
            network,
        })
    }

    /// Sends a message to the Bitcoin node.
    pub async fn send(&mut self, message: BitcoinMessage) -> Result<(), Error> {
        do_send(&mut self.write, message, self.network).await
    }

    /// Receives a message from the Bitcoin node.
    pub async fn recv(&mut self) -> Result<BitcoinMessage, Error> {
        do_recv(&mut self.read, self.network).await
    }
}

async fn do_send(
    write: &mut WriteHalf<TcpStream>,
    message: BitcoinMessage,
    network: Network,
) -> Result<(), Error> {
    write.write_all(&message.encode(network)).await?;

    Ok(())
}

async fn do_recv(
    read: &mut ReadHalf<TcpStream>,
    network: Network,
) -> Result<BitcoinMessage, Error> {
    let mut buffer = [0; HEADER_BYTES];
    read.read_exact(&mut buffer).await?;

    let header = decode_header(&buffer)?;
    header.verify_magic(network)?;

    let mut payload = vec![0; header.payload_size];
    read.read_exact(&mut payload).await?;
    header.verify_checksum(&payload)?;

    decode_payload(&header, &payload)
}

/// The Bitcoin network to connect to.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Network {
    Testnet,
    Mainnet,
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Testnet => write!(f, "testnet"),
            Network::Mainnet => write!(f, "mainnet"),
        }
    }
}

fn magic_string(network: Network) -> [u8; MAGIC_BYTES] {
    match network {
        Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
        Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
    }
}

/// The possible messages that can be sent or received.
#[derive(Debug, PartialEq, Eq)]
pub enum BitcoinMessage {
    Version(Version),
    Verack(Verack),
    Ping(Ping),
    Pong(Pong),
}

/// The version message.
/// Normally only sent during handshake.
#[derive(Debug, PartialEq, Eq)]
pub struct Version {
    pub version: u32,
}

/// The verack message.
/// Normally only sent during handshake.
#[derive(Debug, PartialEq, Eq)]
pub struct Verack;

/// The ping message.
#[derive(Debug, PartialEq, Eq)]
pub struct Ping {
    /// A nonce that can be set and used to identify the matching pong message.
    pub nonce: u64,
}

/// The pong message.
#[derive(Debug, PartialEq, Eq)]
pub struct Pong {
    /// The nonce from the matching ping message.
    pub nonce: u64,
}

trait Encode {
    fn name(&self) -> &'static str;
    fn encode(&self) -> Vec<u8>;
}

impl Encode for Version {
    fn name(&self) -> &'static str {
        "version"
    }

    fn encode(&self) -> Vec<u8> {
        let mut result = vec![0; VERSION_BYTES];
        (&mut result[0..])
            .write_u32::<LittleEndian>(self.version)
            .unwrap();
        result
    }
}

impl Encode for Verack {
    fn name(&self) -> &'static str {
        "verack"
    }

    fn encode(&self) -> Vec<u8> {
        vec![]
    }
}

impl Encode for Ping {
    fn name(&self) -> &'static str {
        "ping"
    }

    fn encode(&self) -> Vec<u8> {
        let mut result = vec![0; 8];
        (&mut result[0..])
            .write_u64::<LittleEndian>(self.nonce)
            .unwrap();
        result
    }
}

impl BitcoinMessage {
    fn encode(&self, network: Network) -> Vec<u8> {
        let (payload, name) = match self {
            BitcoinMessage::Version(version) => (version.encode(), version.name()),
            BitcoinMessage::Verack(verack) => (verack.encode(), verack.name()),
            BitcoinMessage::Ping(ping) => (ping.encode(), ping.name()),
            BitcoinMessage::Pong(_) => unimplemented!("Sending pong is not implemented"),
        };

        let mut name_bytes = vec![0; NAME_BYTES];
        name_bytes[0..name.len()].copy_from_slice(name.as_bytes());
        let checksum = checksum(&payload);

        let mut encoded = Vec::with_capacity(HEADER_BYTES + payload.len());
        encoded.extend_from_slice(magic_string(network).as_ref());
        encoded.extend_from_slice(name_bytes.as_ref());
        WriteBytesExt::write_u32::<LittleEndian>(&mut encoded, payload.len() as u32)
            .expect("Failed to write payload size");
        encoded.extend_from_slice(&checksum);
        encoded.extend_from_slice(&payload);

        encoded
    }
}

/// Returns the first 4 bytes of SHA256(SHA256(bytes)), which is the checksum used by the Bitcoin protocol.
fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut second_hasher = Sha256::new();
    second_hasher.update(hasher.finalize());
    let result = second_hasher.finalize();
    result[..4].try_into().expect("Incorrect checksum length")
}

fn decode_header<'a>(bytes: &'a [u8; HEADER_BYTES]) -> Result<Header<'a>, Error> {
    let (magic, bytes) = take_bytes(bytes, MAGIC_BYTES);
    let (name, bytes) = take_bytes(bytes, NAME_BYTES);
    let (mut payload_size_bytes, bytes) = take_bytes(bytes, PAYLOAD_SIZE_BYTES);
    let (checksum_bytes, _) = take_bytes(bytes, CHECKSUM_BYTES);

    let magic = magic.try_into().expect("Incorrect magic size");
    let name = std::str::from_utf8(name)?.trim_end_matches('\0');
    let payload_size = ReadBytesExt::read_u32::<LittleEndian>(&mut payload_size_bytes)? as usize;
    let checksum: [u8; CHECKSUM_BYTES] =
        checksum_bytes.try_into().expect("Incorrect checksum size");

    Ok(Header {
        magic,
        name,
        payload_size,
        checksum,
    })
}

fn decode_payload(header: &Header, payload: &[u8]) -> Result<BitcoinMessage, Error> {
    match header.name {
        "version" => decode_version(payload),
        "verack" => decode_verack(payload),
        "pong" => decode_pong(payload),
        _ => Err(Error::UnknownMessage(header.name.to_string())),
    }
}

fn take_bytes<'a>(bytes: &'a [u8], size: usize) -> (&'a [u8], &'a [u8]) {
    (&bytes[..size], &bytes[size..])
}

fn decode_version(mut bytes: &[u8]) -> Result<BitcoinMessage, Error> {
    let version = ReadBytesExt::read_u32::<LittleEndian>(&mut bytes)?;
    Ok(BitcoinMessage::Version(Version { version }))
}

fn decode_verack(_bytes: &[u8]) -> Result<BitcoinMessage, Error> {
    Ok(BitcoinMessage::Verack(Verack {}))
}

fn decode_pong(mut bytes: &[u8]) -> Result<BitcoinMessage, Error> {
    let nonce = ReadBytesExt::read_u64::<LittleEndian>(&mut bytes)?;
    Ok(BitcoinMessage::Pong(Pong { nonce }))
}

#[cfg(test)]
mod test {
    use super::*;
    use assert2::assert;

    #[test]
    fn test_version_roundtrip() -> Result<(), Error> {
        let message = BitcoinMessage::Version(Version { version: 456 });
        let encoded = message.encode(Network::Testnet);
        let decoded = decode(&encoded, Network::Testnet)?;

        assert!(decoded == message);

        Ok(())
    }

    #[test]
    fn test_verack_roundtrip() -> Result<(), Error> {
        let message = BitcoinMessage::Verack(Verack {});
        let encoded = message.encode(Network::Testnet);
        let decoded = decode(&encoded, Network::Testnet)?;

        assert!(decoded == message);

        Ok(())
    }

    #[test]
    fn test_checksum() {
        let message = BitcoinMessage::Version(Version { version: 456 });
        let mut encoded = message.encode(Network::Testnet);
        encoded[MAGIC_BYTES + NAME_BYTES + PAYLOAD_SIZE_BYTES] += 1;

        assert!(decode(&encoded, Network::Testnet) == Err(Error::ChecksumMismatch));
    }

    #[test]
    fn test_invalid_magic() {
        let message = BitcoinMessage::Version(Version { version: 456 });
        let mut encoded = message.encode(Network::Testnet);
        encoded[0] += 1;

        assert!(decode(&encoded, Network::Testnet) == Err(Error::MagicMismatch));
    }

    fn decode(bytes: &[u8], network: Network) -> Result<BitcoinMessage, Error> {
        let (header_bytes, payload_bytes) = take_bytes(bytes, HEADER_BYTES);
        let header = decode_header(header_bytes.try_into().expect("Invalid header size"))?;
        header.verify_magic(network)?;

        if header.magic != magic_string(network).as_ref() {
            return Err(Error::MagicMismatch);
        }

        if header.checksum != checksum(payload_bytes) {
            return Err(Error::ChecksumMismatch);
        }

        let payload = &payload_bytes[..header.payload_size];
        decode_payload(&header, payload)
    }
}
