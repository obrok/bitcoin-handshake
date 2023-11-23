FROM ubuntu:20.04

# Environment variables
ENV ARCH=x86_64
ENV BITCOIN_VERSION=0.21.1
ENV BITCOIN_URL=https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-${ARCH}-linux-gnu.tar.gz
ENV BITCOIN_DATA_DIR=/blockchain/bitcoin/data

# Install dependencies
RUN apt update
RUN apt install ca-certificates gnupg gpg wget jq --no-install-recommends -y

# Download and verify bitcoind
RUN cd /tmp
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS.asc
RUN wget -qO bitcoin-${BITCOIN_VERSION}-${ARCH}-linux-gnu.tar.gz "${BITCOIN_URL}"
RUN cat SHA256SUMS.asc | grep bitcoin-${BITCOIN_VERSION}-${ARCH}-linux-gnu.tar.gz | awk '{ print $1 }'

# Unpack and install bitcoind
RUN mkdir -p /opt/bitcoin/${BITCOIN_VERSION}
RUN mkdir -p ${BITCOIN_DATA_DIR}
RUN tar -xzvf bitcoin-${BITCOIN_VERSION}-${ARCH}-linux-gnu.tar.gz -C /opt/bitcoin/${BITCOIN_VERSION} --strip-components=1 --exclude=*-qt
RUN ln -s /opt/bitcoin/${BITCOIN_VERSION} /opt/bitcoin/current
RUN rm -rf /tmp/*

# Copy config file
COPY bitcoin.conf ${BITCOIN_DATA_DIR}/bitcoin.conf

ENTRYPOINT ["/opt/bitcoin/current/bin/bitcoind", "-conf=${BITCOIN_DATA_DIR}/bitcoin.conf", "-datadir=${BITCOIN_DATA_DIR}"]