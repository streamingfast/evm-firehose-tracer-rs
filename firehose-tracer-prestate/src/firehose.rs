//! Reads a block back from a production Firehose endpoint.
//!
//! Only `sf.firehose.v2.Fetch/Block` is called. Its messages are generated, and live in
//! [`firehose_tracer::pb`] next to the block types rather than being hand-declared here, so the
//! field numbers and the `SingleBlockRequest.reference` oneof are the schema's rather than a
//! hand-copied approximation. The unary call is still issued through [`tonic::client::Grpc`]
//! directly, so no service-stub codegen plugin has to be kept in step with the `tonic` version.

use eyre::{eyre, Context};
use firehose_tracer::pb::sf::{
    ethereum::r#type::v2::Block,
    firehose::v2::{
        single_block_request::{BlockNumber, Reference},
        SingleBlockRequest, SingleBlockResponse,
    },
};
use prost::Message as _;
use tonic::{
    transport::{Channel, ClientTlsConfig},
    Request,
};

/// Resolves the bearer token a StreamingFast endpoint expects.
#[derive(Debug)]
pub struct FirehoseAuth;

impl FirehoseAuth {
    /// Where an API key is exchanged for a short-lived JWT.
    pub const ISSUE_URL: &'static str = "https://auth.streamingfast.io/v1/auth/issue";

    /// Returns `SF_JWT` when set, otherwise exchanges `SF_API_KEY` for a fresh token.
    pub async fn token_from_env() -> eyre::Result<String> {
        if let Ok(token) = std::env::var("SF_JWT") {
            if !token.is_empty() {
                return Ok(token);
            }
        }

        let api_key = std::env::var("SF_API_KEY").map_err(|_| {
            eyre!(
                "neither SF_JWT nor SF_API_KEY is set; a production Firehose endpoint rejects \
                 unauthenticated calls"
            )
        })?;

        Self::issue(&api_key).await
    }

    /// Exchanges `api_key` for a JWT.
    pub async fn issue(api_key: &str) -> eyre::Result<String> {
        #[derive(serde::Deserialize)]
        struct Issued {
            token: String,
        }

        let issued: Issued = reqwest::Client::new()
            .post(Self::ISSUE_URL)
            .json(&serde_json::json!({ "api_key": api_key }))
            .send()
            .await
            .context("calling the StreamingFast auth issuer")?
            .error_for_status()
            .context("the StreamingFast auth issuer rejected the API key")?
            .json()
            .await
            .context("decoding the issued token")?;

        Ok(issued.token)
    }
}

/// A client for `sf.firehose.v2.Fetch` against a production endpoint.
#[derive(Debug)]
pub struct FirehoseFetcher {
    channel: Channel,
    token: String,
}

impl FirehoseFetcher {
    /// gRPC path of the unary fetch method.
    pub const BLOCK_PATH: &'static str = "/sf.firehose.v2.Fetch/Block";

    /// Type URL suffix the response payload must carry.
    pub const BLOCK_TYPE: &'static str = "sf.ethereum.type.v2.Block";

    /// A busy chain's block comfortably exceeds tonic's four-megabyte default decode limit.
    pub const MAX_DECODING_SIZE: usize = 256 * 1024 * 1024;

    /// Connects to `endpoint` (an `https://host:port` URL) authenticating with `token`.
    pub async fn connect(endpoint: &str, token: String) -> eyre::Result<Self> {
        let channel = Channel::from_shared(endpoint.to_owned())
            .with_context(|| format!("parsing Firehose endpoint {endpoint}"))?
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .context("configuring TLS for the Firehose endpoint")?
            .connect()
            .await
            .with_context(|| format!("connecting to {endpoint}"))?;

        Ok(Self { channel, token })
    }

    /// Fetches the block at `number` as production Firehose emitted it.
    pub async fn block(&self, number: u64) -> eyre::Result<Block> {
        let mut client = tonic::client::Grpc::new(self.channel.clone())
            .max_decoding_message_size(Self::MAX_DECODING_SIZE);

        client
            .ready()
            .await
            .context("the Firehose endpoint never became ready")?;

        let mut request = Request::new(SingleBlockRequest {
            reference: Some(Reference::BlockNumber(BlockNumber { num: number })),
            ..Default::default()
        });
        let bearer = format!("Bearer {}", self.token)
            .parse()
            .context("building the authorization header")?;
        request.metadata_mut().insert("authorization", bearer);

        let response = client
            .unary(
                request,
                Self::BLOCK_PATH
                    .parse()
                    .expect("the fetch path is a valid gRPC path"),
                tonic_prost::ProstCodec::<SingleBlockRequest, SingleBlockResponse>::default(),
            )
            .await
            .with_context(|| format!("fetching block {number} from Firehose"))?;

        let any = response
            .into_inner()
            .block
            .ok_or_else(|| eyre!("Firehose returned no block for {number}"))?;

        if !any.type_url.ends_with(Self::BLOCK_TYPE) {
            return Err(eyre!(
                "Firehose returned a {} payload, expected {}",
                any.type_url,
                Self::BLOCK_TYPE
            ));
        }

        Block::decode(any.value.as_slice())
            .with_context(|| format!("decoding the Firehose block for {number}"))
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::{BlockNumber, Reference, SingleBlockRequest};

    /// `reference` is a three-armed oneof and the other two arms address a block by hash+number or
    /// by cursor. Picking the wrong one would still compile and still be a valid request, so pin
    /// that a fetch goes out on the block-number arm (tag 3) carrying the height.
    #[test]
    fn a_single_block_request_addresses_the_block_by_number() {
        let encoded = SingleBlockRequest {
            reference: Some(Reference::BlockNumber(BlockNumber { num: 49_663_794 })),
            ..Default::default()
        }
        .encode_to_vec();

        // field 3, wire type 2 (length-delimited) => 0x1a, then the nested message.
        assert_eq!(encoded[0], 0x1a);
        assert_eq!(
            BlockNumber::decode(&encoded[2..])
                .expect("the nested message decodes")
                .num,
            49_663_794
        );
    }
}
