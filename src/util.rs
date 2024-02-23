use base64::{engine::general_purpose::URL_SAFE, Engine};
use crypto_common::OutputSizeUser;
use generic_array::GenericArray;
use serde::{Deserialize, Deserializer, Serializer};

// https://github.com/serde-rs/serde/issues/661
pub fn as_base64<M, S>(
	data: &GenericArray<u8, <M as OutputSizeUser>::OutputSize>,
	serializer: S,
) -> Result<S::Ok, S::Error>
where
	S: Serializer,
	M: OutputSizeUser,
{
	serializer.serialize_str(&URL_SAFE.encode(&data[..]))
}

pub fn from_base64<'de, M, D>(
	deserializer: D,
) -> Result<GenericArray<u8, <M as OutputSizeUser>::OutputSize>, D::Error>
where
	D: Deserializer<'de>,
	M: OutputSizeUser,
{
	use serde::de::Error;
	String::deserialize(deserializer)
		.and_then(|string| {
			URL_SAFE
				.decode(&string)
				.map_err(|err| Error::custom(err.to_string()))
		})
		.map(|bytes| GenericArray::from_slice(&bytes).clone())
}
