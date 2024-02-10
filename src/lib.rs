use std::fmt::Debug;

use crypto_common::OutputSizeUser;
use generic_array::{ArrayLength, GenericArray};
use hmac::Mac;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Macaroon<M>(String, Caveat<M>, #[cfg_attr(feature = "serde", serde(skip))] M);

enum Caveat<M> {}