#[cfg(test)]
mod test;
mod util;

use std::fmt::Debug;

use crypto_common::{KeyInit, KeySizeUser, OutputSizeUser};
use generic_array::GenericArray;
use hmac::Mac;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use util::{as_base64, from_base64};

impl<T> MacHelper for T where T: Mac + KeyInit {}
/// Helper for computing HMACs more conveniently:
trait MacHelper: Mac + KeyInit {
	fn process<K, T>(key: K, data: T) -> GenericArray<u8, Self::OutputSize>
	where
		K: AsRef<[u8]>,
		T: AsRef<[u8]>,
	{
		<Self as Mac>::new_from_slice(key.as_ref())
			.expect("HMAC should be able to handle keys of any size")
			.chain_update(data)
			.finalize()
			.into_bytes()
	}
}

/// Trait implementing the verification logic for a caveat. This trait need only be implemeted on
/// the server-side. Clients wanting to add their own caveats to tokens don't need this trait.
pub trait Caveat {
	type Error;
	type Context;

	/// Verify the caveat. Use the context for any information needed to properly check caveats.
	/// This method should return `Ok(())` if the caveat passes (i.e. the client is allowed to do what
	/// they're attempting to do) or `Err(...)` if the caveat prohibits the action the bearer is
	/// attempting.
	fn verify(&self, ctx: &Self::Context) -> Result<(), Self::Error>;
}

/// A macaroon token. For an introduction to macaroons, see [fly.io's execellent blog post](https://fly.io/blog/macaroons-escalated-quickly/).
/// Our format isn't exactly the same as the one in their examples, but it's very similar.
///
/// To generate a new macaroon on the server side, see [`Macaroon::new`](`Macaroon::new`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Macaroon<C, M>(
	String,
	Vec<C>,
	#[serde(
		bound = "",
		serialize_with = "as_base64::<M, _>",
		deserialize_with = "from_base64::<M, _>"
	)]
	GenericArray<u8, <M as OutputSizeUser>::OutputSize>,
)
where
	M: OutputSizeUser;

impl<C, M> Macaroon<C, M>
where
	M: Mac + KeySizeUser + KeyInit,
	C: Serialize,
{
	/// Add a caveat to a token. See the documentation of [`Macaroon::new`](`Macaroon::new`) for an example.
	pub fn attenuate(mut self, caveat: C) -> Self {
		self.2 = M::process(
			&self.2,
			// TODO: should we really unwrap?
			canonical_json::to_string(&json!(caveat))
				.expect("JSON serialization shouldn't be fallible")
				.into_bytes(),
		);
		self.1.push(caveat);
		self
	}

	/// Get the tail of the caveat. Useful e.g. for generating and checking third party caveats.
	pub fn tail(&self) -> &GenericArray<u8, <M as OutputSizeUser>::OutputSize> {
		&self.2
	}
}

impl<C, M> Macaroon<C, M>
where
	M: Mac + KeySizeUser + KeyInit,
	C: Caveat + Serialize,
{
	/// Create a new macaroon given a key, caveat type, hmac function and token identifier.
	///
	/// To create a macaroon, you need to first define the caveats. To do this, create a type that
	/// implements [`Caveat`]:
	///
	/// ```
	/// use rustmacaroon::Caveat;
	/// use anyhow::anyhow;
	/// use serde::{Serialize, Deserialize};
	///
	/// #[derive(Serialize, Deserialize)]
	/// enum MyCaveats {
	///   Path(String),
	///   Readonly,
	/// }
	///
	/// struct Request {
	///   path: String,
	///   is_write: bool
	/// }
	///
	/// impl Caveat for MyCaveats {
	///   type Error = anyhow::Error;
	///   type Context = Request;
	///
	///   fn verify(&self, ctx: &Self::Context) -> Result<(), Self::Error> {
	///     match self {
	///       MyCaveats::Path(path) if path != ctx.path => Err(anyhow!("You can only access path {path}")),
	///       MyCaveats::Readonly if ctx.is_write => Err(anyhow!("You can only read")),
	///       _ => Ok(())
	///     }
	///   }
	/// }
	/// ```
	///
	/// > Note: If you're only a client and just want to add a caveat but not verify caveats, **you
	/// do not need to implement the `Caveat` trait**.
	///
	/// When verifying, caveats have access to a user-defined "context". This is everything the
	/// verifier needs to know in order to accurately verify the caveat. For example, in a web
	/// server, the context might be the request the user is making.
	///
	/// This caveat type provides the validation logic for your macaroon. Now, you can create a
	/// token:
	///
	/// ```
	/// use sha2::Sha256;
	/// use hmac::{Hmac};
	///
	/// let key = b"mysecretkey";
	///
	/// // Note that the token ID ("asdfghjkl" here) should be some (ideally random) byte array or
	/// // string that uniquely identifies this token.
	/// let macaroon: Macaroon<MyCaveats, Hmac<Sha256>> = Macaroon::new(
	///   "asdfghjkl",
	///   &key,
	/// );
	///
	/// // Add some caveats:
	/// let macaroon = macaroon
	///   .attenuate(MyCaveats::Path("/images"))
	///   .attenuate(MyCaveats::Readonly);
	/// ```
	///
	/// Use [`verify`](`Macaroon::verify`) to check your token's signature and validate all caveats.
	/// [`verify`](`Macaroon::verify`) will only return `Ok(())` if the signature is valid and every
	/// caveat passes:
	///
	/// ```
	/// // Error: You can only read
	/// assert!(
	///   macaroon.verify(key, Request {
	///     path: "/images",
	///     is_write: true
	///   }).is_err()
	/// );
	///
	/// // Okay!
	/// assert!(
	///   macaroon.verify(key, Request {
	///     path: "/images",
	///     is_write: false
	///   }).is_ok()
	/// );
	/// ```
	pub fn new<T, K>(id: T, key: K) -> Self
	where
		T: AsRef<str>,
		K: AsRef<[u8]>,
	{
		Macaroon(
			String::from(id.as_ref()),
			Vec::new(),
			M::process(key, id.as_ref()),
		)
	}

	/// Check the signature and verify every caveat. See the documentation of
	/// [`Macaroon::new`](`Macaroon::new`) for an example.
	pub fn verify<K>(&self, key: K, ctx: &C::Context) -> Result<(), VerificationError<C>>
	where
		K: AsRef<[u8]>,
	{
		let expected_signature = std::iter::once(self.0.as_bytes().to_vec())
			.chain(
				self.1
					.iter()
					// TODO: maybe don't unwrap?
					.map(|c| canonical_json::to_string(&json!(c)).unwrap().into_bytes()),
			)
			.fold(key.as_ref().to_vec(), |key, data| {
				M::process(key, data).to_vec()
			});

		if expected_signature != self.2.as_slice() {
			return Err(VerificationError::InvalidToken);
		}

		self.1
			.iter()
			.try_for_each(|caveat| caveat.verify(ctx))
			.map_err(|e| VerificationError::CaveatFailed(e))
	}
}

/// Encodes a failure to verify a token.
#[derive(Debug, Clone, Error, PartialEq)]
pub enum VerificationError<C>
where
	C: Caveat,
{
	/// The token is properly signed, but one of the caveats forbids the attempted action.
	#[error("This token is not authorized for the attempted action")]
	CaveatFailed(C::Error),
	/// The token is either not valid as a whole or has an incorrect or forged signature.
	#[error("The token isn't a properly constructed Macaroon or its signature is not valid")]
	InvalidToken,
}
