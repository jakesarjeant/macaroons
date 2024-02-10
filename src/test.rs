use std::ops::Range;

use crate::{Caveat, Macaroon};
use crypto_common::KeyInit;
use hmac::Hmac;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
enum CaveatError {
	#[error("Forbidden")]
	Forbidden,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct BoolCaveat;
impl Caveat for BoolCaveat {
	type Error = CaveatError;
	type Context = bool;

	fn verify(&self, ctx: &Self::Context) -> Result<(), Self::Error> {
		if *ctx {
			Ok(())
		} else {
			Err(CaveatError::Forbidden)
		}
	}
}

#[test]
fn create_macaroon_with_hmac_key() {
	let key = <Hmac<Sha512> as KeyInit>::generate_key(&mut OsRng);

	let macaroon: Macaroon<BoolCaveat, Hmac<Sha512>> = Macaroon::new("mymacaroon", key);

	assert!(macaroon.verify(key, &true).is_ok());
}

#[test]
fn create_macaroon_with_arbitrary_secret() {
	let key = b"mysecretkey";

	let macaroon: Macaroon<BoolCaveat, Hmac<Sha512>> = Macaroon::new("mymacaroon", key);

	assert!(macaroon.verify(key, &true).is_ok());
}

#[test]
fn caveats_can_reject() {
	let key = b"mysecretkey";

	let macaroon: Macaroon<BoolCaveat, Hmac<Sha512>> =
		Macaroon::new("mymacaroon", key).attenuate(BoolCaveat);

	assert_eq!(
		macaroon.verify(key, &false),
		Err(crate::VerificationError::CaveatFailed(
			CaveatError::Forbidden
		))
	);
}

#[test]
fn caveats_can_pass() {
	let key = b"mysecretkey";

	let macaroon: Macaroon<BoolCaveat, Hmac<Sha512>> =
		Macaroon::new("mymacaroon", key).attenuate(BoolCaveat);

	assert!(macaroon.verify(key, &true).is_ok())
}

#[test]
fn invalid_signature_rejects() {
	let key = b"mysecretkey";

	let macaroon: Macaroon<BoolCaveat, Hmac<Sha512>> =
		Macaroon::new("mymacaroon", "nottherightkey").attenuate(BoolCaveat);

	assert_eq!(
		macaroon.verify(key, &true),
		Err(crate::VerificationError::InvalidToken)
	)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RangeCaveat(Range<usize>);
impl Caveat for RangeCaveat {
	type Error = CaveatError;
	type Context = usize;

	fn verify(&self, ctx: &Self::Context) -> Result<(), Self::Error> {
		if self.0.contains(ctx) {
			Ok(())
		} else {
			Err(CaveatError::Forbidden)
		}
	}
}

#[test]
fn simple_range() {
	let key = b"mysecretkey";

	let macaroon: Macaroon<RangeCaveat, Hmac<Sha512>> =
		Macaroon::new("mymacaroon", key).attenuate(RangeCaveat(14..18));

	let error = Err(crate::VerificationError::CaveatFailed(
		CaveatError::Forbidden,
	));

	assert_eq!(macaroon.verify(key, &12), error);
	assert_eq!(macaroon.verify(key, &13), error);
	assert!(macaroon.verify(key, &14).is_ok());
	assert!(macaroon.verify(key, &15).is_ok());
	assert!(macaroon.verify(key, &16).is_ok());
	assert!(macaroon.verify(key, &17).is_ok());
	assert_eq!(macaroon.verify(key, &18), error);
	assert_eq!(macaroon.verify(key, &19), error);
}

#[test]
fn nested_ranges() {
	let key = b"mysecretkey";

	let macaroon: Macaroon<RangeCaveat, Hmac<Sha512>> = Macaroon::new("mymacaroon", key)
		.attenuate(RangeCaveat(10..20))
		.attenuate(RangeCaveat(14..18));

	let error = Err(crate::VerificationError::CaveatFailed(
		CaveatError::Forbidden,
	));

	assert_eq!(macaroon.verify(key, &12), error);
	assert_eq!(macaroon.verify(key, &13), error);
	assert!(macaroon.verify(key, &14).is_ok());
	assert!(macaroon.verify(key, &15).is_ok());
	assert!(macaroon.verify(key, &16).is_ok());
	assert!(macaroon.verify(key, &17).is_ok());
	assert_eq!(macaroon.verify(key, &18), error);
	assert_eq!(macaroon.verify(key, &19), error);
}

#[test]
fn overlapping_ranges() {
	let key = b"mysecretkey";

	let macaroon: Macaroon<RangeCaveat, Hmac<Sha512>> = Macaroon::new("mymacaroon", key)
		.attenuate(RangeCaveat(10..16))
		.attenuate(RangeCaveat(14..18));

	let error = Err(crate::VerificationError::CaveatFailed(
		CaveatError::Forbidden,
	));

	assert_eq!(macaroon.verify(key, &9), error);
	assert_eq!(macaroon.verify(key, &10), error);
	assert_eq!(macaroon.verify(key, &11), error);
	assert_eq!(macaroon.verify(key, &12), error);
	assert_eq!(macaroon.verify(key, &13), error);
	assert!(macaroon.verify(key, &14).is_ok());
	assert!(macaroon.verify(key, &15).is_ok());
	assert_eq!(macaroon.verify(key, &16), error);
	assert_eq!(macaroon.verify(key, &17), error);
	assert_eq!(macaroon.verify(key, &18), error);
	assert_eq!(macaroon.verify(key, &19), error);
}

#[test]
fn disjointed_ranges() {
	let key = b"mysecretkey";

	let macaroon: Macaroon<RangeCaveat, Hmac<Sha512>> = Macaroon::new("mymacaroon", key)
		.attenuate(RangeCaveat(10..14))
		.attenuate(RangeCaveat(16..18));

	let error = Err(crate::VerificationError::CaveatFailed(
		CaveatError::Forbidden,
	));

	assert_eq!(macaroon.verify(key, &9), error);
	assert_eq!(macaroon.verify(key, &10), error);
	assert_eq!(macaroon.verify(key, &11), error);
	assert_eq!(macaroon.verify(key, &12), error);
	assert_eq!(macaroon.verify(key, &13), error);
	assert_eq!(macaroon.verify(key, &14), error);
	assert_eq!(macaroon.verify(key, &15), error);
	assert_eq!(macaroon.verify(key, &16), error);
	assert_eq!(macaroon.verify(key, &17), error);
	assert_eq!(macaroon.verify(key, &18), error);
	assert_eq!(macaroon.verify(key, &19), error);
}

#[test]
fn verify_deserialized() {
	let key = b"mysecretkey";

	let original_macaroon: Macaroon<RangeCaveat, Hmac<Sha512>> = Macaroon::new("mymacaroon", key)
		.attenuate(RangeCaveat(10..16))
		.attenuate(RangeCaveat(14..18));

	let serialized =
		serde_json::to_string(&original_macaroon).expect("Failed to serialize macaroon");

	let macaroon: Macaroon<RangeCaveat, Hmac<Sha512>> =
		serde_json::from_str(&serialized).expect("Failed to deserialize macaroon");

	let error = Err(crate::VerificationError::CaveatFailed(
		CaveatError::Forbidden,
	));

	assert_eq!(macaroon.verify(key, &9), error);
	assert_eq!(macaroon.verify(key, &10), error);
	assert_eq!(macaroon.verify(key, &11), error);
	assert_eq!(macaroon.verify(key, &12), error);
	assert_eq!(macaroon.verify(key, &13), error);
	assert!(macaroon.verify(key, &14).is_ok());
	assert!(macaroon.verify(key, &15).is_ok());
	assert_eq!(macaroon.verify(key, &16), error);
	assert_eq!(macaroon.verify(key, &17), error);
	assert_eq!(macaroon.verify(key, &18), error);
	assert_eq!(macaroon.verify(key, &19), error);
}

#[derive(Serialize, Deserialize)]
struct AbstractRangeCaveat(Range<usize>);

#[test]
fn client_side_refine() {
	let key = b"mysecretkey";

	let original_macaroon: Macaroon<RangeCaveat, Hmac<Sha512>> =
		Macaroon::new("mymacaroon", key).attenuate(RangeCaveat(10..16));

	let serialized =
		serde_json::to_string(&original_macaroon).expect("Failed to serialize macaroon");

	let serialized = {
		let client_macaroon: Macaroon<AbstractRangeCaveat, Hmac<Sha512>> =
			serde_json::from_str(&serialized).expect("Failed to deserialize macaroon");

		let new_macaroon = client_macaroon.attenuate(AbstractRangeCaveat(14..18));

		serde_json::to_string(&new_macaroon).expect("Failed to re-serialize macaroon")
	};

	let macaroon: Macaroon<RangeCaveat, Hmac<Sha512>> =
		serde_json::from_str(&serialized).expect("Failed to deserialize macaroon");

	let error = Err(crate::VerificationError::CaveatFailed(
		CaveatError::Forbidden,
	));

	assert_eq!(macaroon.verify(key, &9), error);
	assert_eq!(macaroon.verify(key, &10), error);
	assert_eq!(macaroon.verify(key, &11), error);
	assert_eq!(macaroon.verify(key, &12), error);
	assert_eq!(macaroon.verify(key, &13), error);
	assert!(macaroon.verify(key, &14).is_ok());
	assert!(macaroon.verify(key, &15).is_ok());
	assert_eq!(macaroon.verify(key, &16), error);
	assert_eq!(macaroon.verify(key, &17), error);
	assert_eq!(macaroon.verify(key, &18), error);
	assert_eq!(macaroon.verify(key, &19), error);
}
