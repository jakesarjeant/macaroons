<div align="center">
	<h1>RustMacaroon</h1>
	<p>
		<a href="https://docs.rs/rustmacaroon">docs.rs</a> |
		<a href="https://crates.io/crates/rustmacaroon">crates.io</a> |
		<a href="https://github.com/jakesarjeant/macaroons">github.com</a>
	</p>
	<p>
	<img alt="License: BSD 3-clause" src="https://img.shields.io/github/license/jakesarjeant/macaroons?color=orange&style=for-the-badge" />
	<img alt="Latest release" src="https://img.shields.io/crates/v/rustmacaroon?color=yellow&style=for-the-badge" />
	<img alt="Github issue counter" src="https://img.shields.io/github/issues/jakesarjeant/macaroons?style=for-the-badge" />
	</p>
</div>

<p align="center">
	<code>&lt;&gt;Rusty <a href="https://fly.io/blog/macaroons-escalated-quickly/">Macaroons!</a>&lt;/&gt;</code>
</p>

---

This is a Rust implementation of "Macaroon" authentication tokens. [Macaroons](http://research.google.com/pubs/pub41892.html) are a standard developed by google for decentralized or distributed authorization.

# 🙋 Macaroons?

Macaroons are a new type of bearer authorization token designed for distributed authorization. They are constructed by chaining together "caveats" that restrict their capabilities, allowing them to be restricted to a given user, organization, project, transaction size, or anything else you might want.

This authorization scheme has multiple benefits. First of all, by chaining together signatures, any clients can add new criteria to their tokens on their own. For example, a user with read-write access to a file could share it by adding a read-only requirement to his token and sharing the access token.

In addition to normal, locally verified requirement, macaroons introduce the notion of a "third-party caveat". these are caveats that rather than being checked locally are instead checked by an unknown service. If you want to learn more about how this works, I recommend [fly.io's excellent blog post on the topic](https://fly.io/blog/macaroons-escalated-quickly).

# ⚡ Get started

To generate macaroons, you first need to define the verification logic for your tokens' caveats. To do this, create a struct that implements `Caveat`:

```rust
use serde::{Serialize, Deserialize};
use rustmacaroon::Caveat;
use anyhow::anyhow;

#[derive(Serialize, Deserialize)]
struct MyCaveat {
  File {
    filename: String
  },
  Readonly
}

#[derive(Default)]
struct Request {
  filename: String,
  is_write: bool,
}

impl Caveat for MyCaveat {
  type Error = anyhow::Error;
  type Context = Request;

  fn verify(&self, req: &Self::Context) -> Result<(), Self::Error> {
    match self {
      MyCaveat::Readonly if !req.is_write => Ok(()),
      MyCaveat::Filename(f) if req.filename == f => Ok(()),
      _ => Err(anyhow!("Unauthorized!"))
    }
  }
}
```

Now, you can start generating macaroons. Macaroons are signed using HMAC, so rustmacaroon integrates with the `hamc` library:

```rs
use hmac::Hmac;
use sha2::Sha256;

let key = b"mysecretkey";

let macaroon: Macaroon<MyCaveat, Hmac<Sha256>> = Macaroon::new("macaroon id", key);

// Verify the macaroon. This one is always valid.
assert!(macaroon.verify(key, Default::default()).is_ok());

let macaroon = macaroon.attenuate(MyCaveat::Readonly);

assert!(macaroon.verify(key, &Request {
  is_write: true,
  ..Default::default()
}).is_err());
```

One of the powerful features of Macaroons is that you can attenuate macaroons on the client side! To do this, you just need share the Caveat type between the server and client codebase (although the `Caveat` trait implementation should live in a newtype in the server codebase; your client shouldn't need the authorization logic). Then, you can parse the macaroon with serde and attenuate it like normal!

# 🚧 What isn't supported

One powerful feature of Macaroons is the ability to verify third party caveats. Currently, this library doesn't provide built-in support for third-party caveats. However, if your application needs to support them, it is perfectly possible to implement third-party caveats on top of rustmacaroon. The reasons for this decision are many, but primarily the fact that they significantly complicate the API and many user-facing applications don't even really need or want to support them.

If anyone shows interest in support for this feature, third-party caveats may be added in a future version, but there's not currently any plan to do so otherwise.

---

<sup>Copyright © 2024 – Jake Sarjeant</sup>
