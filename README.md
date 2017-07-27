## Seekrit: Cryptography utilities for iOS and Mac OS X.

* Symmetric and asymmetric encryption using the [Curve25519](http://cr.yp.to/ecdh.html) elliptic-key algorithm (based on [libSodium](https://github.com/jedisct1/libsodium)). This offers much smaller keys than RSA (256 bits vs 2048 bits) and faster performance too; in particular, key generation is almost instantaneous.
* Digital signatures using [Ed25519](http://ed25519.cr.yp.to/) (also from [libSodium](https://github.com/jedisct1/libsodium)). Again, this offers much smaller signatures and faster signing and verification.
* [Digital signatures of JSON objects](https://github.com/couchbase/couchbase-lite-ios/wiki/Signed-Documents). Unlike other existing algorithms for this, it allows the signature to be stored within the object being signed, and allows the object to be parsed and re-encoded without breaking the signature. This makes it ideal for signing JSON documents used by Couchbase.
* Conversions of binary data to and from series of English words, for secure verbal exchange of secrets (based on [mnemonicode](https://github.com/singpolyma/mnemonicode)). For instance, a 256-bit public key converts to 24 words, which can be transcribed over the phone.
* QR code generation and scanning, for secure visual exchange of secrets. A public key converted to a QR code can be printed on a business card, published on a website, or transmitted directly from one device's screen to another's camera. Secret data can be transmitted securely between devices as long as you're reasonably careful to watch for eaveswatchers.

## Authors

The code in this repository was written by Jens Alfke, except for the iOS QR-code implementation and sample app, by Pasin Suriyentrakorn.

## Disclaimer

* This is sample code, not an official supported Couchbase product.
* This code has not been extensively tested.

## License

* Code in this repository: Apache 2.0
* libSodium: ISC License
* mnemonicode: Unnamed license, apparently BSD or MIT
