node-aes-gcm
============
[![NPM version][npm-image]][npm-url] [![Build Status][travis-image]][travis-url] [![Dependency Status][daviddm-image]][daviddm-url]

[AES][] [GCM][] module for [node.js][node] using OpenSSL

[AES]: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
[GCM]: http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
[GCMr]: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
[node]: http://nodejs.org
[crypto]: http://nodejs.org/api/crypto.html
[cryptogcm]: http://lollyrock.com/articles/nodejs-encryption/
[OpenSSL]: http://www.openssl.org/
[IV]: http://en.wikipedia.org/wiki/Initialization_vector

Installation
------------

`node-aes-gcm` is available through npm:

``` bash
$ npm install node-aes-gcm
```

Rationale
---------

The reason for the existence of this module is that the [node.js][node] [crypto][] module didn't use to expose a way to make use of the ability of [GCM (Galois Counter Mode)][GCM] to perform both encryption and authentication simultaneously when I needed it.  Since this functionality was available in [OpenSSL][] 1.0+, I wrote this thin wrapper around [OpenSSL][] to expose this functionality for use in [node.js][node].  Apparently, this functionality is now also available using the standard [crypto][] module as shown [in this example][cryptogcm].

[GCM][] is a useful mode to communicate securely with small embedded devices, because of its low operating overhead.  When combined with [node.js][node], large scalable systems can be designed. Another advantage is that it is unencumbered by patents.

While this module was originally written for my own use and was limited to a [AES-128][AES] cipher (128-bit key) and 96-bit [initialization vector][IV] (IV), the current version supports AES-128, AES-192 and AES-256 with any length of IV.  It generates a 128-bit authentication tag and includes support for additional authenticated data (AAD).

The module exports 2 functions: `encrypt` and `decrypt`.

encrypt
-------

`encrypt` has the following signature:

#### encrypt(key, iv, plaintext, aad)

* `key` is a 16, 24 or 32-byte `Buffer` object containing the [AES][] key used for encryption.
* `iv` is a `Buffer` object containing the initialization vector.
* `plaintext` is a `Buffer` object containing the plaintext to be encrypted.
* `aad` is a `Buffer` object containing the additional authenticated data that is not encrypted but is anthenticated by the authentication tag.

All parameters are required.  If a parameter is not used (which may often be the case for `aad`), an empty buffer should be specified (for example: `new Buffer([])`).

The `encrypt` function returns an object containing the following items:

``` javascript
{
  ciphertext: Buffer,
  auth_tag: Buffer
}
```

* `ciphertext` is a `Buffer` object containing the encrypted data.
* `auth_tag` is a 16-byte `Buffer` object containing the authentication tag that is used by the `decrypt` function to verify the correctness and authenticity of both the encrypted data and the additional authenticated data.

decrypt
-------

`decrypt` has the following signature:

#### decrypt(key, iv, ciphertext, aad, auth_tag)

* `key` is a 16, 24 or 32-byte `Buffer` object containing the [AES][] key used for encryption.
* `iv` is a `Buffer` object containing the initialization vector.
* `ciphertext` is a `Buffer` object containing the ciphertext to be decrypted.
* `aad` is a `Buffer` object containing the additional authenticated data that was used when encryption was done and that is hashed into the authentication tag.
* `auth_tag` is a 16-byte `Buffer` object containing the authentication tag that verifies the correctness and authenticity of both the encrypted data end the additional authenticated data.

All parameters are required.  If a parameter is not used (which may often be the case for `aad`), an empty buffer should be specified (for example: `new Buffer([])`).

The `decrypt` function returns an object containing the following items:

``` javascript
{
  plaintext: Buffer,
  auth_ok: Boolean
}
```

* `plaintext` is a `Buffer` object containing the decrypted data.
* `auth_ok` is a Boolean indicating whether the encrypted data and additional authenticated data passed verification (`true`) or failed (`false`).

Examples
--------

The following example is shows an interactive node session using this module to execute Test Case 3 from the NIST [GCM revised spec][GCMr]:

``` javascript
> gcm = require('node-aes-gcm')
{ encrypt: [Function], decrypt: [Function] }
> key = new Buffer([0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08])
<Buffer fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08>
> iv = new Buffer([0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88])
<Buffer ca fe ba be fa ce db ad de ca f8 88>
> plaintext = new Buffer([0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55])
<Buffer d9 31 32 25 f8 84 06 e5 a5 59 09 c5 af f5 26 9a 86 a7 a9 53 15 34 f7 da 2e 4c 30 3d 8a 31 8a 72 1c 3c 0c 95 95 68 09 53 2f cf 0e 24 49 a6 b5 25 b1 6a ed ...>
> e = gcm.encrypt(key, iv, plaintext, new Buffer([]))
{ ciphertext: <Buffer 42 83 1e c2 21 77 74 24 4b 72 21 b7 84 d0 d4 9c e3 aa 21 2f 2c 02 a4 e0 35 c1 7e 23 29 ac a1 2e 21 d5 14 b2 54 66 93 1c 7d 8f 6a 5a ac 84 aa 05 1b a3 0b ...>,
  auth_tag: <Buffer 4d 5c 2a f3 27 cd 64 a6 2c f3 5a bd 2b a6 fa b4> }
> d = gcm.decrypt(key, iv, e.ciphertext, new Buffer([]), e.auth_tag)
{ plaintext: <Buffer d9 31 32 25 f8 84 06 e5 a5 59 09 c5 af f5 26 9a 86 a7 a9 53 15 34 f7 da 2e 4c 30 3d 8a 31 8a 72 1c 3c 0c 95 95 68 09 53 2f cf 0e 24 49 a6 b5 25 b1 6a ed ...>,
  auth_ok: true }

```

An extensive test script is provided that covers all NIST [GCM revised spec][GCMr] test cases and can be used as a reference example.

[npm-image]: https://badge.fury.io/js/node-aes-gcm.svg
[npm-url]: https://npmjs.org/package/node-aes-gcm
[travis-image]: https://travis-ci.org/xorbit/node-aes-gcm.svg?branch=master
[travis-url]: https://travis-ci.org/xorbit/node-aes-gcm
[daviddm-image]: https://david-dm.org/xorbit/node-aes-gcm.svg?theme=shields.io
[daviddm-url]: https://david-dm.org/xorbit/node-aes-gcm

