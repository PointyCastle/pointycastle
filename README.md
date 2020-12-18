# **!!! Important Message !!!**

This project is being relicensed from a combination of the
"GNU LESSER GENERAL PUBLIC LICENSE 3.0" and "Mozilla Public License 2.0"
to the Bouncy Castle license. The new license can be read in the LICENSE file.

Subsequent to this change, this library will be transitioned into the
Bouncy Castle project. The Bouncy Castle team will take over the maintenance
and development of this library.

See https://github.com/bcgit/pc-dart for the new code.


Pointy Castle
=============

A Dart library for encryption and decryption. In this release, most of the classes
are ports of Bouncy Castle from Java to Dart. The porting is almost always
direct except for some classes that had been added to ease the use of low level
data.

To make sure nothing fails, tests and benchmarks for every algorithm are
provided. The expected results are taken from the Bouncy Castle Java version
and also from standards, and matched against the results got from Pointy Castle.

## Algorithms

In this release, the following algorithms are implemented:

**Block ciphers:**
  * AES

**Asymmetric block ciphers:**
  * RSA

**Asymmetric block cipher encodings:**
  * PKCS1
  * OAEP

**Stream ciphers:**
  * Salsa20

**Block cipher modes of operation:**
  * CBC (Cipher Block Chaining mode)
  * CFB (Cipher Feedback mode)
  * ECB (Electronic Code Book mode)
  * GCTR (GOST 28147 OFB counter mode)
  * OFB (Output FeedBack mode)
  * CTR (Counter mode)
  * SIC

**Paddings:**
  * PKCS7
  * ISO7816-4

**Digests:**
  * Blake2b
  * MD2
  * MD4
  * MD5
  * RIPEMD-128|160|256|320
  * SHA-1
  * SHA-224|256|384|512
  * SHA-512/t (t=8 to 376 and 392 to 504 in multiples of 8)
  * Keccak-224|256|384|512*
  * Tiger
  * Whirlpool

*_Keccak is currently implemented as SHA3Digest._

**MACs:**
  * HMAC
  * CMAC

**Signatures:**
  * (DET-)ECDSA
  * RSA

**Password based key derivators:**
  * PBKDF2
  * scrypt

**Asymmetric key generators:**
  * ECDSA
  * RSA

**Secure PRNGs:**
  * Based on block cipher in CTR mode
  * Based on block cipher in CTR mode with auto reseed (for forward security)
  * Based on Fortuna algorithm

### Instantiating implementation objects

There are two ways to instantiate objects that implement the
algorithms:

- using the registry, or
- without the registry.

#### Using the registry

Using the registry, the algorithm name is provided to high-level class
factories.

This is especially convenient when an algorithm involves multiple
algorithm implementation classes to implement. All the necessary
classes can all be instantiated with a single name
(e.g. "HMAC/SHA-256" or "SHA-1/HMAC/PBKDF2"), and they are
automatically combined together with the correct values.

To use the registry, either import `pointycastle.dart` or
`export.dart`.  For example,

```dart
import "package:pointycastle/pointycastle.dart";

final sha256 = Digest("SHA-256");
final sha1 = Digest("SHA-1");
final md5 = Digest("MD5");

final hmacSha256 = Mac("SHA-256/HMAC");
final hmacSha1 = Mac("SHA-1/HMAC");
final hmacMd5 = Mac("MD5/HMAC");

final derivator = KeyDerivator("SHA-1/HMAC/PBKDF2");

final signer = Signer("SHA-256/RSA");
```

#### Without the registry

Without the registry, each implementation class must be instantiated
using its constructor.

If an algorithm involves multiple algorithm implementation classes,
they each have to be individually instantiated and combined together
with the correct values.

To use the constructors, import `export.dart`.  For example,

``` dart
import "package:pointycastle/export.dart";

final sha256 = SHA256Digest();
final sha1 = SHA1Digest();
final md5 = MD5Digest();

final hmacSha256 = HMac(SHA256Digest(), 64);
final hmacSha512 = HMac(SHA512Digest(), 128);
final hmacMd5 = HMac(MD5Digest(), 64);

final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));

final signer = RSASigner(SHA256Digest(), '0609608648016503040201');
```

#### Registry vs without registry

Using the registry means that all algorithms will be imported by
default, which can increase the compiled size of your program.

To avoid this, instantiate **all** classes directly by using their
constructors.

### Importing libraries

There are two main approaches for importing Point Castle libraries:

- only import _pointycastle.dart_ (which includes the high-level API and
  the interfaces); or
- only import _export.dart_ (which includes the high-level API, interfaces
  and all the implementation classes).
  
It is also possible to import _api.dart_ (the high-level API) and
selectively import individual implementation classes as they are
needed. But this method requires a lot more programmer effort, and no
longer has any advantage over simply importing _export.dart_ and
relying Dart's tree shaking to leave out code that is not needed.

The registry can be used with any of these approaches. The different
approaches only affects access to the implementation classes.

Therefore, when avoiding the code size overheads of the registry, be
careful not to accidentally use the registry. Since the single use of
a factory from the registry will cause the entire registry to be
loaded.

## Tutorials

Some articles on how to use some of Pointy Castle's features can be
found under the _tutorials_ directory in the sources.

- [Calculating a digest](https://github.com/PointyCastle/pointycastle/blob/master/tutorials/digest.md) - calculating a hash or digest (e.g. SHA-256, SHA-1, MD5)
- [Calculating a HMAC](https://github.com/PointyCastle/pointycastle/blob/master/tutorials/hmac.md) - calculating a hash-based message authentication code (e.g. HMAC-SHA256, HMAC-SHA1)
- [Using AES-CBC](https://github.com/PointyCastle/pointycastle/blob/master/tutorials/aes-cbc.md) - block encryption and decryption with AES-CBC
- [Using RSA](https://github.com/PointyCastle/pointycastle/blob/master/tutorials/rsa.md) - key generation, signing/verifying, and encryption/decryption
- Some [tips](https://github.com/PointyCastle/pointycastle/blob/master/tutorials/tips.md) on using Pointy Castle

_Note: the above links are to the most recent versions on the master
branch on GitHub. They may be different from the version here._
