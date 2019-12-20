Changelog
=========

#### Version TBD

* Fixed OAEPEncoding and PKCS1Encoding to use provided output offset value.
* Fixed RSA block length and offset checks in RSAEngine.processBlock.
* Fixed RSASigner.verifySignature to return false when signature is bad.
* Add optional `normalize` boolean on `generateSignature` and `normalize` function on `ECSignature` to convert an ecdsa signature to lower-s form

#### Version 1.0.2 (2019-11-15)

* Add non-Keccak SHA3 support
* Add CMAC support ("AES/CMAC")
* Add ISO7816-4 padding support
* Fixes in CBCBlockCipherMac and CMac

#### Version 1.0.1 (2019-02-20)

* Add Blake2b support

#### Version 1.0.0 (2018-12-17) (Dart SDK version 2.0)

* Support Dart 2 and Strong Mode
* Migrate from `package:bignum.BigInteger` to `dart:core.BigInt`
* Remove Quiver and fixnum dependency
* OAEP encoding for block ciphers


#### Version 0.10.0 (2016-02-04) (Dart SDK version 0.14.0)

* First Pointy Castle release.

* Reorganised file structure.

* Completely new Registry implementation that dynamically loads imported implementations using reflection.
  It is explained in [this commit](https://github.com/PointyCastle/pointycastle/commit/2da75e5a8d7bdbf95d08329add9f13b9070b75d4).

* Migrated from unittest to test package.


### cipher releases

#### Version 0.8.0 (2014-??-??) (Dart SDK version ???)

* **[bug 80]** PaddedBlockCipher doesn't add padding when data length is a multiple of the block 
                size. This fix introduces a **BREAKING CHANGE** in PaddedBlockCipher specification.
                Read its API documentation to know about the changes.


#### Version 0.7.0 (2014-03-22) (Dart SDK version 1.3.0-dev.5.2)

* **[enh 15]** Implement stream cipher benchmarks.
* **[enh 64]** Benchmark and optimize digests.
* **[enh 74]** Make SHA-3 usable in terms of speed.

* **[bug 67]** Removed some unused code.
* **[bug 68]** Fix process() method of PaddedBlockCipher.
* **[bug 75]** Remove a registry dependency in the Scrypt algorithm.
