cipher
======

A Dart library for encryption/decryption mainly based on Bouncy Castle Java
library. Most of the classes are ports of Bouncy Castle from Java to Dart. The
porting is almost always direct except for some classes that had been added to
ease the use of low level data.

Tests and benchmarks for every algorithm are also provided. The expected results
for the tests are computed with the Bouncy Castle Java version and matched
against the results got from Dart. Following is a list of the algorithms
implemented in the last release.

**Stream ciphers:**
- Salsa 20

**Block ciphers:**
- AES (fast version)

**Block cipher modes of operation:**
- SIC (a.k.a. CTR)

**Digests:**
- RIPEMD160
