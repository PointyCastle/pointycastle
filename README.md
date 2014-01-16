cipher
======

A Dart library for encryption and decryption. As of today, most of the classes 
are ports of Bouncy Castle from Java to Dart. The porting is almost always 
direct except for some classes that had been added to ease the use of low level 
data.

To make sure nothing fails, tests and benchmarks for every algorithm are 
provided. The expected results are taken from the Bouncy Castle Java version 
and also from standards, and matched against the results got from cipher.

As of the last release, the following algorithms are implemented:


**Block ciphers:**

  * AES (fast version)


**Stream ciphers:**

  * Salsa 20


**Block cipher modes of operation:**

  * SIC (a.k.a. CTR)
  * CBC


**Paddings:**

  * PKCS7


**Digests:**

  * RIPEMD-160
  * SHA-1
  * SHA-256


**MACs:**

  * HMAC
  
  
**Signatures:**

  * ECDSA
  
  
**Password based key derivators:**

  * PBKDF2
  * scrypt
  
  
**Asymmetric key generators:**

  * ECDSA
  
  
**Entropy sources (true RNGs):**

  * URL based (can be used, for example, with random.org)
  * File based (can be used, for example, with /dev/random)
  
  
**Secure PRNGs:**

  * Based on block cipher in CTR mode
  * Based on block cipher in CTR mode with auto reseed (for forward security)
  
  
