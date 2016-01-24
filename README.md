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

  * AES


**Asymmetric block ciphers:**

  * RSA


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


**Digests:**

  * MD2
  * MD4
  * MD5
  * RIPEMD-128
  * RIPEMD-160
  * RIPEMD-256
  * RIPEMD-320
  * SHA-1
  * SHA-224
  * SHA-256
  * SHA-3
  * SHA-384
  * SHA-512
  * SHA-512/t
  * Tiger
  * Whirlpool


**MACs:**

  * HMAC
  
  
**Signatures:**

  * (DET-)ECDSA
  * RSA
  
  
**Password based key derivators:**

  * PBKDF2
  * scrypt
  
  
**Asymmetric key generators:**

  * ECDSA
  * RSA
  
  
**Entropy sources (true RNGs):**

  * URL based (can be used, for example, with random.org)
  * File based (can be used, for example, with /dev/random)
  
  
**Secure PRNGs:**

  * Based on block cipher in CTR mode
  * Based on block cipher in CTR mode with auto reseed (for forward security)
  * Based on Fortuna algorithm
  
  
