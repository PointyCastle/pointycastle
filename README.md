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


**Stream ciphers:**
  * Salsa 20


**Block ciphers:**
  * AES (fast version)


**Block cipher modes of operation:**
  * SIC (a.k.a. CTR)


**Digests:**
  * RIPEMD160
