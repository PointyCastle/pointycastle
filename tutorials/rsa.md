# RSA

This article describes how to use the Pointy Castle package, an
implementation of cryptographic algorithms for use with the Dart
programming language, to use the RSA algorithm to:

- generate a key pair;
- create a signature and to verify a signature;
- encrypt and decrypt.

## Overview

The RSA (Rivest Shamir Adleman) algorithm is an asymmetric
cryptographic algorithm (also known as a public-key algorithm). It
uses two keys: a public key that is used for encrypting data and
verifying signatures, and a private key that is used for decrypting
data and creating signatures.

## Generating RSA key pairs

To generate a pair of RSA keys:

1. Obtain a `SecureRandom` number generator.
2. Instantiate an `RSAKeyGenrator` object.
3. Initialize the key generator object with the secure random number generator and other parameters.
4. Invoke the object's `generateKeyPair` method.

This is a function to generate an RSA key pair:

```dart
import 'dart:math';
import 'dart:typed_data';

import "package:pointycastle/api.dart";
import 'package:pointycastle/asymmetric/api.dart';
import "package:pointycastle/key_generators/api.dart";
import 'package:pointycastle/random/fortuna_random.dart';

AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRSAkeyPair(
    SecureRandom secureRandom,
    {int bitLength = 2048}) {
  // Create an RSA key generator and initialize it

  final keyGen = RSAKeyGenerator()
      ..init(ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
          secureRandom));

  // Use the generator

  final pair = keyGen.generateKeyPair();

  // Cast the generated key pair into the RSA key types

  final myPublic = pair.publicKey as RSAPublicKey;
  final myPrivate = pair.privateKey as RSAPrivateKey;

  return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(myPublic, myPrivate);
}

SecureRandom exampleSecureRandom() {
  final secureRandom = FortunaRandom();

  final seedSource = Random.secure();
  final seeds = <int>[];
  for (int i = 0; i < 32; i++) {
    seeds.add(seedSource.nextInt(255));
  }
  secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

  return secureRandom;
}

final pair = generateRSAkeyPair(exampleSecureRandom());
final public = pair.publicKey;
final private = pair.privateKey;
```

### Secure random number generator

The key generator requires an instance of `SecureRandom`. The above
example shows the use of the Fortuna random number generator
(initialized with a less-secure random seed), but other methods can be
used too.

### Implementation

#### Using the registry

If using the registry, invoke the  `KeyGenerator` factory  with the algorithm name of "RSA".

```dart
final keyGen = KeyGenerator('RSA');
```

#### Without the registry

If the registry is not used, explicitly import the libraries and instantiate the `RSAKeyGenerator` directly.

```dart
import "package:pointycastle/api.dart";
import 'package:pointycastle/asymmetric/api.dart';
import "package:pointycastle/key_generators/api.dart";

final keyGen = RSAKeyGenerator();
```

### Initialize

The RSA key generator must be initialized with both an
`RSAKeyGeneratorParameters` and the `SecureRandom` number generator.
This is done by creating a `ParametersWithRandom` with the two, and
passing that to the key generator `init` method.

```
SecureRandom mySecureRandom = ...

final rsaParams = RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64);
final paramsWithRnd = ParametersWithRandom(rsaParams, mySecureRandom);
keyGen.init(paramsWithRnd);
```

The `RSAKeyGeneratorParameters` has:

- the public exponent to use (must be an odd number)

- bit strength (e.g. 2048 or 4096)

- a certainty factor (the maximum number of rounds used by the
  Miller-Rabin primality test: larger numbers increase the probability
  a non-prime is correctly identified as being non-prime).

### Generation

Invoke the `generateKeyPair` method on the `RSAKeyGenrator` to
generate the key pair.

```
final pair = keyGen.generateKeyPair();

final myPublic = pair.publicKey as RSAPublicKey;
final myPrivate = pair.privateKey as RSAPrivateKey;
```

It returns an `AsymmetricKeyPair<PublicKey,PrivateKey>`, so the type
for the `publicKey` and `privateKey` members are the abstract classes
`PublicKey` and `PrivateKey`.  The members will need to be cast into
an `RSAPublicKey` and `RSAPrivateKey` to use them as RSA keys.

## Signing and verifying

To create a signature:

1. Obtain an `RSAPrivateKey`.

2. Instantiate an `RSASigner` with the desired `Digest` algorithm
   object and an algorithm identifier.

3. Initialize the object for signing with the private key.

4. Invoke the object's `generateSignature` method with the data
   being signed.

To verify a signature:

1. Obtain an `RSAPublicKey`.

2. Instantiate an `RSASigner` with the desired `Digest` algorithm
   object and algorithm identifier.

3. Initialize the object for verification with the public key.

4. Invoke the object's `verifySignature` method with the data
   that was supposedly signed and the signature.

The following functions creates a signature and verifies a signature
using SHA-256 as the digest algorithm:

```
import "package:pointycastle/api.dart";
import 'package:pointycastle/asymmetric/api.dart';
import "package:pointycastle/digests/sha256.dart";
import "package:pointycastle/signers/rsa_signer.dart";

Uint8List rsaSign(RSAPrivateKey privateKey, Uint8List dataToSign) {

  final signer = RSASigner(SHA256Digest(), '0609608648016503040201');

  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey)); // true=sign

  final sig = signer.generateSignature(dataToSign);

  return sig.bytes;
}

bool rsaVerify(
    RSAPublicKey publicKey, Uint8List signedData, Uint8List signature) {
  final sig = RSASignature(signature);

  final verifier = RSASigner(SHA256Digest(), '0609608648016503040201');

  verifier.init(false, PublicKeyParameter<RSAPublicKey>(publicKey)); // false=verify

  try {
    return verifier.verifySignature(signedData, sig);
  } on ArgumentError {
	return false; // for Pointy Castle 1.0.2 when signature has been modified
  }
}
```

### Implementation

#### Using the registry

If using the registry, invoke the `Signer` factory with the name of
the digest algorithm and signing algorithm (e.g. "SHA-256/RSA" or
"SHA-1/RSA").

```
final signer = Signer('SHA-256/RSA');
```

#### Without the registry

If the registry is not used, explicitly import the libraries and
instantiate the objects directly. Instantiate a Digest object and pass
it as the first argument to the constructor for the `RSASigner`.

```
  final signer = RSASigner(SHA256Digest(), '0609608648016503040201');
```

The second parameter identifies the signing algorithm being used, and
will be incorporated into the signature. It **must** be the correct
value corresponding to the algorithm of the first parameter.

Its value is the hexadecimal string representation of the DER encoding
of an ASN.1 Object Identifier (OID).

For example, "0609608648016503040201" is the value for
2.16.840.1.101.3.4.2.1, which is the OID for SHA-256 (specifically:
joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
csor(3) nistAlgorithm(4) hashAlgs(2) sha256(1)). Note: that hex
encoding must includes a tag byte (0x06 as the first byte in this
example) and the length (0x09 in the second byte), as well as the
actual bytes representing the OID.

If the registry was used, the correct algorithm identifier is
automatically used. But when creating the objects directly, the
correct value must be found and entered into the code. The following
values were found in the source code for the `RSASigner` (the
_lib/signers/rsa_signer.dart_ file), in the `_DIGEST_IDENTIFIER_HEXES`
private member.

| Algorithm  | Object Identifier      | Hexadecimal encoding of DER |
|------------|------------------------|-----------------------------|
| MD2        | 1.2.840.113549.2.2     | 06082a864886f70d0202   |
| MD4        | 1.2.840.113549.2.4     | 06082a864886f70d0204   |
| MD5        | 1.2.840.113549.2.5     | 06082a864886f70d0205   |
| RIPEMD-128 | 1.3.36.3.2.2           | 06052b24030202         |
| RIPEMD-160 | 1.3.36.3.2.1           | 06052b24030201         |
| RIPEMD-256 | 1.3.36.3.2.3           | 06052b24030203         |
| SHA-1      | 1.3.14.3.2.26          | 06052b0e03021a         |
| SHA-224    | 2.16.840.1.101.3.4.2.4 | 0609608648016503040204 |
| SHA-256    | 2.16.840.1.101.3.4.2.1 | 0609608648016503040201 |
| SHA-384    | 2.16.840.1.101.3.4.2.2 | 0609608648016503040202 |
| SHA-512    | 2.16.840.1.101.3.4.2.3 | 0609608648016503040203 |

**Important:** both the signer and verifier must use the same value,
otherwise the signature will not validate.

### Initialize

Use the `init` method to initialize the signer. The first parameter
determines whether it can be used for signing, and the second
parameter is an RSA key.

For signing, use true and the private key.

```
  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
```

For verifying, use false and the public key.

```
  verifier.init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
```

### Sign

To generate a signature, pass the data being signed to
the `generateSignature` method.

It returns an `RSASignature`, from which the bytes making up the
signature can be obtained using the `bytes` getter.

```
Uint8List dataToSign = ...

final sig = signer.generateSignature(dataToSign);

final signatureBytes = sig.bytes;
```

### Verify

To verify a signature, pass the data that was supposedly signed and
the signature (as a `RSASignature` object) to the `verifySignature`
method.

It returns true if the signature is valid, otherwise it should return
false.

Note: in Pointy Castle 1.0.2 and earlier, `verifySignature` returns
false if the data had been modified, but will usually throw an
`ArgumentError` if the signature had been modified.

```
final sig = RSASignature(signatureBytes);

bool sigOk;
try {
  sigOk = verifier.verifySignature(signedData, sig);
} on ArgumentError {
  sigOk = false;
}
```

### Internal details

It is useful to know what is contained in the signature bytes, 
if the program needs to interoperate with another program
that was not implemented with Pointy Castle.

The signature is created from: the digest of the data, and the digest
algorithm identifier OID.

After calculating the digest over the data, a DER encoding is created
of an ASN.1 Object whose tag is 48 (0x30) which contains a sequence
of:

- (tag 0x30) ASN.1 OBJECT IDENTIFIER with the algorithm identifier
- (tag 0x05) ASN.1 NULL
- (tag 0x04) ASN.1 OCTET STRING containing the digest bytes

The value of the algorithm identifier is the Object Identifier that
was provided to the `init` method (as a hexadecimal string), but
ignoring its tag and always using 0x30 as the tag.

A block is created, whose size depends on the bit-length of the RSA
keys. The first byte of the block is a type code byte with the value
of 0x01, followed by as many 0xFF padding bytes as needed, a single
end-of-padding 0x00 byte, and finally the DER bytes.

The block is then processed with the private key. That is, the bytes
are interpreted as a large integer, the RSA formula is applied to that
large integer and numbers from the private key, and the resulting
number represented as bytes. Those final bytes are the bytes that make
up the signature.

When verifying a signature, a digest is calculated on the data that
was supposedly signed. A calculated block is created in the same way
(which is why verifier must be initialized with the same algorithm
identifier OID). The signature being verified is processed with the
public key, to produced a recovered block.  If the recovered block are
the same as the calculated block, then the signature is valid.

## RSA encryption and decryption

To encrypt using RSA and an asymmetric block cipher:

1. Instantiate an `AsymmetricalBlockCipher` object with an `RSAEngine` object.
2. Initialize the asymmetrical block cipher for encryption and with the public key.
3. Invoke the object's `processBlock` method with the plaintext blocks
   to produce the ciphertext blocks.

To decrypt using RSA and an asymmetric block cipher:

1. Instantiate an AsymmetricalBlockCipher object with an RSAEngine object.
2. Initialize the asymmetrical block cipher for decryption and with the private key.
3. Invoke the object's `processBlock` method with the ciphertext blocks
   to produce the plaintext blocks.


Pointy Castle has implementations of these asymmetric block ciphers:

- Optimal Asymmetric Encryption Padding (OAEP), implemented by the `OAEPEncoding` class
- PKCS #1, implemented by the `PKCS1Encoding` class.

Note: RFC 2437 says, "OAEP is recommended for new applications;
PKCS #1 is included only for compatibility with existing applications, and
is not recommended for new applications."

Pointy Castle implements the _Encoding Method for Encryption OAEP_
(EME-OAEP) from PKCS #1 version 2.0. The EME-OAEP in PKCS #1 version
2.1 was changed in a non-backward compatible way. Therefore, a program
written using Point Castle's implementation of OAEP cannot
interoperate with other programs that use OAEP from PKCS #1 version
2.1 or later.

The following functions encrypt and decrypt data using RSA with OAEP:

```dart
Uint8List rsaEncrypt(RSAPublicKey myPublic, Uint8List dataToEncrypt) {
  final encryptor = OAEPEncoding(RSAEngine())
    ..init(true, PublicKeyParameter<RSAPublicKey>(myPublic)); // true=encrypt

  return _processInBlocks(encryptor, dataToEncrypt);
}

Uint8List rsaDecrypt(RSAPrivateKey myPrivate, Uint8List cipherText) {
  final decryptor = OAEPEncoding(RSAEngine())
    ..init(false, PrivateKeyParameter<RSAPrivateKey>(myPrivate)); // false=decrypt

  return _processInBlocks(decryptor, cipherText);
}

Uint8List _processInBlocks(AsymmetricBlockCipher engine, Uint8List input) {
  final numBlocks = input.length ~/ engine.inputBlockSize +
      ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

  final output = Uint8List(numBlocks * engine.outputBlockSize);

  var inputOffset = 0;
  var outputOffset = 0;
  while (inputOffset < input.length) {
    final chunkSize = (inputOffset + engine.inputBlockSize <= input.length)
        ? engine.inputBlockSize
        : input.length - inputOffset;

    outputOffset += engine.processBlock(
        input, inputOffset, chunkSize, output, outputOffset);

    inputOffset += chunkSize;
  }

  return (output.length == outputOffset)
      ? output
      : output.sublist(0, outputOffset);
}
```

### Implementation

#### Using the registry

If using the registry, invoke the `AsymmetricBlockCipher` factory with
the name of the asymmetric block cipher: "RSA/OAEP", "RSA/PKCS1" or
"RSA".

```dart
final encryptor = AsymmetricBlockCipher('RSA/OAEP');
```

#### Without the registry

If the registry is not used, explicitly import the libraries and instantiate the object directly.

When creating the `PKCS1Encoding` and `OAEPEncoding`, the `RSAEngine`
needs to be provided to its constructor.

```dart
import "package:pointycastle/api.dart";
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';

final p = OAEPEncoding(RSAEngine());

// final p = PKCS1Encoding(RSAEngine());
```

### Initialization

Use the `init` method to initialize the asymmetric block cipher. The
first parameter determines whether it is used for encryption, and the
second parameter is an RSA key.

For encrypting, use true and the public key.

```dart
p.init(true, PublicKeyParameter<RSAPublicKey>(myPublic));
```

For decrypting, use false and the private key.

```dart
p.init(false, PrivateKeyParameter<RSAPrivateKey>(myPrivate));
```

### Providing the data

The data being encrypted/decrypted must be processed in blocks. Each
input block is processed into an output block.

The maximum size of a block can be obtained from the `inputBlockSize`
and `outputBlockSize` getters. They have different values, and
therefore care must be taken to use the correct size when stepping
through the input and output.

The values are a _maximum_, so the input blocks can be smaller. But
it usually only makes sense for the final block to be smaller, and all
the other blocks to be the maximum size.

The `processBlock` method has five arguments:

- the `Uint8List` where the input block is read from
- offset into the input where the block starts
- length of the input block
- the output `Uint8List` where the calculated block will be written to
- offset into the output where the block starts writing from

It returns the number of bytes written. Which is especially important
for the last block, which can be smaller than the maximum output block
size.

If the ciphertext cannot be decrypted, an `ArgumentError` is thrown.
The message associated with the `ArgumentError` can be ignored, since
it only describes the symptoms and not the cause: it does not help in
diagnosing why it failed.

Even if the ciphertext was successfully decrypted (i.e. no exception
was thrown), it does not guarantee the result is the same as the
plaintext that was encrypted. Encryption is designed to provides
confidentiality, and not integrity.  If data integrity is important,
additional mechanisms -- such as digests, HMACs or signatures --
should also be used.

### Internal details

#### OAEP

When encrypting in the OAEP asymmetric block cipher mode, the maximum
input block size is 41 bytes smaller than the maximum input block size
of the underlying RSA engine (Pointy Castle's implementation of OAEP
is hard-coded to use SHA-1 as its hash function).

For each input block, a block using the OAEP Encoding Method for
Encryption (EME-OAEP) is created. The EME-OAEP block is always the
maximum block size of the underlying RSA engine. The Mask Generation
Function used to create the block is the default MGF1 function. The
EME-OAEP block is encrypted by the underlying RSA engine (as described
below).

As mentioned before, Pointy Castle implements OAEP from PKCS #1
version 2.0. This is not compatible with OAEP from PKCS #1 version 2.1
or later.

#### PKCS #1

When encrypting in the PKCS #1 asymmetric block cipher mode, the
maximum input block size is always 10 bytes smaller than the maximum
input block size of the underlying RSA engine.

From each input block, another block is produced that is always the
maximum block size of the underlying RSA engine. This larger block
contains:

- a type code byte of 0x02;
- random non-zero padding bytes (at least eight bytes);
- end-of-padding zero byte (0x00); and
- all the bytes from the input block.

This expanded block is encrypted by the underlying RSA engine (as
described in the next section).

#### RSA

The `RSAEngine` encrypts by interpreting every byte of the entire
input block as a large integer.  The RSA formula is applied to that
large integer and the numbers from the public key, and the resulting
number represented as bytes. Those final bytes are the bytes that make
up the output block.

The `RSAEngine` must always be used with a padding scheme, such as
OAEP or PKCS #1 described above. RSA is a deterministic algorithm
which is vulnerable to various forms of attack if padding (and
preferably randomness) is added.

