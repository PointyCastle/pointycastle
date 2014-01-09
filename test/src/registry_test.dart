// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.registry_test;

import "package:cipher/cipher.dart";

import "package:unittest/unittest.dart";
import "package:unittest/matcher.dart";

void main() {

  initCipher();

  group( "registry:", () {

    test( "initCipher() can be called several times", () {

      initCipher();
      initCipher();

    });

    test( "Digest returns valid implementations", () {

      _testDigest( "RIPEMD-160" );
      _testDigest( "SHA-1" );
      _testDigest( "SHA-256" );

    });

    test( "ECDomainParameters returns valid implementations", () {

      _testECDomainParameters( "prime192v1" );

    });

    test( "BlockCipher returns valid implementations", () {

      _testBlockCipher( "AES" );

    });

    test( "StreamCipher returns valid implementations", () {

      _testStreamCipher( "Salsa20" );
      _testStreamCipher( "AES/SIC" );
      _testStreamCipher( "AES/CTR" );

    });

    test( "EntropySource returns valid implementations", () {

      _testEntropySource( "file:///dev/random" );
      _testEntropySource( "http://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f" );
      _testEntropySource( "https://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f" );

    });

    test( "KeyFactory returns valid implementations", () {

      _testKeyFactory( "SHA-1/HMAC/PBKDF2" );
      _testKeyFactory( "scrypt" );

    });

    test( "Mac returns valid implementations", () {

      _testMac( "SHA-1/HMAC" );
      _testMac( "SHA-256/HMAC" );
      _testMac( "RIPEMD-160/HMAC" );

    });

    test( "ChainingBlockCipher returns valid implementations", () {

      _testChainingBlockCipher( "AES/SIC" );
      _testChainingBlockCipher( "AES/CTR" );
      _testChainingBlockCipher( "AES/CBC" );

    });

    test( "PaddedBlockCipher returns valid implementations", () {

      _testPaddedBlockCipher( "AES/SIC/PKCS7" );

    });

    test( "Padding returns valid implementations", () {

      _testPadding( "PKCS7" );

    });

    test( "SecureRandom returns valid implementations", () {

      _testSecureRandom( "AES/CTR/PRNG" );
      _testSecureRandom( "AES/CTR/AUTO-SEED-PRNG" );

    });

    test( "Signer returns valid implementations", () {

  		_testSigner( "ECDSA" );

    });

  });

}

void _testBlockCipher( String algorithmName ) {
  var cipher = new BlockCipher(algorithmName);
  expect( cipher, new isInstanceOf<BlockCipher>("BlockCipher") );
  expect( cipher.algorithmName, algorithmName );
}

void _testStreamCipher( String algorithmName ) {
  var cipher = new StreamCipher(algorithmName);
  expect( cipher, new isInstanceOf<StreamCipher>("StreamCipher") );
  expect( cipher.algorithmName, algorithmName );
}

void _testDigest( String algorithmName ) {
  var digest = new Digest(algorithmName);
  expect( digest, new isInstanceOf<Digest>("Digest") );
  expect( digest.algorithmName, algorithmName );
}

void _testKeyFactory( String algorithmName ) {
  var kf = new KeyFactory(algorithmName);
  expect( kf, new isInstanceOf<KeyFactory>("KeyFactory") );
  expect( kf.algorithmName, algorithmName );
}

void _testMac( String algorithmName ) {
  var mac = new Mac(algorithmName);
  expect( mac, new isInstanceOf<Mac>("Mac") );
  expect( mac.algorithmName, algorithmName );
}

void _testPadding( String algorithmName ) {
  var padding = new Padding(algorithmName);
  expect( padding, new isInstanceOf<Padding>("Padding") );
  expect( padding.algorithmName, algorithmName );
}

void _testChainingBlockCipher( String algorithmName ) {
  var parts = algorithmName.split("/");

  var cbc = new ChainingBlockCipher(algorithmName);
  expect( cbc, new isInstanceOf<ChainingBlockCipher>("ChainingBlockCipher") );
  expect( cbc.algorithmName, equals(algorithmName) );

  var bc = cbc.underlyingCipher;
  expect( bc, new isInstanceOf<BlockCipher>("BlockCipher") );
  expect( bc.algorithmName, equals(parts[0]) );
}

void _testPaddedBlockCipher( String algorithmName ) {
  var parts = algorithmName.split("/");

  var pbc = new PaddedBlockCipher(algorithmName);
  expect( pbc, new isInstanceOf<PaddedBlockCipher>("PaddedBlockCipher") );
  expect( pbc.algorithmName, algorithmName );

  var padding = pbc.padding;
  expect( padding, new isInstanceOf<Padding>("Padding") );
  expect( padding.algorithmName, equals(parts[2]) );

  var cbc = pbc.underlyingCipher;
  expect( cbc, new isInstanceOf<ChainingBlockCipher>("ChainingBlockCipher") );
  expect( cbc.algorithmName, equals("${parts[0]}/${parts[1]}") );

  var bc = cbc.underlyingCipher;
  expect( bc, new isInstanceOf<BlockCipher>("BlockCipher") );
  expect( bc.algorithmName, equals(parts[0]) );
}

void _testECDomainParameters(String domainName) {
	var domain = new ECDomainParameters(domainName);
	expect( domain, new isInstanceOf<ECDomainParameters>("ECDomainParameters") );
	expect( domain.domainName, domainName );
}

void _testSigner(String algorithmName) {
	var signer = new Signer(algorithmName);
	expect( signer, new isInstanceOf<Signer>("Signer") );
	expect( signer.algorithmName, algorithmName );
}

void _testSecureRandom(String algorithmName) {
	var rnd = new SecureRandom(algorithmName);
	expect( rnd, new isInstanceOf<SecureRandom>("SecureRandom") );
	expect( rnd.algorithmName, algorithmName );
}

void _testEntropySource(String sourceName) {
	var source = new EntropySource(sourceName);
	expect( source, new isInstanceOf<EntropySource>("EntropySource") );
	expect( source.sourceName, sourceName );
}


