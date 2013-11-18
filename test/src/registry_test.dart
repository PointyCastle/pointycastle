// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.test.registry_test;

import "package:cipher/cipher.dart";

import "package:unittest/unittest.dart";
import "package:unittest/matcher.dart";

void main() {
  
  initCipher();
  
  test( "initCipher() can be called several times", () {

    initCipher();
    initCipher();

  });

  test( "BlockCipher returns valid implementations", () {
  
    _testBlockCipher( "Null" );
    _testBlockCipher( "AES" );

  });

  test( "ChainingBlockCipher returns valid implementations", () {

    _testChainingBlockCipher( "Null/SIC" );
    _testChainingBlockCipher( "Null/CTR" );
    _testChainingBlockCipher( "Null/CBC" );
    
  });

  test( "StreamCipher returns valid implementations", () {
    
    _testStreamCipher( "Null" );
    _testStreamCipher( "Salsa20" );
    _testStreamCipher( "Null/SIC" );
    _testStreamCipher( "Null/CTR" );

  });

  test( "Digest returns valid implementations", () {
    
    _testDigest( "RIPEMD-160" );

  });

  test( "Padding returns valid implementations", () {
    
    _testPadding( "PKCS7" );

  });

  test( "PaddedBlockCipher returns valid implementations", () {
  
    _testPaddedBlockCipher( "Null/SIC/PKCS7" );

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