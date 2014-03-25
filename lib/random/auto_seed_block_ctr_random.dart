// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.random.auto_seed_block_ctr_random;

import "dart:typed_data";

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";
import "package:cipher/random/block_ctr_random.dart";
import "package:cipher/params/parameters_with_iv.dart";
import "package:cipher/params/key_parameter.dart";

/**
 * An implementation of [SecureRandom] that uses a [BlockCipher] with CTR mode to generate random
 * values and automatically self reseeds itself after each request for data, in order to achieve
 * forward security. See section 4.1 of the paper:
 * Practical Random Number Generation in Software (by John Viega).
 */
class AutoSeedBlockCtrRandom implements SecureRandom {

  BlockCtrRandom _delegate;
  final bool _reseedIV;

  var _inAutoReseed = false;
  var _autoReseedKeyLength;

  String get algorithmName => "${_delegate.cipher.algorithmName}/CTR/AUTO-SEED-PRNG";

  AutoSeedBlockCtrRandom(BlockCipher cipher, [this._reseedIV=true]) {
    _delegate = new BlockCtrRandom(cipher);
  }

  void seed(ParametersWithIV<KeyParameter> params) {
    _autoReseedKeyLength = params.parameters.key.length;
    _delegate.seed( params );
  }

  int nextUint8() => _autoReseedIfNeededAfter( () {
    return _delegate.nextUint8();
  });

  int nextUint16() => _autoReseedIfNeededAfter( () {
    return _delegate.nextUint16();
  });

  int nextUint32() => _autoReseedIfNeededAfter( () {
    return _delegate.nextUint32();
  });

  BigInteger nextBigInteger( int bitLength ) => _autoReseedIfNeededAfter( () {
    return _delegate.nextBigInteger(bitLength);
  });

  Uint8List nextBytes( int count ) => _autoReseedIfNeededAfter( () {
    return _delegate.nextBytes(count);
  });

  dynamic _autoReseedIfNeededAfter( dynamic closure ) {
    if( _inAutoReseed ) {
      return closure();
    } else {
      _inAutoReseed = true;
      var ret = closure();
      _doAutoReseed();
      _inAutoReseed = false;
      return ret;
    }
  }

  void _doAutoReseed() {
    var newKey = nextBytes(_autoReseedKeyLength);
    var keyParam = new KeyParameter(newKey);

    var params;
    if (_reseedIV) {
      params = new ParametersWithIV(keyParam, nextBytes(_delegate.cipher.blockSize));
    } else {
      params = keyParam;
    }

    _delegate.seed( params );
  }

}
