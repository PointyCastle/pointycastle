// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.key_derivators.scrypt;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/params/key_derivators/scrypt_parameters.dart";
import "package:cipher/params/key_derivators/pbkdf2_parameters.dart";
import "package:cipher/key_derivators/base_key_derivator.dart";
import "package:cipher/key_derivators/pbkdf2.dart";
import "package:cipher/macs/hmac.dart";
import "package:cipher/digests/sha256.dart";

/**
 * Implementation of SCrypt password based key derivation function. See the next link for info on how to choose N, r, and p:
 *
 *    * [http://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors]
 *
 * This implementation is based on Java implementation by Will Glozer, which can be found at:
 *
 *    * [https://github.com/wg/scrypt]
 */
class Scrypt extends BaseKeyDerivator {

  static final int _MAX_VALUE = 0x7fffffff;

  ScryptParameters _params;

  String get algorithmName => "scrypt";

  int get keySize => _params.desiredKeyLength;

  void reset() {
    _params = null;
  }

  void init( ScryptParameters params ) {
    _params = params;
  }

  int deriveKey( Uint8List inp, int inpOff, Uint8List out, int outOff ) {
    var key = _scryptJ( new Uint8List.fromList(inp.sublist(inpOff)), _params.salt, _params.N, _params.r, _params.p, _params.desiredKeyLength );
    out.setRange( 0, keySize, key );
    return keySize;
  }

  Uint8List _scryptJ(Uint8List passwd, Uint8List salt, int N, int r, int p, int dkLen) {
    if (N < 2 || (N & (N - 1)) != 0) throw new ArgumentError("N must be a power of 2 greater than 1");

    if (N > _MAX_VALUE / 128 / r) throw new ArgumentError("Parameter N is too large");
    if (r > _MAX_VALUE / 128 / p) throw new ArgumentError("Parameter r is too large");

    var DK = new Uint8List(dkLen);

    var B  = new Uint8List(128 * r * p);
    var XY = new Uint8List(256 * r);
    var V  = new Uint8List(128 * r * N);

    var pbkdf2 = new PBKDF2KeyDerivator(new HMac(new SHA256Digest(), 64));

    pbkdf2.init(new Pbkdf2Parameters(salt, 1, p * 128 * r));
    pbkdf2.deriveKey( passwd, 0, B, 0 );

    for( var i=0 ; i<p ; i++ ) {
      _smix(B, i * 128 * r, r, N, V, XY);
    }

    pbkdf2.init(new Pbkdf2Parameters(B, 1, dkLen));
    pbkdf2.deriveKey( passwd, 0, DK, 0 );

    return DK;
  }

  void _smix(Uint8List B, int Bi, int r, int N, Uint8List V, Uint8List XY) {
    var Xi = 0;
    var Yi = 128 * r;

    _arraycopy(B, Bi, XY, Xi, 128 * r);

    for( var i=0 ; i<N ; i++ ) {
      _arraycopy(XY, Xi, V, i * (128 * r), 128 * r);
      _blockmix_salsa8(XY, Xi, Yi, r);
    }

    for( var i=0 ; i<N ; i++ ) {
      var j = _integerify(XY, Xi, r) & (N - 1);
      _blockxor(V, j * (128 * r), XY, Xi, 128 * r);
      _blockmix_salsa8(XY, Xi, Yi, r);
    }

    _arraycopy(XY, Xi, B, Bi, 128 * r);
  }

  void _blockmix_salsa8(Uint8List BY, int Bi, int Yi, int r) {
    var X = new Uint8List(64);

    _arraycopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

    for( var i=0 ; i<2*r ; i++ ) {
      _blockxor(BY, i * 64, X, 0, 64);
      _salsa20_8(X);
      _arraycopy(X, 0, BY, Yi + (i * 64), 64);
    }

    for( var i=0 ; i<r ; i++ ) {
      _arraycopy(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64);
    }

    for( var i=0 ; i<r ; i++ ) {
      _arraycopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
    }
  }

  int _R(int a, int b) => (a << b) | (new Uint32(a) >> (32 - b)).toInt();

  void _salsa20_8(Uint8List B) {
    var B32 = new Uint32List(16);
    var x = new Uint32List(16);

    for( var i=0 ; i<16 ; i++ ) {
      B32[i]  = (B[i * 4 + 0] & 0xff) << 0;
      B32[i] |= (B[i * 4 + 1] & 0xff) << 8;
      B32[i] |= (B[i * 4 + 2] & 0xff) << 16;
      B32[i] |= (B[i * 4 + 3] & 0xff) << 24;
    }

    _arraycopy(B32, 0, x, 0, 16);

    for( var i=8 ; i>0 ; i-=2 ) {
      x[ 4] ^= _R(x[ 0]+x[12], 7);  x[ 8] ^= _R(x[ 4]+x[ 0], 9);
      x[12] ^= _R(x[ 8]+x[ 4],13);  x[ 0] ^= _R(x[12]+x[ 8],18);
      x[ 9] ^= _R(x[ 5]+x[ 1], 7);  x[13] ^= _R(x[ 9]+x[ 5], 9);
      x[ 1] ^= _R(x[13]+x[ 9],13);  x[ 5] ^= _R(x[ 1]+x[13],18);
      x[14] ^= _R(x[10]+x[ 6], 7);  x[ 2] ^= _R(x[14]+x[10], 9);
      x[ 6] ^= _R(x[ 2]+x[14],13);  x[10] ^= _R(x[ 6]+x[ 2],18);
      x[ 3] ^= _R(x[15]+x[11], 7);  x[ 7] ^= _R(x[ 3]+x[15], 9);
      x[11] ^= _R(x[ 7]+x[ 3],13);  x[15] ^= _R(x[11]+x[ 7],18);
      x[ 1] ^= _R(x[ 0]+x[ 3], 7);  x[ 2] ^= _R(x[ 1]+x[ 0], 9);
      x[ 3] ^= _R(x[ 2]+x[ 1],13);  x[ 0] ^= _R(x[ 3]+x[ 2],18);
      x[ 6] ^= _R(x[ 5]+x[ 4], 7);  x[ 7] ^= _R(x[ 6]+x[ 5], 9);
      x[ 4] ^= _R(x[ 7]+x[ 6],13);  x[ 5] ^= _R(x[ 4]+x[ 7],18);
      x[11] ^= _R(x[10]+x[ 9], 7);  x[ 8] ^= _R(x[11]+x[10], 9);
      x[ 9] ^= _R(x[ 8]+x[11],13);  x[10] ^= _R(x[ 9]+x[ 8],18);
      x[12] ^= _R(x[15]+x[14], 7);  x[13] ^= _R(x[12]+x[15], 9);
      x[14] ^= _R(x[13]+x[12],13);  x[15] ^= _R(x[14]+x[13],18);
    }

    for( var i=0 ; i<16 ; ++i ) {
      B32[i] = x[i] + B32[i];
    }

    for( var i=0 ; i<16 ; i++ ) {
      B[i * 4 + 0] = (new Uint32(B32[i]) >> 0 ).toInt() & 0xff;
      B[i * 4 + 1] = (new Uint32(B32[i]) >> 8 ).toInt() & 0xff;
      B[i * 4 + 2] = (new Uint32(B32[i]) >> 16).toInt() & 0xff;
      B[i * 4 + 3] = (new Uint32(B32[i]) >> 24).toInt() & 0xff;
    }
  }

  void _blockxor(Uint8List S, int Si, Uint8List D, int Di, int len) {
    for( var i=0 ; i<len ; i++ ) {
      D[Di + i] ^= S[Si + i];
    }
  }

  int _integerify(Uint8List B, int Bi, int r) {
    var n;

    Bi += (2 * r - 1) * 64;

    n  = (B[Bi + 0] & 0xff) << 0;
    n |= (B[Bi + 1] & 0xff) << 8;
    n |= (B[Bi + 2] & 0xff) << 16;
    n |= (B[Bi + 3] & 0xff) << 24;

    return n;
  }

  void _arraycopy(List<int> inp, int inpOff, List<int> out, int outOff, int len)
    => out.setRange(outOff, outOff+len, inp.sublist(inpOff) );

}
