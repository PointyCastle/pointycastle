// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.key_factories.scrypt;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/params/scrypt_parameters.dart";
import "package:cipher/params/pbkdf2_parameters.dart";

/**
 * Implementation of SCrypt password based key derivation function. See the next link for info on how to choose N, r, and p:
 *
 *    * [http://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors]
 *
 * This implementation is based on Java implementation by Will Glozer, which can be found at:
 *
 *    * [https://github.com/wg/scrypt]
 */
class Scrypt implements KeyFactory {

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

    var pbkdf2 = new KeyFactory("SHA-256/HMAC/PBKDF2");

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

  /*
  Uint8List _MFcrypt(Uint8List P, Uint8List S, int N, int r, int p, int dkLen) {
    int MFLenBytes = r * 128;
    Uint8List bytes = _SingleIterationPBKDF2(P, S, p * MFLenBytes);

    int BLen = (new Uint8(bytes.length) >> 2).toInt();
    var B = new List<Uint32>(BLen);

    for( var i=0 ; i<B.length ; i++ ) {
      B[i] = new Uint32.fromLittleEndian(bytes, i*4);
    }

    int MFLenWords = (new Uint8(MFLenBytes) >> 2).toInt();
    for( int BOff=0 ; BOff<BLen ; BOff+=MFLenWords ) {
      _SMix(B, BOff, N, r);
    }

    for( var i=0 ; i<B.length ; i++ ) {
      B[i].toLittleEndian(bytes, i*4);
    }

    return _SingleIterationPBKDF2(P, bytes, dkLen);
  }

  Uint8List _SingleIterationPBKDF2(Uint8List P, Uint8List S, int dkLen) {
//    var sha256 = new Digest("SHA-256");
    //PBEParametersGenerator pGen = new PKCS5S2ParametersGenerator(sha256);
    var pgen = new KeyFactory("SHA-256/HMAC/PBKDF2");
    var params = new Pbkdf2Parameters(S, 1, dkLen);
    pgen.init(params);
    //pGen.init(P, S, 1);
    //KeyParameter key = (KeyParameter) pGen.generateDerivedMacParameters(dkLen * 8);
    var out = new Uint8List(dkLen);
    pgen.deriveKey( P, 0, out, 0);
    return out;
  }

  void _SMix( List<Uint32> B, int BOff, int N, int r ) {
    int BCount = r * 32;

    var blockX1 = new List<Uint32>(16);
    var blockX2 = new List<Uint32>(16);
    var blockY = new List<Uint32>(BCount);

    var X = new List<Uint32>(BCount);
    var V = new List<List<Uint32>>(N); // int[][] V = new int[N][];

    X.setRange( 0, BCount, B.sublist(BOff) ); // System.arraycopy(B, BOff, X, 0, BCount);

    for( var i=0 ; i<N ; ++i ) {
      V[i] = new List<Uint32>.from(X); //Arrays.clone(X);
      _BlockMix(X, blockX1, blockX2, blockY, r);
    }

    var mask = N - 1;
    for( var i=0 ; i<N ; ++i ) {
      int j = X[BCount - 16] & mask;
      _Xor(X, V[j], 0, X);
      _BlockMix(X, blockX1, blockX2, blockY, r);
    }

    B.setRange(BOff, BOff+BCount, X ); // System.arraycopy(X, 0, B, BOff, BCount);
  }

  void _BlockMix(List<Uint32> B, List<Uint32> X1, List<Uint32> X2, List<Uint32> Y, int r) {
    X1.setRange( 0, 16, B.sublist(B.length-16) ); // System.arraycopy(B, B.length - 16, X1, 0, 16);

    int BOff = 0;
    int YOff = 0;
    int halfLen = (new Uint8(B.length) >> 1).toInt();

    for( int i=2*r ; i>0 ; --i ) {
      _Xor(X1, B, BOff, X2);

      _salsa20Core(8, X2, X1);
      Y.setRange( YOff, YOff+16, X1 );// System.arraycopy(X1, 0, Y, YOff, 16);

      YOff = halfLen + BOff - YOff;
      BOff += 16;
    }

    B.setRange( 0, Y.length, Y ); // System.arraycopy(Y, 0, B, 0, Y.length);
  }

  void _Xor(List<Uint32> a, List<Uint32> b, int bOff, List<Uint32> output) {
    for (int i = output.length - 1; i >= 0; --i) {
      output[i] = a[i] ^ b[bOff + i];
    }
  }

  void _salsa20Core( int rounds, List<Uint32> input, List<Uint32> x ) {
    const _STATE_SIZE = 16;

    x.setAll( 0, input );

    for( var i=rounds ; i>0 ; i-=2 ) {
      x[ 4] ^= _rotl((x[ 0]+x[12]), 7);
      x[ 8] ^= _rotl((x[ 4]+x[ 0]), 9);
      x[12] ^= _rotl((x[ 8]+x[ 4]),13);
      x[ 0] ^= _rotl((x[12]+x[ 8]),18);
      x[ 9] ^= _rotl((x[ 5]+x[ 1]), 7);
      x[13] ^= _rotl((x[ 9]+x[ 5]), 9);
      x[ 1] ^= _rotl((x[13]+x[ 9]),13);
      x[ 5] ^= _rotl((x[ 1]+x[13]),18);
      x[14] ^= _rotl((x[10]+x[ 6]), 7);
      x[ 2] ^= _rotl((x[14]+x[10]), 9);
      x[ 6] ^= _rotl((x[ 2]+x[14]),13);
      x[10] ^= _rotl((x[ 6]+x[ 2]),18);
      x[ 3] ^= _rotl((x[15]+x[11]), 7);
      x[ 7] ^= _rotl((x[ 3]+x[15]), 9);
      x[11] ^= _rotl((x[ 7]+x[ 3]),13);
      x[15] ^= _rotl((x[11]+x[ 7]),18);
      x[ 1] ^= _rotl((x[ 0]+x[ 3]), 7);
      x[ 2] ^= _rotl((x[ 1]+x[ 0]), 9);
      x[ 3] ^= _rotl((x[ 2]+x[ 1]),13);
      x[ 0] ^= _rotl((x[ 3]+x[ 2]),18);
      x[ 6] ^= _rotl((x[ 5]+x[ 4]), 7);
      x[ 7] ^= _rotl((x[ 6]+x[ 5]), 9);
      x[ 4] ^= _rotl((x[ 7]+x[ 6]),13);
      x[ 5] ^= _rotl((x[ 4]+x[ 7]),18);
      x[11] ^= _rotl((x[10]+x[ 9]), 7);
      x[ 8] ^= _rotl((x[11]+x[10]), 9);
      x[ 9] ^= _rotl((x[ 8]+x[11]),13);
      x[10] ^= _rotl((x[ 9]+x[ 8]),18);
      x[12] ^= _rotl((x[15]+x[14]), 7);
      x[13] ^= _rotl((x[12]+x[15]), 9);
      x[14] ^= _rotl((x[13]+x[12]),13);
      x[15] ^= _rotl((x[14]+x[13]),18);
    }

    for( var i=0 ; i<_STATE_SIZE; ++i ) {
      x[i] += input[i];
    }
  }

  /// Salsa20Core Helper funcion
  Uint32 _rotl(Uint32 x, int y)  => (x << y) | (x>>-y).toInt();
  */
}
















