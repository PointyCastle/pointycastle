// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.whirlpool;

import "dart:typed_data";

import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/base_digest.dart";

/// Implementation of Whirlpool digest.
class WhirlpoolDigest extends BaseDigest {

  static const _DIGEST_LENGTH_BYTES = 512 ~/ 8;
  static const _BITCOUNT_ARRAY_SIZE = 32;
  static const _ROUNDS = 10;

  static _Constants _CT;

  final _buffer = new Uint8List(64);
  var _bufferPos = 0;

  final _bitCount = new List<Uint16>(_BITCOUNT_ARRAY_SIZE);

  final _hash  = new List<Uint64>(8);
  final _K = new List<Uint64>(8); // the round key
  final _L = new List<Uint64>(8);
  final _block = new List<Uint64>(8); // mu (buffer)
  final _state = new List<Uint64>(8); // the current "cipher" state

  WhirlpoolDigest() {
    if (_CT == null) {
      _CT = new _Constants();
    }
    reset();
  }

  String get algorithmName => "Whirlpool";

  int get digestSize => _DIGEST_LENGTH_BYTES;

  void reset() {
    _bufferPos = 0;
    _buffer.fillRange(0, _buffer.length, 0);

    _bitCount.fillRange(0, _bitCount.length, new Uint16(0));

    _hash.fillRange(0, _hash.length, new Uint64(0));
    _K.fillRange(0, _K.length, new Uint64(0));
    _L.fillRange(0, _L.length, new Uint64(0));
    _block.fillRange(0, _block.length, new Uint64(0));
    _state.fillRange(0, _state.length, new Uint64(0));
  }

  void updateByte(int inp) {
    _buffer[_bufferPos++] = inp;

    if (_bufferPos == _buffer.length) {
        _processFilledBuffer(_buffer, 0);
    }

    _increment();
  }

  void update(Uint8List inp, int inpOff, int len) {
    while (len > 0) {
      updateByte(inp[inpOff]);
      ++inpOff;
      --len;
    }
  }

  int doFinal(Uint8List out, int outOff) {
    // sets out[outOff] .. out[outOff+DIGEST_LENGTH_BYTES]
    _finish();

    for (var i = 0; i < 8; i++) {
      _convertLongToByteArray(_hash[i], out, outOff + (i * 8));
    }

    reset();

    return digestSize;
  }


  // this takes a buffer of information and fills the block
  void _processFilledBuffer(Uint8List inp, int inpOff) {
    // copies into the block...
    for (var i = 0; i < _state.length; i++) {
      _block[i] = _bytesToLongFromBuffer(_buffer, i * 8);
    }
    _processBlock();
    _bufferPos = 0;
    _buffer.fillRange(0, _buffer.length, 0);
  }

  Uint64 _bytesToLongFromBuffer(Uint8List buffer, int startPos) {
    return new Uint64.fromBigEndian(buffer, startPos);
/*
    long rv = (((buffer[startPos + 0] & 0xffL) << 56) |
                 ((buffer[startPos + 1] & 0xffL) << 48) |
                 ((buffer[startPos + 2] & 0xffL) << 40) |
                 ((buffer[startPos + 3] & 0xffL) << 32) |
                 ((buffer[startPos + 4] & 0xffL) << 24) |
                 ((buffer[startPos + 5] & 0xffL) << 16) |
                 ((buffer[startPos + 6] & 0xffL) <<  8) |
                 ((buffer[startPos + 7]) & 0xffL));

      return rv;*/
  }

  void _convertLongToByteArray(Uint64 inputLong, Uint8List outputArray, int offSet) {
    inputLong.toBigEndian(outputArray, offSet);
    /*
      for (int i = 0; i < 8; i++)
      {
          outputArray[offSet + i] = (byte)((inputLong >> (56 - (i * 8))) & 0xff);
      }*/
  }

  void _processBlock() {
    // buffer contents have been transferred to the _block[] array via
    // processFilledBuffer

    // compute and apply K^0
    for (var i = 0; i < 8; i++) {
      _state[i] = _block[i] ^ (_K[i] = _hash[i]);
    }

    // iterate over the rounds
    for (var round = 1; round <= _ROUNDS; round++) {
      for (var i = 0; i < 8; i++) {
        _L[i] = new Uint64(0);
        _L[i] ^= _CT.C0[Uint8.clip(_K[(i - 0) & 7] >> 56)];
        _L[i] ^= _CT.C1[Uint8.clip(_K[(i - 1) & 7] >> 48)];
        _L[i] ^= _CT.C2[Uint8.clip(_K[(i - 2) & 7] >> 40)];
        _L[i] ^= _CT.C3[Uint8.clip(_K[(i - 3) & 7] >> 32)];
        _L[i] ^= _CT.C4[Uint8.clip(_K[(i - 4) & 7] >> 24)];
        _L[i] ^= _CT.C5[Uint8.clip(_K[(i - 5) & 7] >> 16)];
        _L[i] ^= _CT.C6[Uint8.clip(_K[(i - 6) & 7] >>  8)];
        _L[i] ^= _CT.C7[Uint8.clip(_K[(i - 7) & 7])];
      }

      _K.setRange(0, _K.length, _L );

      _K[0] ^= _CT.rc[round];

      // apply the round transformation
      for (var i = 0; i < 8; i++) {
          _L[i] = _K[i];

          _L[i] ^= _CT.C0[Uint8.clip(_state[(i - 0) & 7] >> 56)];
          _L[i] ^= _CT.C1[Uint8.clip(_state[(i - 1) & 7] >> 48)];
          _L[i] ^= _CT.C2[Uint8.clip(_state[(i - 2) & 7] >> 40)];
          _L[i] ^= _CT.C3[Uint8.clip(_state[(i - 3) & 7] >> 32)];
          _L[i] ^= _CT.C4[Uint8.clip(_state[(i - 4) & 7] >> 24)];
          _L[i] ^= _CT.C5[Uint8.clip(_state[(i - 5) & 7] >> 16)];
          _L[i] ^= _CT.C6[Uint8.clip(_state[(i - 6) & 7] >> 8)];
          _L[i] ^= _CT.C7[Uint8.clip(_state[(i - 7) & 7])];
      }

      // save the current state
      _state.setRange(0, _state.length, _L);
    }

    // apply Miuaguchi-Preneel compression
    for (var i = 0; i < 8; i++) {
      _hash[i] ^= _state[i] ^ _block[i];
    }

  }

  /*
   * increment() can be implemented in this way using 2 arrays or
   * by having some temporary variables that are used to set the
   * value provided by EIGHT[i] and carry within the loop.
   *
   * not having done any timing, this seems likely to be faster
   * at the slight expense of 32*(sizeof short) bytes
   */
  /*static*/
  /*
  static {
      EIGHT[BITCOUNT_ARRAY_SIZE - 1] = 8;
  }
  */

  void _increment() {
    var carry = 0;
    for (var i = _bitCount.length - 1; i >= 0; i--) {
      var sum = (_bitCount[i] & 0xff) + _CT.EIGHT[i] + carry;

      carry = sum >> 8;
      _bitCount[i] = new Uint16(sum & 0xff);
    }
  }

  void _finish() {
    /*
     * this makes a copy of the current bit length. at the expense of an
     * object creation of 32 bytes rather than providing a _stopCounting
     * boolean which was the alternative I could think of.
     */
    var bitLength = _copyBitLength();

    _buffer[_bufferPos++] |= 0x80;

    if (_bufferPos == _buffer.length) {
      _processFilledBuffer(_buffer, 0);
    }

    /*
     * Final block contains
     * [ ... data .... ][0][0][0][ length ]
     *
     * if [ length ] cannot fit.  Need to create a new block.
     */
    if (_bufferPos > 32) {
      while (_bufferPos != 0) {
        updateByte(0);
      }
    }

    while (_bufferPos <= 32) {
      updateByte(0);
    }

    // copy the length information to the final 32 bytes of the
    // 64 byte block....
    _buffer.setRange(32, 32+bitLength.length, bitLength);

    _processFilledBuffer(_buffer, 0);
  }

  Uint8List _copyBitLength() {
    var rv = new Uint8List(_BITCOUNT_ARRAY_SIZE);
    for (var i = 0; i < rv.length; i++) {
        rv[i] = (_bitCount[i] & 0xff).toInt();
    }
    return rv;
  }

}

class _Constants {

  static const _REDUCTION_POLYNOMIAL = 0x011d; // 2^8 + 2^4 + 2^3 + 2 + 1;

  final C0 = new List<Uint64>(256);
  final C1 = new List<Uint64>(256);
  final C2 = new List<Uint64>(256);
  final C3 = new List<Uint64>(256);
  final C4 = new List<Uint64>(256);
  final C5 = new List<Uint64>(256);
  final C6 = new List<Uint64>(256);
  final C7 = new List<Uint64>(256);

  final rc = new List<Uint64>(WhirlpoolDigest._ROUNDS + 1);

  final EIGHT = new List<Uint16>.filled(WhirlpoolDigest._BITCOUNT_ARRAY_SIZE, new Uint16(0));

  _Constants() {
    for (var i = 0; i < 256; i++) {
      var v1 = _SBOX[i];
      var v2 = _maskWithReductionPolynomial(v1 << 1);
      var v4 = _maskWithReductionPolynomial(v2 << 1);
      var v5 = v4 ^ v1;
      var v8 = _maskWithReductionPolynomial(v4 << 1);
      var v9 = v8 ^ v1;

      C0[i] = _packIntoLong(v1, v1, v4, v1, v8, v5, v2, v9);
      C1[i] = _packIntoLong(v9, v1, v1, v4, v1, v8, v5, v2);
      C2[i] = _packIntoLong(v2, v9, v1, v1, v4, v1, v8, v5);
      C3[i] = _packIntoLong(v5, v2, v9, v1, v1, v4, v1, v8);
      C4[i] = _packIntoLong(v8, v5, v2, v9, v1, v1, v4, v1);
      C5[i] = _packIntoLong(v1, v8, v5, v2, v9, v1, v1, v4);
      C6[i] = _packIntoLong(v4, v1, v8, v5, v2, v9, v1, v1);
      C7[i] = _packIntoLong(v1, v4, v1, v8, v5, v2, v9, v1);
    }

    rc[0] = new Uint64(0);
    for (var r = 1; r <= WhirlpoolDigest._ROUNDS; r++) {
      var i = 8 * (r - 1);
      rc[r] = new Uint64(
        (C0[i    ] & 0xff00000000000000) ^
        (C1[i + 1] & 0x00ff000000000000) ^
        (C2[i + 2] & 0x0000ff0000000000) ^
        (C3[i + 3] & 0x000000ff00000000) ^
        (C4[i + 4] & 0x00000000ff000000) ^
        (C5[i + 5] & 0x0000000000ff0000) ^
        (C6[i + 6] & 0x000000000000ff00) ^
        (C7[i + 7] & 0x00000000000000ff)
      );
    }

    EIGHT[WhirlpoolDigest._BITCOUNT_ARRAY_SIZE-1] = new Uint16(8);
  }

  Uint64 _packIntoLong(int b7, int b6, int b5, int b4, int b3, int b2, int b1, int b0)
    => (new Uint64(b7) << 56) ^ (new Uint64(b6) << 48) ^ (new Uint64(b5) << 40) ^ (new Uint64(b4) << 32) ^
        (new Uint64(b3) << 24) ^ (new Uint64(b2) << 16) ^ (new Uint64(b1) <<  8) ^ b0;

  /*
   * int's are used to prevent sign extension.  The values that are really being used are
   * actually just 0..255
   */
  int _maskWithReductionPolynomial(int input) {
    var rv = input;
    if (rv >= 0x100) { // high bit set
        rv ^= _REDUCTION_POLYNOMIAL; // reduced by the polynomial
    }
    return rv;
  }

  final _SBOX = [
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
    0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
    0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
    0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
    0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
    0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
    0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
    0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
    0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
    0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
    0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
  ];

}
