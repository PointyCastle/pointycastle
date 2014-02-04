// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.sha3;

import "dart:typed_data";

import "package:cipher/api.dart";
String formatBytesAsHexString(Uint8List bytes) {
  var result = new StringBuffer();
  for (var i = 0; i < bytes.lengthInBytes; i++) {
    var part = bytes[i];
    result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
  }
  return result.toString();
}


/// Implementation of SHA-3 digest.
class SHA3Digest implements Digest {

  static List<Uint64> _keccakRoundConstants = _keccakInitializeRoundConstants();
  static List<Uint32> _keccakRhoOffsets = _keccakInitializeRhoOffsets();

  int _rate;
  int _fixedOutputLength;

  final _state = new Uint8List(1600 ~/ 8);
  final _dataQueue = new Uint8List(1536 ~/ 8);

  int _bitsInQueue;
  bool _squeezing;
  int _bitsAvailableForSqueezing;

  SHA3Digest([int bitLength = 0]) {
    _init(bitLength);
  }

  String get algorithmName => "SHA-3/${_fixedOutputLength}";

  int get digestSize => (_fixedOutputLength ~/ 8);

  void reset() {
    _init(_fixedOutputLength);
  }

  void updateByte(int inp) {
    _doUpdate(new Uint8List.fromList([inp]), 0, 8);
  }

  void update(Uint8List inp, int inpOff, int len) {
    _doUpdate(inp, inpOff, len * 8);
  }

  int doFinal(Uint8List out, int outOff) {
    _squeeze(out, outOff, _fixedOutputLength);

    reset();

    return digestSize;
  }

  void _init(int bitLength) {
    switch (bitLength) {
      case 0:
      case 288:
        _initSponge(1024, 576);
        break;
      case 224:
        _initSponge(1152, 448);
        break;
      case 256:
        _initSponge(1088, 512);
        break;
      case 384:
        _initSponge(832, 768);
        break;
      case 512:
        _initSponge(576, 1024);
        break;
      default: throw new ArgumentError("bitLength (${bitLength}) must be one of 224, 256, 384, or 512");
    }
  }

  void _clearDataQueueSection(int off, int len) {
    _dataQueue.fillRange(off, off + len, 0);
  }

  void _doUpdate(Uint8List data, int off, int databitlen) {
    if ((databitlen % 8) == 0) {
      _absorb(data, off, databitlen);
    } else {
      _absorb(data, off, databitlen - (databitlen % 8));

      var lastByte = new Uint8List(1);

      lastByte[0] = (new Uint8(data[off + (databitlen ~/ 8)]) >> (8 - (databitlen % 8))).toInt();
      _absorb(lastByte, off, databitlen % 8);
    }
  }

  void _initSponge(int rate, int capacity) {
    if ((rate + capacity) != 1600) {
      throw new StateError("Value of (rate + capacity) is not 1600: ${rate + capacity}");
    }
    if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0)) {
      throw new StateError("Invalid rate value: ${rate}");
    }

    _rate = rate;
    _fixedOutputLength = capacity ~/ 2;
    _state.fillRange(0, _state.length, 0);
    _dataQueue.fillRange(0, _dataQueue.length, 0);

    _bitsInQueue = 0;
    _squeezing = false;
    _bitsAvailableForSqueezing = 0;
  }

  void _absorbQueue() {
    _keccakAbsorb(_state, _dataQueue, _rate ~/ 8);

    _bitsInQueue = 0;
  }

  void _absorb(Uint8List data, int off, int databitlen) {
    var i, j, wholeBlocks;

    if ((_bitsInQueue % 8) != 0) {
      throw new StateError("Attempt to absorb with odd length queue");
    }
    if (_squeezing) {
      throw new StateError("Attempt to absorb while squeezing");
    }

    i = 0;
    while (i < databitlen) {
      if ((_bitsInQueue == 0) && (databitlen >= _rate) && (i <= (databitlen - _rate))) {
        wholeBlocks = (databitlen - i) / _rate;

        for (j = 0; j < wholeBlocks; j++) {
          var chunk = new Uint8List(_rate ~/ 8);

          var offset = (off + (i / 8) + (j * chunk.length));
          chunk.setRange(0, chunk.length, data.sublist(offset));

          _keccakAbsorb(_state, chunk, chunk.length);
        }

        i += wholeBlocks * _rate;
      } else {
        var partialBlock = (databitlen - i);

        if ((partialBlock + _bitsInQueue) > _rate) {
          partialBlock = (_rate - _bitsInQueue);
        }

        var partialByte = (partialBlock % 8);
        partialBlock -= partialByte;

        var start = (_bitsInQueue ~/ 8);
        var end = start + (partialBlock ~/ 8);
        var offset = (off + (i ~/ 8));
        _dataQueue.setRange(start, end, data.sublist(offset));

        _bitsInQueue += partialBlock;
        i += partialBlock;
        if (_bitsInQueue == _rate) {
          _absorbQueue();
        }
        if (partialByte > 0) {
          int mask = (1 << partialByte) - 1;
          _dataQueue[_bitsInQueue ~/ 8] = (data[off + (i ~/ 8)] & mask);
          _bitsInQueue += partialByte;
          i += partialByte;
        }
      }
    }
  }

  void _padAndSwitchToSqueezingPhase() {
    if (_bitsInQueue + 1 == _rate) {
      _dataQueue[_bitsInQueue / 8] |= 1 << (_bitsInQueue % 8);
      _absorbQueue();
      _clearDataQueueSection(0, _rate ~/ 8);
    } else {
      _clearDataQueueSection(((_bitsInQueue + 7) ~/ 8), (_rate ~/ 8 - (_bitsInQueue + 7) ~/ 8));
      _dataQueue[_bitsInQueue ~/ 8] |= 1 << (_bitsInQueue % 8);
    }
    _dataQueue[(_rate - 1) ~/ 8] |= 1 << ((_rate - 1) % 8);
    _absorbQueue();

    if (_rate == 1024) {
      _keccakExtract1024bits(_state, _dataQueue);
      _bitsAvailableForSqueezing = 1024;
    } else {
      _keccakExtract(_state, _dataQueue, _rate ~/ 64);
      _bitsAvailableForSqueezing = _rate;
    }

    _squeezing = true;
  }

  void _squeeze(Uint8List output, int offset, int outputLength) {
    var i, partialBlock;

    if (!_squeezing) {
      _padAndSwitchToSqueezingPhase();
    }
    if ((outputLength % 8) != 0) {
      throw new StateError("Output length not a multiple of 8: ${outputLength}");
    }

    i = 0;
    while (i < outputLength) {
      if (_bitsAvailableForSqueezing == 0) {
        _keccakPermutation(_state);

        if (_rate == 1024) {
          _keccakExtract1024bits(_state, _dataQueue);
          _bitsAvailableForSqueezing = 1024;
        } else {
          _keccakExtract(_state, _dataQueue, _rate ~/ 64);
          _bitsAvailableForSqueezing = _rate;
        }
      }
      partialBlock = _bitsAvailableForSqueezing;
      if (partialBlock > (outputLength - i)) {
        partialBlock = (outputLength - i);
      }

      var start = (offset + (i ~/ 8));
      var end = start + (partialBlock ~/ 8);
      var offset2 = (_rate - _bitsAvailableForSqueezing) ~/ 8;
      output.setRange(start, end, _dataQueue.sublist(offset2));
      _bitsAvailableForSqueezing -= partialBlock;
      i += partialBlock;
    }
  }

  void _fromBytesToWords(List<Uint64> stateAsWords, Uint8List state) {
    for (int i = 0; i < (1600 ~/ 64); i++) {
      stateAsWords[i] = new Uint64(0);
      int index = i * (64 ~/ 8);
      for (int j = 0; j < (64 ~/ 8); j++) {
        stateAsWords[i] |= (new Uint64(state[index + j]) << (8 * j));
      }
    }
  }

  void _fromWordsToBytes(Uint8List state, List<Uint64> stateAsWords) {
    for (int i = 0; i < (1600 ~/ 64); i++) {
      int index = i * (64 ~/ 8);
      for (int j = 0; j < (64 ~/ 8); j++) {
        state[index + j] = (stateAsWords[i] >> (8 * j)).toInt();
      }
    }
  }

  void _keccakPermutation(Uint8List state) {
    var longState = new List<Uint64>(state.length ~/ 8);

    _fromBytesToWords(longState, state);
    _keccakPermutationOnWords(longState);
    _fromWordsToBytes(state, longState);
  }

  void _keccakPermutationAfterXor(Uint8List state, Uint8List data, int dataLengthInBytes) {
    for (var i = 0; i < dataLengthInBytes; i++) {
      state[i] ^= data[i];
    }
    _keccakPermutation(state);
  }

  void _keccakPermutationOnWords(List<Uint64> state) {
    int i;

    for (i = 0; i < 24; i++) {
      theta(state);
      rho(state);
      pi(state);
      chi(state);
      _iota(state, i);
    }
  }

  var C = new List<Uint64>(5);

  void theta(List<Uint64> A) {
    for (var x = 0; x < 5; x++) {
      C[x] = new Uint64(0);
      for (var y = 0; y < 5; y++) {
        C[x] ^= A[x + 5 * y];
      }
    }
    for (var x = 0; x < 5; x++) {
      var dX = ((((C[(x + 1) % 5]) << 1) ^ ((C[(x + 1) % 5]) >> (64 - 1)))) ^ C[(x + 4) % 5];
      for (int y = 0; y < 5; y++) {
        A[x + 5 * y] ^= dX;
      }
    }
  }

  void rho(List<Uint64> A) {
    for (var x = 0; x < 5; x++) {
      for (var y = 0; y < 5; y++) {
        var index = x + 5 * y;
        if (_keccakRhoOffsets[index] != 0) {
          A[index] = (A[index] << _keccakRhoOffsets[index]) ^ ((A[index]) >> (64 - _keccakRhoOffsets[index].toInt()));
        }
      }
    }
  }

  var tempA = new List<Uint64>(25);

  void pi(List<Uint64> A) {
    tempA.setRange(0, tempA.length, A);

    for (var x = 0; x < 5; x++) {
      for (var y = 0; y < 5; y++) {
        A[y + 5 * ((2 * x + 3 * y) % 5)] = tempA[x + 5 * y];
      }
    }
  }

  var chiC = new List<Uint64>(5);

  void chi(List<Uint64> A) {
    for (var y = 0; y < 5; y++) {
      for (var x = 0; x < 5; x++) {
        chiC[x] = A[x + 5 * y] ^ ((~A[(((x + 1) % 5) + 5 * y)]) & A[(((x + 2) % 5) + 5 * y)]);
      }
      for (var x = 0; x < 5; x++) {
        A[x + 5 * y] = chiC[x];
      }
    }
  }

  void _iota(List<Uint64> A, int indexRound) {
    A[(((0) % 5) + 5 * ((0) % 5))] ^= _keccakRoundConstants[indexRound];
  }

  void _keccakAbsorb(Uint8List byteState, Uint8List data, int dataInBytes) {
    _keccakPermutationAfterXor(byteState, data, dataInBytes);
  }


  void _keccakExtract1024bits(Uint8List byteState, Uint8List data) {
    data.setRange(0, 128, byteState);
  }


  void _keccakExtract(Uint8List byteState, Uint8List data, int laneCount) {
    data.setRange(0, laneCount * 8, byteState);
  }

  static List<Uint64> _keccakInitializeRoundConstants() {
    var keccakRoundConstants = new List<Uint64>(24);
    var LFSRstate = new Uint8List(1);

    LFSRstate[0] = 0x01;
    var i, j, bitPosition;

    for (i = 0; i < 24; i++) {
      keccakRoundConstants[i] = new Uint64(0);
      for (j = 0; j < 7; j++) {
        bitPosition = (1 << j) - 1;
        if (_LFSR86540(LFSRstate)) {
          keccakRoundConstants[i] ^= 1 << bitPosition;
        }
      }
    }

    return keccakRoundConstants;
  }

  static bool _LFSR86540(Uint8List LFSR) {
    bool result = (((LFSR[0]) & 0x01) != 0);
    if (((LFSR[0]) & 0x80) != 0) {
      LFSR[0] = ((LFSR[0] << 1) ^ 0x71);
    } else {
      LFSR[0] <<= 1;
    }

    return result;
  }

  static List<Uint32> _keccakInitializeRhoOffsets() {
    var keccakRhoOffsets = new List<Uint32>(25);
    int x, y, t, newX, newY;

    keccakRhoOffsets[(((0) % 5) + 5 * ((0) % 5))] = new Uint32(0);
    x = 1;
    y = 0;
    for (t = 0; t < 24; t++) {
      keccakRhoOffsets[(((x) % 5) + 5 * ((y) % 5))] = new Uint32(((t + 1) * (t + 2) ~/ 2) % 64);
      newX = (0 * x + 1 * y) % 5;
      newY = (2 * x + 3 * y) % 5;
      x = newX;
      y = newY;
    }

    return keccakRhoOffsets;
  }

}




