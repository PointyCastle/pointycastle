// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.
library pointycastle.impl.block_cipher.modes.gcm;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/impl/base_aead_block_cipher.dart";
import 'dart:math' show min;

class GCMBlockCipher extends BaseAEADBlockCipher {

  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG =
  new DynamicFactoryConfig.suffix(BlockCipher, "/GCM",
          (_, final Match match) =>
          () {
        BlockCipher underlying = new BlockCipher(match.group(1));
        return new GCMBlockCipher(underlying);
      });

  Uint8List _h;
  Uint8List _counter;
  Uint8List _e;
  Uint8List _e0;
  Uint8List _x;
  int _processedBytes;


  GCMBlockCipher(BlockCipher cipher) : super(cipher);

  @override
  String get algorithmName => "${underlyingCipher.algorithmName}/GCM";

  @override
  void prepare(KeyParameter keyParam) {
    if (macSize!=16) {
      throw new ArgumentError("macSize should be equal to 16 for GCM");
    }

    underlyingCipher.init(true, keyParam);

    _h = new Uint8List(blockSize);
    underlyingCipher.processBlock(_h, 0, _h, 0);

    _counter = _computeInitialCounter(nonce);

    _e0 = new Uint8List(16);
    _computeE(_counter, _e0);

    _e = new Uint8List(16);

    _x = new Uint8List(16);

    _processedBytes = 0;
  }

  Uint8List _computeInitialCounter(Uint8List iv) {
    Uint8List counter = new Uint8List(16);

    if (iv.length==12) {
      counter.setAll( 0, iv );
      counter[15] = 1;
    } else {
      _gHASH(counter, iv);
      var length = new Uint8List.view((new Uint64List(2)..[0] = iv.length*8).buffer);
      length = new Uint8List.fromList(length.reversed.toList());

      _gHASHBlock(counter, length);

    }
    return counter;

  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {

    var length = blockSize < inp.length-inpOff ? blockSize : inp.length-inpOff;

    var i = new Uint8List(blockSize);
    i.setAll(0, inp.skip(inpOff).take(length));

    _processedBytes += length;

    _getNextCTRBlock(_e);

    var o = new Uint8List.fromList(i);
    _xor(o, _e);
    if (length<blockSize) o.fillRange(length, blockSize, 0);

    out.setRange(outOff, outOff+length, o);

    var c = forEncryption ? o : i;

    _gHASHBlock(_x, c);

    return length;
  }

  void _gHASH(Uint8List x, Uint8List y) {
    var block = new Uint8List(16);
    for (var i=0;i<y.length;i+=16) {
      block.setAll(0, y.sublist(i,min(i+16,y.length)));
      block.fillRange(min(i+16,y.length)-i, 16, 0);
      _gHASHBlock(x, block);
    }
  }

  void _gHASHBlock(Uint8List x, Uint8List y) {
    _xor(x,y);
    _mult(x, _h);
  }

  void _getNextCTRBlock(Uint8List out) {
    _counter[15]++;
    for (var i=15;i>=12&&_counter[i]==256;i--) {
      _counter[i] = 0;
      if (i>12) _counter[i-1]++;
    }

    _computeE(_counter, out);
  }

  void _computeE(Uint8List inp, Uint8List out) {
    underlyingCipher.processBlock( inp, 0, out, 0 );
  }

  final Uint8List r = new Uint8List(16)..[0] = 0xe1;

  void _mult(Uint8List x, Uint8List y) {
    var v = x;
    var z = new Uint8List(x.length);

    for (var i=0;i<128;i++) {
      if (_bit(y,i)) {
        _xor(z,v);
      }
      if (_shiftRight(v)) {
        _xor(v,r);
      }
    }

    x.setAll(0, z);
  }

  void _xor(Uint8List x, Uint8List y) {
    for (var i=0;i<x.length;i++) {
      x[i] ^= y[i];
    }
  }

  bool _bit(Uint8List x, int n) {
    int byte = n~/8;
    int mask = 1<<(7-n%8);
    return x[byte]&mask==mask;
  }

  bool _shiftRight(Uint8List x) {
    bool overflow = false;
    for (var i=0;i<x.length;i++) {
      var nextOverflow = x[i]&0x1==0x1;
      x[i] >>= 1;
      if (overflow) x[i] |= 0x80;
      overflow = nextOverflow;
    }
    return overflow;
  }

  @override
  int doFinal(Uint8List out, int outOff) {

    var result = remainingInput.length>0 ? processBlock(remainingInput, 0, out, outOff) : 0;

    var len = new Uint8List.view((new Uint64List(2)..[1] = aad.length*8..[0] = _processedBytes*8).buffer);
    len = new Uint8List.fromList(len.reversed.toList());

    _gHASHBlock(_x, len);

    _xor(_x, _e0);

    if (forEncryption) {
      out.setAll(outOff+result, _x);
      result+=_x.length;
    }

    validateMac();

    return result;
  }

  @override
  Uint8List get mac => _x;

  @override
  void processAADBytes(Uint8List inp, int inpOff, int len) {
    var block = new Uint8List(16);
    for (var i=0;i<len;i+=16) {
      block.fillRange(0, 16, 0);
      block.setAll(0, inp.sublist(inpOff+i,inpOff+min(i+16,len)));
      _gHASHBlock(_x, block);
    }
  }

}


