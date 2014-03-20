// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.api.ufixnum_test;

import 'dart:typed_data';

import "package:bignum/bignum.dart";
import "package:cipher/api/ufixnum.dart";
import "package:unittest/unittest.dart";

void main() {
  _test8();
  _test16();
  _test32();
  _testRegister64();
  _testRegister64List();

  _testUint8();
  _testUint16();
  _testUint32();
  _testUint64();
}

void _test8() {

  group( "int8:", () {

    test( "clip8()", () {
      expect(clip8(0x00),  0x00);
      expect(clip8(0xFF),  0xFF);
      expect(clip8(0x100), 0x00);
    });

    test( "sum8()", () {
      expect(sum8(0x00, 0x01), 0x01);
      expect(sum8(0xFF, 0x01), 0x00);
    });

    test( "sub8()", () {
      expect(sub8(0x00, 0x01), 0xFF);
      expect(sub8(0xFF, 0x01), 0xFE);
    });

    test( "shiftl8()", () {
      expect(shiftl8(0xAB, 0), 0xAB);
      expect(shiftl8(0xAB, 4), 0xB0);
      expect(shiftl8(0xAB, 8), 0xAB);
    });

    test( "shiftr8()", () {
      expect(shiftr8(0xAB, 0), 0xAB);
      expect(shiftr8(0xAB, 4), 0x0A);
      expect(shiftr8(0xAB, 8), 0xAB);
    });

    test( "neg8()", () {
      expect(neg8(0x00), 0x00);
      expect(neg8(0xFF), 0x01);
      expect(neg8(0x01), 0xFF);
    });

    test( "not8()", () {
      expect(not8(0x00), 0xFF);
      expect(not8(0xFF), 0x00);
      expect(not8(0x01), 0xFE);
    });

    test( "rotl8()", () {
      expect(rotl8(0xAB, 0), 0xAB);
      expect(rotl8(0x7F, 1), 0xFE);
      expect(rotl8(0xAB, 4), 0xBA);
      expect(rotl8(0xAB, 8), 0xAB);
    });

    test( "rotr8()", () {
      expect(rotr8(0xAB, 0), 0xAB);
      expect(rotr8(0xFE, 1), 0x7F);
      expect(rotr8(0xAB, 4), 0xBA);
      expect(rotr8(0xAB, 8), 0xAB);
    });

  });

}

void _test16() {

  group( "int16:", () {

    test( "clip16()", () {
      expect(clip16( 0x0000), 0x0000);
      expect(clip16( 0xFFFF), 0xFFFF);
      expect(clip16(0x10000), 0x0000);
    });

  });

}

void _test32() {

  group( "int32:", () {

    test( "clip32()", () {
      expect(clip32( 0x00000000), 0x00000000);
      expect(clip32( 0xFFFFFFFF), 0xFFFFFFFF);
      expect(clip32(0x100000000), 0x00000000);
    });

    test( "sum32()", () {
      expect(sum32(0x00000000, 0x00000001), 0x00000001);
      expect(sum32(0xFFFFFFFF, 0x00000001), 0x00000000);
    });

    test( "sub32()", () {
      expect(sub32(0x00000000, 0x00000001), 0xFFFFFFFF);
      expect(sub32(0xFFFFFFFF, 0x00000001), 0xFFFFFFFE);
    });

    test( "shiftl32()", () {
      expect(shiftl32(0x10203040,  0), 0x10203040);
      expect(shiftl32(0x10203040, 16), 0x30400000);
      expect(shiftl32(0x10203040, 32), 0x10203040);
    });

    test( "shiftr32()", () {
      expect(shiftr32(0x10203040,  0), 0x10203040);
      expect(shiftr32(0x10203040, 16), 0x00001020);
      expect(shiftr32(0x10203040, 32), 0x10203040);
    });

    test( "neg32()", () {
      expect(neg32(0x00000000), 0x00000000);
      expect(neg32(0xFFFFFFFF), 0x00000001);
      expect(neg32(0x00000001), 0xFFFFFFFF);
    });

    test( "not32()", () {
      expect(not32(0x00000000), 0xFFFFFFFF);
      expect(not32(0xFFFFFFFF), 0x00000000);
      expect(not32(0x00000001), 0xFFFFFFFE);
    });

    test( "rotl32()", () {
      expect(rotl32(0x10203040,  0), 0x10203040);
      expect(rotl32(0x10203040,  8), 0x20304010);
      expect(rotl32(0x10203040, 16), 0x30401020);
      expect(rotl32(0x10203040, 32), 0x10203040);
    });

    test( "rotr32()", () {
      expect(rotr32(0x10203040,  0), 0x10203040);
      expect(rotr32(0x10203040,  8), 0x40102030);
      expect(rotr32(0x10203040, 16), 0x30401020);
      expect(rotr32(0x10203040, 32), 0x10203040);
    });

    test( "pack32(BIG_ENDIAN)", () {
      var out = new Uint8List(4);
      pack32(0x10203040, out, 0, Endianness.BIG_ENDIAN);
      expect(out[0], 0x10);
      expect(out[1], 0x20);
      expect(out[2], 0x30);
      expect(out[3], 0x40);
    });

    test( "pack32(LITTLE_ENDIAN)", () {
      var out = new Uint8List(4);
      pack32(0x10203040, out, 0, Endianness.LITTLE_ENDIAN);
      expect(out[3], 0x10);
      expect(out[2], 0x20);
      expect(out[1], 0x30);
      expect(out[0], 0x40);
    });

    test( "unpack32(BIG_ENDIAN)", () {
      var inp = new Uint8List.fromList([0x10, 0x20, 0x30, 0x40]);
      expect(unpack32(inp, 0, Endianness.BIG_ENDIAN), 0x10203040);
    });

    test( "unpack32(LITTLE_ENDIAN)", () {
      var inp = new Uint8List.fromList([0x40, 0x30, 0x20, 0x10]);
      expect(unpack32(inp, 0, Endianness.LITTLE_ENDIAN), 0x10203040);
    });

  });

}

void _testRegister64() {

  group( "Register64:", () {

    test( "Register64(hi,lo)", () {
      expect(new Register64(0x00000000, 0x00000000), new Register64(0x00000000, 0x00000000));
      expect(new Register64(0x10203040, 0xFFFFFFFF), new Register64(0x10203040, 0xFFFFFFFF));
    });

    test( "Register64(lo)", () {
      expect(new Register64(0x00000000), new Register64(0x00000000, 0x00000000));
      expect(new Register64(0x10203040), new Register64(0x00000000, 0x10203040));
    });

    test( "Register64(y)", () {
      expect(
          new Register64(new Register64(0x00000000, 0x00000000)),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(new Register64(0x10203040, 0xFFFFFFFF)),
          new Register64(0x10203040, 0xFFFFFFFF));
    });

    test( "==", () {
      expect(
          new Register64(0x00000000, 0x00000000) == new Register64(0x00000000, 0x00000000), true);
      expect(
          new Register64(0x00000000, 0x00000001) == new Register64(0x00000000, 0x00000000), false);
      expect(
          new Register64(0x00000001, 0x00000000) == new Register64(0x00000000, 0x00000000), false);
      expect(
          new Register64(0x00000001, 0x00000001) == new Register64(0x00000000, 0x00000000), false);
    });

    test( "<", () {
      expect(
          new Register64(0x00000000, 0x00000000) < new Register64(0x00000000, 0x00000000), false);

      expect(
          new Register64(0x00000000, 0x00000001) < new Register64(0x00000000, 0x10000000), true);
      expect(
          new Register64(0x00000000, 0x20000000) < new Register64(0x00000000, 0x10000000), false);
      expect(
          new Register64(0x00000001, 0x00000000) < new Register64(0x00000000, 0x10000000), false);

      expect(
          new Register64(0x00000000, 0x00000001) < new Register64(0x10000000, 0x00000000), true);
      expect(
          new Register64(0x00000001, 0x00000001) < new Register64(0x10000000, 0x00000000), true);
      expect(
          new Register64(0x10000000, 0x00000000) < new Register64(0x10000000, 0x00000000), false);
      expect(
          new Register64(0x20000000, 0x00000001) < new Register64(0x10000000, 0x00000000), false);
    });

    test( "<=", () {
      expect(
          new Register64(0x00000000, 0x00000000) <= new Register64(0x00000000, 0x00000000), true);

      expect(
          new Register64(0x00000000, 0x00000001) <= new Register64(0x00000000, 0x10000000), true);
      expect(
          new Register64(0x00000000, 0x20000000) <= new Register64(0x00000000, 0x10000000), false);
      expect(
          new Register64(0x00000001, 0x00000000) <= new Register64(0x00000000, 0x10000000), false);

      expect(
          new Register64(0x00000000, 0x00000001) <= new Register64(0x10000000, 0x00000000), true);
      expect(
          new Register64(0x00000001, 0x00000001) <= new Register64(0x10000000, 0x00000000), true);
      expect(
          new Register64(0x10000000, 0x00000000) <= new Register64(0x10000000, 0x00000000), true);
      expect(
          new Register64(0x20000000, 0x00000001) <= new Register64(0x10000000, 0x00000000), false);
    });

    test( ">", () {
      expect(
          new Register64(0x00000000, 0x00000000) > new Register64(0x00000000, 0x00000000), false);

      expect(
          new Register64(0x00000000, 0x10000000) > new Register64(0x00000000, 0x00000001), true);
      expect(
          new Register64(0x00000000, 0x10000000) > new Register64(0x00000000, 0x20000000), false);
      expect(
          new Register64(0x10000000, 0x00000000) > new Register64(0x00000001, 0x00000000), true);

      expect(
          new Register64(0x10000000, 0x00000001) > new Register64(0x00000000, 0x00000000), true);
      expect(
          new Register64(0x10000000, 0x00000000) > new Register64(0x00000001, 0x00000001), true);
      expect(
          new Register64(0x10000000, 0x00000000) > new Register64(0x10000000, 0x00000000), false);
      expect(
          new Register64(0x10000000, 0x00000000) > new Register64(0x20000000, 0x00000001), false);
    });

    test( ">=", () {
      expect(
          new Register64(0x00000000, 0x00000000) >= new Register64(0x00000000, 0x00000000), true);

      expect(
          new Register64(0x00000000, 0x10000000) >= new Register64(0x00000000, 0x00000001), true);
      expect(
          new Register64(0x00000000, 0x10000000) >= new Register64(0x00000000, 0x20000000), false);
      expect(
          new Register64(0x10000000, 0x00000000) >= new Register64(0x00000001, 0x00000000), true);

      expect(
          new Register64(0x10000000, 0x00000001) >= new Register64(0x00000000, 0x00000000), true);
      expect(
          new Register64(0x10000000, 0x00000000) >= new Register64(0x00000001, 0x00000001), true);
      expect(
          new Register64(0x10000000, 0x00000000) >= new Register64(0x10000000, 0x00000000), true);
      expect(
          new Register64(0x10000000, 0x00000000) >= new Register64(0x20000000, 0x00000001), false);
    });

    test( "set(hi,lo)", () {
      expect(new Register64()..set(0x00000000, 0x00000000), new Register64(0x00000000, 0x00000000));
      expect(new Register64()..set(0x10203040, 0xFFFFFFFF), new Register64(0x10203040, 0xFFFFFFFF));
    });

    test( "set(lo)", () {
      expect(new Register64()..set(0x00000000), new Register64(0x00000000, 0x00000000));
      expect(new Register64()..set(0x10203040), new Register64(0x00000000, 0x10203040));
    });

    test( "set(y)", () {
      expect(
          new Register64()..set(new Register64(0x00000000, 0x00000000)),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64()..set(new Register64(0x10203040, 0xFFFFFFFF)),
          new Register64(0x10203040, 0xFFFFFFFF));
    });

    test( "sum(int)", () {
      expect(
          new Register64(0x00000000, 0x00000000)..sum(0x00000001),
          new Register64(0x00000000, 0x00000001));
      expect(
          new Register64(0x00000000, 0x80000000)..sum(0x80000001),
          new Register64(0x00000001, 0x00000001));
      expect(
          new Register64(0xFFFFFFFF, 0xFFFFFFFF)..sum(0x00000001),
          new Register64(0x00000000, 0x00000000));
    });

    test( "sum(y)", () {
      expect(
          new Register64(0x00000000, 0x00000000)..sum(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000000, 0x00000001));
      expect(
          new Register64(0x00000000, 0x80000000)..sum(new Register64(0x00000000, 0x80000001)),
          new Register64(0x00000001, 0x00000001));
      expect(
          new Register64(0xFFFFFFFF, 0xFFFFFFFF)..sum(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000000, 0x00000000));
    });

    test( "sub(int)", () {
      expect(
          new Register64(0x00000000, 0x00000000)..sub(0x00000001),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x00000001, 0x00000001)..sub(0x80000001),
          new Register64(0x00000000, 0x80000000));
      expect(
          new Register64(0xFFFFFFFF, 0xFFFFFFFF)..sub(0x00000001),
          new Register64(0xFFFFFFFF, 0xFFFFFFFE));
    });

    test( "sub(y)", () {
      expect(
          new Register64(0x00000000, 0x00000000)..sub(new Register64(0x00000000, 0x00000001)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x00000001, 0x00000001)..sub(new Register64(0x00000000, 0x80000001)),
          new Register64(0x00000000, 0x80000000));
      expect(
          new Register64(0xFFFFFFFF, 0xFFFFFFFF)..sub(new Register64(0x00000000, 0x00000001)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFE));
    });

    test( "mul(int)", () {
      expect(
          new Register64(0x00000000, 0x00000000)..mul(0x00000000),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000000)..mul(0x00000001),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000001)..mul(0x00000001),
          new Register64(0x00000000, 0x00000001));
      expect(
          new Register64(0x00000001, 0x00000000)..mul(0x00000001),
          new Register64(0x00000001, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000001)..mul(0xFFFFFFFF),
          new Register64(0x00000000, 0xFFFFFFFF));
      expect(
          new Register64(0x00000000, 0x80000000)..mul(0x00000004),
          new Register64(0x00000002, 0x00000000));
      expect(
          new Register64(0x00000000, 0x80000001)..mul(0x00000004),
          new Register64(0x00000002, 0x00000004));
      expect(
          new Register64(0x80000001, 0x80000001)..mul(0x00000004),
          new Register64(0x00000006, 0x00000004));
    });

    test( "mul(y)", () {
      expect(
          new Register64(0x00000000, 0x00000000)..mul(new Register64(0x00000000, 0x00000000)),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000000)..mul(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000001)..mul(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000000, 0x00000001));
      expect(
          new Register64(0x00000001, 0x00000000)..mul(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000001, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000001)..mul(new Register64(0x00000000, 0xFFFFFFFF)),
          new Register64(0x00000000, 0xFFFFFFFF));
      expect(
          new Register64(0x00000000, 0x80000000)..mul(new Register64(0x00000000, 0x00000004)),
          new Register64(0x00000002, 0x00000000));
      expect(
          new Register64(0x00000000, 0x80000001)..mul(new Register64(0x00000000, 0x00000004)),
          new Register64(0x00000002, 0x00000004));
      expect(
          new Register64(0x80000001, 0x80000001)..mul(new Register64(0x00000000, 0x00000004)),
          new Register64(0x00000006, 0x00000004));
    });

    test( "neg()", () {
      expect(new Register64(0x00000000, 0x00000000)..neg(), new Register64(0x00000000, 0x00000000));
      expect(new Register64(0xFFFFFFFF, 0xFFFFFFFF)..neg(), new Register64(0x00000000, 0x00000001));
      expect(new Register64(0x50505050, 0x05050505)..neg(), new Register64(0xAFAFAFAF, 0xFAFAFAFB));
    });

    test( "not()", () {
      expect(new Register64(0x00000000, 0x00000000)..not(), new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(new Register64(0xFFFFFFFF, 0xFFFFFFFF)..not(), new Register64(0x00000000, 0x00000000));
      expect(new Register64(0x50505050, 0x05050505)..not(), new Register64(0xAFAFAFAF, 0xFAFAFAFA));
    });

    test( "and()", () {
      expect(
          new Register64(0x00000000, 0x00000000)..and(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x10203040, 0x05050505)..and(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0x10203040, 0x05050505));
      expect(
          new Register64(0x10203040, 0x05050505)..and(new Register64(0x00000000, 0xFFFFFFFF)),
          new Register64(0x00000000, 0x05050505));
      expect(
          new Register64(0x10203040, 0x05050505)..and(new Register64(0xFFFFFFFF, 0x00000000)),
          new Register64(0x10203040, 0x00000000));
    });

    test( "or()", () {
      expect(
          new Register64(0x00000000, 0x00000000)..or(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x10203040, 0x05050505)..or(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x10203040, 0x05050505)..or(new Register64(0x00000000, 0xFFFFFFFF)),
          new Register64(0x10203040, 0xFFFFFFFF));
      expect(
          new Register64(0x10203040, 0x05050505)..or(new Register64(0xFFFFFFFF, 0x00000000)),
          new Register64(0xFFFFFFFF, 0x05050505));
    });

    test( "xor()", () {
      expect(
          new Register64(0x00000000, 0x00000000)..xor(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x10203040, 0x05050505)..xor(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0xEFDFCFBF, 0xFAFAFAFA));
      expect(
          new Register64(0x10203040, 0x05050505)..xor(new Register64(0x00000000, 0xFFFFFFFF)),
          new Register64(0x10203040, 0xFAFAFAFA));
      expect(
          new Register64(0x10203040, 0x05050505)..xor(new Register64(0xFFFFFFFF, 0x00000000)),
          new Register64(0xEFDFCFBF, 0x05050505));
    });

    test( "shiftl()", () {
      expect(
          new Register64(0x10203040, 0x05050505)..shiftl( 0),
          new Register64(0x10203040, 0x05050505));
      expect(
          new Register64(0x10203040, 0x05050505)..shiftl(16),
          new Register64(0x30400505, 0x05050000));
      expect(
          new Register64(0x10203040, 0x05050505)..shiftl(32),
          new Register64(0x05050505, 0x00000000));
      expect(
          new Register64(0x10203040, 0x05050505)..shiftl(48),
          new Register64(0x05050000, 0x00000000));
      expect(
          new Register64(0x10203040, 0x05050505)..shiftl(64),
          new Register64(0x10203040, 0x05050505));
    });

    test( "shiftr()", () {
      expect(
          new Register64(0x10203040, 0x05050505)..shiftr( 0),
          new Register64(0x10203040, 0x05050505));
      expect(
          new Register64(0x10203040, 0x05050505)..shiftr(16),
          new Register64(0x00001020, 0x30400505));
      expect(
          new Register64(0x10203040, 0x05050505)..shiftr(32),
          new Register64(0x00000000, 0x10203040));
      expect(
          new Register64(0x10203040, 0x05050505)..shiftr(48),
          new Register64(0x00000000, 0x00001020));
      expect(
          new Register64(0x10203040, 0x05050505)..shiftr(64),
          new Register64(0x10203040, 0x05050505));
    });

    test( "rotl()", () {
      expect(
          new Register64(0x10203040, 0x05050505)..rotl( 0), new Register64(0x10203040, 0x05050505));
      expect(
          new Register64(0x10203040, 0x05050505)..rotl(16), new Register64(0x30400505, 0x05051020));
      expect(
          new Register64(0x10203040, 0x05050505)..rotl(32), new Register64(0x05050505, 0x10203040));
      expect(
          new Register64(0x10203040, 0x05050505)..rotl(48), new Register64(0x05051020, 0x30400505));
      expect(
          new Register64(0x10203040, 0x05050505)..rotl(64), new Register64(0x10203040, 0x05050505));
    });

    test( "rotr()", () {
      expect(
          new Register64(0x10203040, 0x05050505)..rotr( 0), new Register64(0x10203040, 0x05050505));
      expect(
          new Register64(0x10203040, 0x05050505)..rotr(16), new Register64(0x05051020, 0x30400505));
      expect(
          new Register64(0x10203040, 0x05050505)..rotr(32), new Register64(0x05050505, 0x10203040));
      expect(
          new Register64(0x10203040, 0x05050505)..rotr(48), new Register64(0x30400505, 0x05051020));
      expect(
          new Register64(0x10203040, 0x05050505)..rotr(64), new Register64(0x10203040, 0x05050505));
    });

    test( "pack(BIG_ENDIAN)", () {
      var out = new Uint8List(64);
      new Register64(0x10203040, 0x50607080).pack(out, 0, Endianness.BIG_ENDIAN);
      expect(out[0], 0x10);
      expect(out[1], 0x20);
      expect(out[2], 0x30);
      expect(out[3], 0x40);
      expect(out[4], 0x50);
      expect(out[5], 0x60);
      expect(out[6], 0x70);
      expect(out[7], 0x80);
    });

    test( "pack(LITTLE_ENDIAN)", () {
      var out = new Uint8List(64);
      new Register64(0x10203040, 0x50607080).pack(out, 0, Endianness.LITTLE_ENDIAN);
      expect(out[7], 0x10);
      expect(out[6], 0x20);
      expect(out[5], 0x30);
      expect(out[4], 0x40);
      expect(out[3], 0x50);
      expect(out[2], 0x60);
      expect(out[1], 0x70);
      expect(out[0], 0x80);
    });

    test( "unpack(BIG_ENDIAN)", () {
      var inp = new Uint8List.fromList([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
      expect(new Register64()..unpack(inp, 0, Endianness.BIG_ENDIAN), new Register64(0x10203040, 0x50607080));
    });

    test( "unpack(LITTLE_ENDIAN)", () {
      var inp = new Uint8List.fromList([0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10]);
      expect(
         new Register64()..unpack(inp, 0, Endianness.LITTLE_ENDIAN), new Register64(0x10203040, 0x50607080));
    });

    test( "toString()", () {
      expect(new Register64(0x00203040, 0x00050505).toString(), "0020304000050505");
    });

  });

}

void _testRegister64List() {

  group( "Register64List:", () {

    test( "Register64.from()", () {
      final list = new Register64List.from([ [0,1], [2,3], [4,5] ]);

      expect(list[0], new Register64(0x00000000, 0x00000001));
      expect(list[1], new Register64(0x00000002, 0x00000003));
      expect(list[2], new Register64(0x00000004, 0x00000005));
    });

  });
}

void _testUint8() {

  group( "Uint8:", () {

    test( "Uint8()", () {
      expect( new Uint8(0x00).toInt(),  equals(0x00) );
      expect( new Uint8(0xFF).toInt(),  equals(0xFF) );
      expect( new Uint8(0x100).toInt(), equals(0x00) );
    });

    test( "size getters", () {
      var val = new Uint8(0);
      expect( val.bitLength, 8 );
      expect( val.byteLength, 1 );
    });

    test( "toUintX()", () {
      var val = new Uint8(0x10);
      expect(val.toUint8(), new Uint8(0x10));
      expect(val.toUint16(), new Uint16(0x10));
      expect(val.toUint32(), new Uint32(0x10));
      expect(val.toUint64(), new Uint64(0,0x10));
    });

    test( "operator ==", () {
      var l = new Uint8(0x80);
      expect( l==0x80, true );
      expect( l==0xFF, false );
      expect( l==l, true );
    });

    test( "operator <", () {
      var l = new Uint8(0x80);
      expect( l<0x00, false );
      expect( l<0x80, false );
      expect( l<0xFF, true );
      expect( l<l,    false );
    });

    test( "operator <=", () {
      var l = new Uint8(0x80);
      expect( l<=0x00, false );
      expect( l<=0x80, true );
      expect( l<=0xFF, true );
      expect( l<=l,    true );
    });

    test( "operator >", () {
      var l = new Uint8(0x80);
      expect( l>0x00, true );
      expect( l>0x80, false );
      expect( l>0xFF, false );
      expect( l>l,    false );
    });

    test( "operator >=", () {
      var l = new Uint8(0x80);
      expect( l>=0x00, true );
      expect( l>=0x80, true );
      expect( l>=0xFF, false );
      expect( l>=l,    true );
    });

    test( "operator - (unary)", () {
      expect( (-new Uint8(0x80)).toInt(), 0x80 );
      expect( (-new Uint8(0x01)).toInt(), 0xFF );
      expect( (-new Uint8(0x00)).toInt(), 0x00 );
    });

    test( "operator ~ (unary)", () {
      expect( (~new Uint8(0x55)).toInt(), 0xAA );
      expect( (~new Uint8(0xFF)).toInt(), 0x00 );
      expect( (~new Uint8(0x00)).toInt(), 0xFF );
    });

    test( "operator +", () {
      var l = new Uint8(0x80);
      expect( (l+0x100).toInt(), 0x80 );
      expect( (l+0x80).toInt(),  0x00 );
      expect( (l+0x10).toInt(),  0x90 );
      expect( (l+0x00).toInt(),  0x80 );
    });

    test( "operator -", () {
      var l = new Uint8(0x80);
      expect( (l-0x100).toInt(), 0x80 );
      expect( (l-0x80).toInt(),  0x00 );
      expect( (l-0x10).toInt(),  0x70 );
      expect( (l-0x00).toInt(),  0x80 );
    });

    test( "operator *", () {
      var l = new Uint8(0x10);
      expect( (l*0x00).toInt(), 0x00 );
      expect( (l*0x01).toInt(), 0x10 );
      expect( (l*0x08).toInt(), 0x80 );
      expect( (l*0x10).toInt(), 0x00 );
    });

    test( "operator /", () {
      var l = new Uint8(0x10);
      expect( (l/0x02).toInt(), 0x08 );
      expect( (l/0x08).toInt(), 0x02 );
      expect( (l/0x0F).toInt(), 0x01 );
      expect( (l/0xFF).toInt(), 0x00 );
    });

    test( "operator %", () {
      var l = new Uint8(0x10);
      expect( (l%0x02).toInt(), 0x00 );
      expect( (l%0x08).toInt(), 0x00 );
      expect( (l%0x0F).toInt(), 0x01 );
      expect( (l%0xFF).toInt(), 0x10 );
    });

    test( "operator &", () {
      var l = new Uint8(0x55);
      expect( (l&0x00).toInt(), 0x00 );
      expect( (l&0x01).toInt(), 0x01 );
      expect( (l&0xF0).toInt(), 0x50 );
      expect( (l&0xFF).toInt(), 0x55 );
    });

    test( "operator |", () {
      var l = new Uint8(0x55);
      expect( (l|0x00).toInt(), 0x55 );
      expect( (l|0x02).toInt(), 0x57 );
      expect( (l|0xF0).toInt(), 0xF5 );
      expect( (l|0xFF).toInt(), 0xFF );
    });

    test( "operator ^", () {
      var l = new Uint8(0x55);
      expect( (l^0x00).toInt(), 0x55 );
      expect( (l^0x02).toInt(), 0x57 );
      expect( (l^0xF0).toInt(), 0xA5 );
      expect( (l^0xFF).toInt(), 0xAA );
    });

    test( "operator <<", () {
      var val = new Uint8(0x10);
      expect( (val<<0).toInt(),  0x10 );
      expect( (val<<3).toInt(),  0x80 );
      expect( (val<<4).toInt(),  0x00 );
      expect( (val<<-5).toInt(), 0x80 );
      expect( (val<<8).toInt(),  0x10 );
    });

    test( "operator >>", () {
      var val = new Uint8(0x80);
      expect( (val>>0).toInt(),  0x80 );
      expect( (val>>3).toInt(),  0x10 );
      expect( (val>>4).toInt(),  0x08 );
      expect( (val>>-5).toInt(), 0x10 );
      expect( (val>>8).toInt(),  0x80 );
    });

    test( "rotl()", () {
      var val = new Uint8(0x10);
      expect( val.rotl(0).toInt(),  0x10 );
      expect( val.rotl(3).toInt(),  0x80 );
      expect( val.rotl(8).toInt(),  0x10 );
      try {
        val.rotl(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "rotr()", () {
      var val = new Uint8(0x10);
      expect( val.rotr(0).toInt(),  0x10 );
      expect( val.rotr(3).toInt(),  0x02 );
      expect( val.rotr(8).toInt(),  0x10 );
      try {
        val.rotr(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "toBigEndian()", () {
      var out = new Uint8List(1);
      new Uint8(0x10).toBigEndian( out, 0 );
      expect( out[0], equals(0x10) );
    });

    test( "toLittleEndian()", () {
      var out = new Uint8List(1);
      new Uint8(0x10).toLittleEndian( out, 0 );
      expect( out[0], equals(0x10) );
    });

  });

}

void _testUint16() {

  group( "Uint16:", () {

    test( "Uint16()", () {
      expect( new Uint16(0x0000).toInt(),  equals(0x0000) );
      expect( new Uint16(0xFFFF).toInt(),  equals(0xFFFF) );
      expect( new Uint16(0x10000).toInt(), equals(0x0000) );
    });

    test( "Uint16.fromLittleEndian()", () {
      var data = new Uint8List.fromList( [0x10,0x20] );
      expect( new Uint16.fromLittleEndian(data, 0).toInt(), 0x2010 );
    });

    test( "Uint16.fromBigEndian()", () {
      var data = new Uint8List.fromList( [0x10,0x20] );
      expect( new Uint16.fromBigEndian(data, 0).toInt(), 0x1020 );
    });

    test( "size getters", () {
      var val = new Uint16(0);
      expect( val.bitLength, 16 );
      expect( val.byteLength, 2 );
    });

    test( "toUintX()", () {
      var val = new Uint16(0x1020);
      expect(val.toUint8(), new Uint8(0x20));
      expect(val.toUint16(), new Uint16(0x1020));
      expect(val.toUint32(), new Uint32(0x1020));
      expect(val.toUint64(), new Uint64(0,0x1020));
    });

    test( "operator ==", () {
      var l = new Uint16(0x8080);
      expect( l==0x8080, true );
      expect( l==0xFFFF, false );
      expect( l==l, true );
    });

    test( "operator <", () {
      var l = new Uint16(0x8080);
      expect( l<0x0000, false );
      expect( l<0x8080, false );
      expect( l<0xFFFF, true );
      expect( l<l,      false );
    });

    test( "operator <=", () {
      var l = new Uint16(0x8080);
      expect( l<=0x0000, false );
      expect( l<=0x8080, true );
      expect( l<=0xFFFF, true );
      expect( l<=l,      true );
    });

    test( "operator >", () {
      var l = new Uint16(0x8080);
      expect( l>0x0000, true );
      expect( l>0x8080, false );
      expect( l>0xFFFF, false );
      expect( l>l,      false );
    });

    test( "operator >=", () {
      var l = new Uint16(0x8080);
      expect( l>=0x0000, true );
      expect( l>=0x8080, true );
      expect( l>=0xFFFF, false );
      expect( l>=l,      true );
    });

    test( "operator - (unary)", () {
      expect( (-new Uint16(0x8000)).toInt(), 0x8000 );
      expect( (-new Uint16(0x0001)).toInt(), 0xFFFF );
      expect( (-new Uint16(0x0000)).toInt(), 0x0000 );
    });

    test( "operator ~ (unary)", () {
      expect( (~new Uint16(0x5555)).toInt(), 0xAAAA );
      expect( (~new Uint16(0xFFFF)).toInt(), 0x0000 );
      expect( (~new Uint16(0x0000)).toInt(), 0xFFFF );
    });

    test( "operator +", () {
      var l = new Uint16(0x8000);
      expect( (l+0x10000).toInt(), 0x8000 );
      expect( (l+0x8000).toInt(),  0x0000 );
      expect( (l+0x1000).toInt(),  0x9000 );
      expect( (l+0x0000).toInt(),  0x8000 );
    });

    test( "operator -", () {
      var l = new Uint16(0x8000);
      expect( (l-0x10000).toInt(), 0x8000 );
      expect( (l-0x8000).toInt(),  0x0000 );
      expect( (l-0x1000).toInt(),  0x7000 );
      expect( (l-0x0000).toInt(),  0x8000 );
    });

    test( "operator *", () {
      var l = new Uint16(0x1000);
      expect( (l*0x0000).toInt(), 0x0000 );
      expect( (l*0x0001).toInt(), 0x1000 );
      expect( (l*0x0008).toInt(), 0x8000 );
      expect( (l*0x0010).toInt(), 0x0000 );
    });

    test( "operator /", () {
      var l = new Uint16(0x1000);
      expect( (l/0x0002).toInt(), 0x0800 );
      expect( (l/0x0800).toInt(), 0x0002 );
      expect( (l/0x0F00).toInt(), 0x0001 );
      expect( (l/0xFFFF).toInt(), 0x0000 );
    });

    test( "operator ~/", () {
      var l = new Uint16(0x1000);
      expect( (l/0x0002).toInt(), 0x0800 );
      expect( (l/0x0800).toInt(), 0x0002 );
      expect( (l/0x0F00).toInt(), 0x0001 );
      expect( (l/0xFFFF).toInt(), 0x0000 );
    });

    test( "operator %", () {
      var l = new Uint16(0x1000);
      expect( (l%0x0002).toInt(), 0x0000 );
      expect( (l%0x0008).toInt(), 0x0000 );
      expect( (l%0x0F00).toInt(), 0x0100 );
      expect( (l%0xFFFF).toInt(), 0x1000 );
    });

    test( "operator &", () {
      var l = new Uint16(0x5555);
      expect( (l&0x0000).toInt(), 0x0000 );
      expect( (l&0x0101).toInt(), 0x0101 );
      expect( (l&0xF0F0).toInt(), 0x5050 );
      expect( (l&0xFFFF).toInt(), 0x5555 );
    });

    test( "operator |", () {
      var l = new Uint16(0x5555);
      expect( (l|0x0000).toInt(), 0x5555 );
      expect( (l|0x0202).toInt(), 0x5757 );
      expect( (l|0xF0F0).toInt(), 0xF5F5 );
      expect( (l|0xFFFF).toInt(), 0xFFFF );
    });

    test( "operator ^", () {
      var l = new Uint16(0x5555);
      expect( (l^0x0000).toInt(), 0x5555 );
      expect( (l^0x0202).toInt(), 0x5757 );
      expect( (l^0xF0F0).toInt(), 0xA5A5 );
      expect( (l^0xFFFF).toInt(), 0xAAAA );
    });

    test( "operator <<", () {
      var val = new Uint16(0x1000);
      expect( (val<<0).toInt(),   0x1000 );
      expect( (val<<3).toInt(),   0x8000 );
      expect( (val<<4).toInt(),   0x0000 );
      expect( (val<<-13).toInt(), 0x8000 );
      expect( (val<<16).toInt(),  0x1000 );
    });

    test( "operator >>", () {
      var val = new Uint16(0x8000);
      expect( (val>>0).toInt(),   0x8000 );
      expect( (val>>3).toInt(),   0x1000 );
      expect( (val>>4).toInt(),   0x0800 );
      expect( (val>>-13).toInt(), 0x1000 );
      expect( (val>>16).toInt(),  0x8000 );
    });

    test( "rotl()", () {
      var val = new Uint16(0x1000);
      expect( val.rotl(0).toInt(),  0x1000 );
      expect( val.rotl(3).toInt(),  0x8000 );
      expect( val.rotl(16).toInt(),  0x1000 );
      try {
        val.rotl(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "rotr()", () {
      var val = new Uint16(0x1000);
      expect( val.rotr(0).toInt(),  0x1000 );
      expect( val.rotr(3).toInt(),  0x0200 );
      expect( val.rotr(16).toInt(),  0x1000 );
      try {
        val.rotr(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "toBigEndian()", () {
      var out = new Uint8List(2);
      new Uint16(0x1020).toBigEndian( out, 0 );
      expect( out[0], equals(0x10) );
      expect( out[1], equals(0x20) );
    });

    test( "toLittleEndian()", () {
      var out = new Uint8List(2);
      new Uint16(0x1020).toLittleEndian( out, 0 );
      expect( out[0], equals(0x20) );
      expect( out[1], equals(0x10) );
    });

  });

}

void _testUint32() {

  group( "Uint32:", () {

    test( "Uint32()", () {
      expect( new Uint32(0x00000000).toInt(),  equals(0x00000000) );
      expect( new Uint32(0xFFFFFFFF).toInt(),  equals(0xFFFFFFFF) );
      expect( new Uint32(0x100000000).toInt(), equals(0x00000000) );
    });

    test( "Uint32.fromLittleEndian()", () {
      var data = new Uint8List.fromList( [0x10,0x20,0x30,0x40] );
      expect( new Uint32.fromLittleEndian(data, 0).toInt(), 0x40302010 );
    });

    test( "Uint32.fromBigEndian()", () {
      var data = new Uint8List.fromList( [0x10,0x20,0x30,0x40] );
      expect( new Uint32.fromBigEndian(data, 0).toInt(), 0x10203040 );
    });

    test( "size getters", () {
      var val = new Uint32(0);
      expect( val.bitLength, 32 );
      expect( val.byteLength, 4 );
    });

    test( "toUintX()", () {
      var val = new Uint32(0x10203040);
      expect(val.toUint8(), new Uint8(0x40));
      expect(val.toUint16(), new Uint16(0x3040));
      expect(val.toUint32(), new Uint32(0x10203040));
      expect(val.toUint64(), new Uint64(0,0x10203040));
    });

    test( "operator ==", () {
      var l = new Uint32(0x80808080);
      expect( l==0x80808080, true );
      expect( l==0xFFFFFFFF, false );
      expect( l==l,          true );
    });

    test( "operator <", () {
      var l = new Uint32(0x80808080);
      expect( l<0x00000000, false );
      expect( l<0x80808080, false );
      expect( l<0xFFFFFFFF, true );
      expect( l<l,          false );
    });

    test( "operator <=", () {
      var l = new Uint32(0x80808080);
      expect( l<=0x00000000, false );
      expect( l<=0x80808080, true );
      expect( l<=0xFFFFFFFF, true );
      expect( l<=l,          true );
    });

    test( "operator >", () {
      var l = new Uint32(0x80808080);
      expect( l>0x00000000, true );
      expect( l>0x80808080, false );
      expect( l>0xFFFFFFFF, false );
      expect( l>l,          false );
    });

    test( "operator >=", () {
      var l = new Uint32(0x80808080);
      expect( l>=0x00000000, true );
      expect( l>=0x80808080, true );
      expect( l>=0xFFFFFFFF, false );
      expect( l>=l,          true );
    });

    test( "operator - (unary)", () {
      expect( (-new Uint32(0x80000000)).toInt(), 0x80000000 );
      expect( (-new Uint32(0x00000001)).toInt(), 0xFFFFFFFF );
      expect( (-new Uint32(0x00000000)).toInt(), 0x00000000 );
    });

    test( "operator ~ (unary)", () {
      expect( (~new Uint32(0x55555555)).toInt(), 0xAAAAAAAA );
      expect( (~new Uint32(0xFFFFFFFF)).toInt(), 0x00000000 );
      expect( (~new Uint32(0x00000000)).toInt(), 0xFFFFFFFF );
    });

    test( "operator +", () {
      var l = new Uint32(0x80000000);
      expect( (l+0x100000000).toInt(), 0x80000000 );
      expect( (l+0x80000000).toInt(),  0x00000000 );
      expect( (l+0x10000000).toInt(),  0x90000000 );
      expect( (l+0x00000000).toInt(),  0x80000000 );
    });

    test( "operator -", () {
      var l = new Uint32(0x80000000);
      expect( (l-0x100000000).toInt(), 0x80000000 );
      expect( (l-0x80000000).toInt(),  0x00000000 );
      expect( (l-0x10000000).toInt(),  0x70000000 );
      expect( (l-0x00000000).toInt(),  0x80000000 );
    });

    test( "operator *", () {
      var l = new Uint32(0x10000000);
      expect( (l*0x00000000).toInt(), 0x00000000 );
      expect( (l*0x00000001).toInt(), 0x10000000 );
      expect( (l*0x00000008).toInt(), 0x80000000 );
      expect( (l*0x00000010).toInt(), 0x00000000 );
    });

    test( "operator /", () {
      var l = new Uint32(0x10000000);
      expect( (l/0x00000002).toInt(), 0x08000000 );
      expect( (l/0x08000000).toInt(), 0x00000002 );
      expect( (l/0x0F000000).toInt(), 0x00000001 );
      expect( (l/0xFFFFFFFF).toInt(), 0x00000000 );
    });

    test( "operator ~/", () {
      var l = new Uint32(0x10000000);
      expect( (l/0x00000002).toInt(), 0x08000000 );
      expect( (l/0x08000000).toInt(), 0x00000002 );
      expect( (l/0x0F000000).toInt(), 0x00000001 );
      expect( (l/0xFFFFFFFF).toInt(), 0x00000000 );
    });

    test( "operator %", () {
      var l = new Uint32(0x10000000);
      expect( (l%0x00000002).toInt(), 0x00000000 );
      expect( (l%0x00000008).toInt(), 0x00000000 );
      expect( (l%0x0F000000).toInt(), 0x01000000 );
      expect( (l%0xFFFFFFFF).toInt(), 0x10000000 );
    });

    test( "operator &", () {
      var l = new Uint32(0x55555555);
      expect( (l&0x00000000).toInt(), 0x00000000 );
      expect( (l&0x01010101).toInt(), 0x01010101 );
      expect( (l&0xF0F0F0F0).toInt(), 0x50505050 );
      expect( (l&0xFFFFFFFF).toInt(), 0x55555555 );
    });

    test( "operator |", () {
      var l = new Uint32(0x55555555);
      expect( (l|0x00000000).toInt(), 0x55555555 );
      expect( (l|0x02020202).toInt(), 0x57575757 );
      expect( (l|0xF0F0F0F0).toInt(), 0xF5F5F5F5 );
      expect( (l|0xFFFFFFFF).toInt(), 0xFFFFFFFF );
    });

    test( "operator ^", () {
      var l = new Uint32(0x55555555);
      expect( (l^0x00000000).toInt(), 0x55555555 );
      expect( (l^0x02020202).toInt(), 0x57575757 );
      expect( (l^0xF0F0F0F0).toInt(), 0xA5A5A5A5 );
      expect( (l^0xFFFFFFFF).toInt(), 0xAAAAAAAA );
    });

    test( "operator <<", () {
      var val = new Uint32(0x10000000);
      expect( (val<<0).toInt(),   0x10000000 );
      expect( (val<<3).toInt(),   0x80000000 );
      expect( (val<<4).toInt(),   0x00000000 );
      expect( (val<<-29).toInt(), 0x80000000 );
      expect( (val<<32).toInt(),  0x10000000 );
    });

    test( "operator >>", () {
      var val = new Uint32(0x80000000);
      expect( (val>>0).toInt(),   0x80000000 );
      expect( (val>>3).toInt(),   0x10000000 );
      expect( (val>>4).toInt(),   0x08000000 );
      expect( (val>>-29).toInt(), 0x10000000 );
      expect( (val>>32).toInt(),  0x80000000 );
    });

    test( "rotl()", () {
      var val = new Uint32(0x10000000);
      expect( val.rotl(0).toInt(),  0x10000000 );
      expect( val.rotl(3).toInt(),  0x80000000 );
      expect( val.rotl(32).toInt(), 0x10000000 );
      try {
        val.rotl(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "rotr()", () {
      var val = new Uint32(0x10000000);
      expect( val.rotr(0).toInt(),  0x10000000 );
      expect( val.rotr(3).toInt(),  0x02000000 );
      expect( val.rotr(32).toInt(), 0x10000000 );
      try {
        val.rotr(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "toBigEndian()", () {
      var out = new Uint8List(4);
      new Uint32(0x10203040).toBigEndian( out, 0 );
      expect( out[0], equals(0x10) );
      expect( out[1], equals(0x20) );
      expect( out[2], equals(0x30) );
      expect( out[3], equals(0x40) );
    });

    test( "toLittleEndian()", () {
      var out = new Uint8List(4);
      new Uint32(0x10203040).toLittleEndian( out, 0 );
      expect( out[0], equals(0x40) );
      expect( out[1], equals(0x30) );
      expect( out[2], equals(0x20) );
      expect( out[3], equals(0x10) );
    });

  });
}

void _testUint64() {

  group( "Uint64:", () {

    test( "Uint64()", () {
      expect( new Uint64(0,0).toRadixString(16), "0" );
      expect( new Uint64(0xFFFFFFFF,0xFFFFFFFF).toRadixString(16), "ffffffffffffffff" );
    });

    test( "Uint64.fromLittleEndian()", () {
      var data = new Uint8List.fromList( [0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80] );
      expect( new Uint64.fromLittleEndian(data, 0).toRadixString(16), "8070605040302010" );
    });

    test( "Uint64.fromBigEndian()", () {
      var data = new Uint8List.fromList( [0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80] );
      expect( new Uint64.fromBigEndian(data, 0).toRadixString(16), "1020304050607080" );
    });

    test( "size getters", () {
      var val = new Uint64(0,0);
      expect( val.bitLength, 64 );
      expect( val.byteLength, 8 );
    });

    test( "toUintX()", () {
      var val = new Uint64(0x10203040,0x50607080);
      expect(val.toUint8(), new Uint8(0x80));
      expect(val.toUint16(), new Uint16(0x7080));
      expect(val.toUint32(), new Uint32(0x50607080));
      expect(val.toUint64(), new Uint64(0x10203040,0x50607080));
    });

    test( "operator ==", () {
      var l = new Uint64(0x80808080,0x80808080);
      expect( l==new BigInteger("8080808080808080",16), true );
      expect( l==new BigInteger("FFFFFFFFFFFFFFFF",16), false );
      expect( l==l, true );
    });

    test( "operator <", () {
      var l = new Uint64(0x80808080,0x80808080);
      expect( l<new BigInteger("0000000000000000",16), false );
      expect( l<new BigInteger("8080808080808080",16), false );
      expect( l<new BigInteger("FFFFFFFFFFFFFFFF",16), true );
      expect( l<l, false );
    });

    test( "operator <=", () {
      var l = new Uint64(0x80808080,0x80808080);
      expect( l<=new BigInteger("0000000000000000",16), false );
      expect( l<=new BigInteger("8080808080808080",16), true );
      expect( l<=new BigInteger("FFFFFFFFFFFFFFFF",16), true );
      expect( l<=l, true );
    });

    test( "operator >", () {
      var l = new Uint64(0x80808080,0x80808080);
      expect( l>new BigInteger("0000000000000000",16), true );
      expect( l>new BigInteger("8080808080808080",16), false );
      expect( l>new BigInteger("FFFFFFFFFFFFFFFF",16), false );
      expect( l>l, false );
    });

    test( "operator >=", () {
      var l = new Uint64(0x80808080,0x80808080);
      expect( l>=new BigInteger("0000000000000000",16), true );
      expect( l>=new BigInteger("8080808080808080",16), true );
      expect( l>=new BigInteger("FFFFFFFFFFFFFFFF",16), false );
      expect( l>=l, true );
    });

    test( "operator - (unary)", () {
      expect( (-new Uint64(0x80000000,0x00000000)).toRadixString(16), "8000000000000000" );
      expect( (-new Uint64(0x00000000,0x00000001)).toRadixString(16), "ffffffffffffffff" );
      expect( (-new Uint64(0x00000000,0x00000000)).toRadixString(16),                "0" );
    });

    test( "operator ~ (unary)", () {
      expect( (~new Uint64(0x55555555,0x55555555)).toRadixString(16), "aaaaaaaaaaaaaaaa" );
      expect( (~new Uint64(0xFFFFFFFF,0xFFFFFFFF)).toRadixString(16),                "0" );
      expect( (~new Uint64(0x00000000,0x00000000)).toRadixString(16), "ffffffffffffffff" );
    });

    test( "operator +", () {
      var l = new Uint64(0x80000000,0x00000000);
      expect( (l+new BigInteger("8000000000000000",16)).toRadixString(16),                "0" );
      expect( (l+new BigInteger("1000000000000000",16)).toRadixString(16), "9000000000000000" );
      expect( (l+new BigInteger("0000000000000000",16)).toRadixString(16), "8000000000000000" );
    });

    test( "operator -", () {
      var l = new Uint64(0x80000000,0x00000000);
      expect( (l-new BigInteger("8000000000000000",16)).toRadixString(16),                "0");
      expect( (l-new BigInteger("1000000000000000",16)).toRadixString(16), "7000000000000000");
      expect( (l-new BigInteger("0000000000000000",16)).toRadixString(16), "8000000000000000");
    });

    test( "operator *", () {
      var l = new Uint64(0x10000000,0x00000000);
      expect( (l*new BigInteger("0000000000000000",16)).toRadixString(16),                "0" );
      expect( (l*new BigInteger("0000000000000001",16)).toRadixString(16), "1000000000000000" );
      expect( (l*new BigInteger("0000000000000008",16)).toRadixString(16), "8000000000000000" );
      expect( (l*new BigInteger("0000000000000010",16)).toRadixString(16),                "0" );
    });

    test( "operator /", () {
      var l = new Uint64(0x10000000,0x00000000);
      expect( (l/new BigInteger("0000000000000002",16)).toRadixString(16), "800000000000000" );
      expect( (l/new BigInteger("0800000000000000",16)).toRadixString(16),               "2" );
      expect( (l/new BigInteger("0F00000000000000",16)).toRadixString(16),               "1" );
      expect( (l/new BigInteger("FFFFFFFFFFFFFFFF",16)).toRadixString(16),               "0" );
    });

    test( "operator ~/", () {
      var l = new Uint64(0x10000000,0x00000000);
      expect( (l/new BigInteger("0000000000000002",16)).toRadixString(16), "800000000000000" );
      expect( (l/new BigInteger("0800000000000000",16)).toRadixString(16),               "2" );
      expect( (l/new BigInteger("0F00000000000000",16)).toRadixString(16),               "1" );
      expect( (l/new BigInteger("FFFFFFFFFFFFFFFF",16)).toRadixString(16),               "0" );
    });

    test( "operator %", () {
      var l = new Uint64(0x10000000,0x00000000);
      expect( (l%new BigInteger("0000000000000002",16)).toRadixString(16),                "0" );
      expect( (l%new BigInteger("0000000000000008",16)).toRadixString(16),                "0" );
      expect( (l%new BigInteger("0F00000000000000",16)).toRadixString(16),  "100000000000000" );
      expect( (l%new BigInteger("FFFFFFFFFFFFFFFF",16)).toRadixString(16), "1000000000000000" );
    });

    test( "operator &", () {
      var l = new Uint64(0x55555555,0x55555555);
      expect( (l&new BigInteger("0000000000000000",16)).toRadixString(16),                "0" );
      expect( (l&new BigInteger("0101010101010101",16)).toRadixString(16),  "101010101010101" );
      expect( (l&new BigInteger("F0F0F0F0F0F0F0F0",16)).toRadixString(16), "5050505050505050" );
      expect( (l&new BigInteger("FFFFFFFFFFFFFFFF",16)).toRadixString(16), "5555555555555555" );
    });

    test( "operator |", () {
      var l = new Uint64(0x55555555,0x55555555);
      expect( (l|new BigInteger("0000000000000000",16)).toRadixString(16), "5555555555555555" );
      expect( (l|new BigInteger("0202020202020202",16)).toRadixString(16), "5757575757575757" );
      expect( (l|new BigInteger("F0F0F0F0F0F0F0F0",16)).toRadixString(16), "f5f5f5f5f5f5f5f5" );
      expect( (l|new BigInteger("FFFFFFFFFFFFFFFF",16)).toRadixString(16), "ffffffffffffffff" );
    });

    test( "operator ^", () {
      var l = new Uint64(0x55555555,0x55555555);
      expect( (l^new BigInteger("0000000000000000",16)).toRadixString(16), "5555555555555555" );
      expect( (l^new BigInteger("0202020202020202",16)).toRadixString(16), "5757575757575757" );
      expect( (l^new BigInteger("F0F0F0F0F0F0F0F0",16)).toRadixString(16), "a5a5a5a5a5a5a5a5" );
      expect( (l^new BigInteger("FFFFFFFFFFFFFFFF",16)).toRadixString(16), "aaaaaaaaaaaaaaaa" );
    });

    test( "operator <<", () {
      var val = new Uint64(0x00000000,0x00000001);
      expect( (val<<0).toRadixString(16),                  "1" );
      expect( (val<<3).toRadixString(16),                  "8" );
      expect( (val<<4).toRadixString(16),                 "10" );
      expect( (val<<32).toRadixString(16),         "100000000" );
      expect( (val<<-61).toRadixString(16),                "8" );
      expect( (val<<64).toRadixString(16),                 "1" );
    });

    test( "operator >>", () {
      var val = new Uint64(0x80000000,0x00000000);
      expect( (val>>0).toRadixString(16),   "8000000000000000" );
      expect( (val>>3).toRadixString(16),   "1000000000000000" );
      expect( (val>>4).toRadixString(16),    "800000000000000" );
      expect( (val>>32).toRadixString(16),          "80000000" );
      expect( (val>>-61).toRadixString(16), "1000000000000000" );
      expect( (val>>64).toRadixString(16),  "8000000000000000" );
    });

    test( "rotl()", () {
      var val = new Uint64(0x10000000,0x00000000);
      expect( val.rotl(0).toRadixString(16),  "1000000000000000" );
      expect( val.rotl(3).toRadixString(16),  "8000000000000000" );
      expect( val.rotl(64).toRadixString(16), "1000000000000000" );
      try {
        val.rotl(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "rotr()", () {
      var val = new Uint64(0x10000000,0x00000000);
      expect( val.rotr(0).toRadixString(16),  "1000000000000000" );
      expect( val.rotr(3).toRadixString(16),   "200000000000000" );
      expect( val.rotr(64).toRadixString(16), "1000000000000000" );
      try {
        val.rotr(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "toBigEndian()", () {
      var out = new Uint8List(8);
      new Uint64(0x80203040,0x50607010).toBigEndian( out, 0 );
      expect( out[0], equals(0x80) );
      expect( out[1], equals(0x20) );
      expect( out[2], equals(0x30) );
      expect( out[3], equals(0x40) );
      expect( out[4], equals(0x50) );
      expect( out[5], equals(0x60) );
      expect( out[6], equals(0x70) );
      expect( out[7], equals(0x10) );
    });

    test( "toLittleEndian()", () {
      var out = new Uint8List(8);
      new Uint64(0x80203040,0x50607010).toLittleEndian( out, 0 );
      expect( out[0], equals(0x10) );
      expect( out[1], equals(0x70) );
      expect( out[2], equals(0x60) );
      expect( out[3], equals(0x50) );
      expect( out[4], equals(0x40) );
      expect( out[5], equals(0x30) );
      expect( out[6], equals(0x20) );
      expect( out[7], equals(0x80) );
    });

  });
}

