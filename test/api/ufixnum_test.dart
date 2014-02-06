// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.api.ufixnum_test;

import 'dart:typed_data';

import "package:cipher/api/ufixnum.dart";
import "package:unittest/unittest.dart";

void main() {
  _testUint8();
  _testUint16();
  _testUint32();
  _testUint64();
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
    });

    test( "operator >>", () {
      var val = new Uint8(0x80);
      expect( (val>>0).toInt(),  0x80 );
      expect( (val>>3).toInt(),  0x10 );
      expect( (val>>4).toInt(),  0x08 );
      expect( (val>>-5).toInt(), 0x10 );
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
    });

    test( "operator >>", () {
      var val = new Uint16(0x8000);
      expect( (val>>0).toInt(),   0x8000 );
      expect( (val>>3).toInt(),   0x1000 );
      expect( (val>>4).toInt(),   0x0800 );
      expect( (val>>-13).toInt(), 0x1000 );
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
    });

    test( "operator >>", () {
      var val = new Uint32(0x80000000);
      expect( (val>>0).toInt(),   0x80000000 );
      expect( (val>>3).toInt(),   0x10000000 );
      expect( (val>>4).toInt(),   0x08000000 );
      expect( (val>>-29).toInt(), 0x10000000 );
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
      expect( new Uint64(0x0000000000000000).toInt(),  equals(0x0000000000000000) );
      expect( new Uint64(0xFFFFFFFFFFFFFFFF).toInt(),  equals(0xFFFFFFFFFFFFFFFF) );
      expect( new Uint64(0x10000000000000000).toInt(), equals(0x0000000000000000) );
    });

    test( "Uint64.fromLittleEndian()", () {
      var data = new Uint8List.fromList( [0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80] );
      expect( new Uint64.fromLittleEndian(data, 0).toInt(), 0x8070605040302010 );
    });

    test( "Uint64.fromBigEndian()", () {
      var data = new Uint8List.fromList( [0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80] );
      expect( new Uint64.fromBigEndian(data, 0).toInt(), 0x1020304050607080 );
    });

    test( "size getters", () {
      var val = new Uint64(0);
      expect( val.bitLength, 64 );
      expect( val.byteLength, 8 );
    });

    test( "operator ==", () {
      var l = new Uint64(0x8080808080808080);
      expect( l==0x8080808080808080, true );
      expect( l==0xFFFFFFFFFFFFFFFF, false );
      expect( l==l,                  true );
    });

    test( "operator <", () {
      var l = new Uint64(0x8080808080808080);
      expect( l<0x0000000000000000, false );
      expect( l<0x8080808080808080, false );
      expect( l<0xFFFFFFFFFFFFFFFF, true );
      expect( l<l,          false );
    });

    test( "operator <=", () {
      var l = new Uint64(0x8080808080808080);
      expect( l<=0x0000000000000000, false );
      expect( l<=0x8080808080808080, true );
      expect( l<=0xFFFFFFFFFFFFFFFF, true );
      expect( l<=l,                  true );
    });

    test( "operator >", () {
      var l = new Uint64(0x8080808080808080);
      expect( l>0x0000000000000000, true );
      expect( l>0x8080808080808080, false );
      expect( l>0xFFFFFFFFFFFFFFFF, false );
      expect( l>l,                  false );
    });

    test( "operator >=", () {
      var l = new Uint64(0x8080808080808080);
      expect( l>=0x0000000000000000, true );
      expect( l>=0x8080808080808080, true );
      expect( l>=0xFFFFFFFFFFFFFFFF, false );
      expect( l>=l,                  true );
    });

    test( "operator - (unary)", () {
      expect( (-new Uint64(0x8000000000000000)).toInt(), 0x8000000000000000 );
      expect( (-new Uint64(0x0000000000000001)).toInt(), 0xFFFFFFFFFFFFFFFF );
      expect( (-new Uint64(0x0000000000000000)).toInt(), 0x0000000000000000 );
    });

    test( "operator ~ (unary)", () {
      expect( (~new Uint64(0x5555555555555555)).toInt(), 0xAAAAAAAAAAAAAAAA );
      expect( (~new Uint64(0xFFFFFFFFFFFFFFFF)).toInt(), 0x0000000000000000 );
      expect( (~new Uint64(0x0000000000000000)).toInt(), 0xFFFFFFFFFFFFFFFF );
    });

    test( "operator +", () {
      var l = new Uint64(0x8000000000000000);
      expect( (l+0x10000000000000000).toInt(), 0x8000000000000000 );
      expect( (l+0x8000000000000000).toInt(),  0x0000000000000000 );
      expect( (l+0x1000000000000000).toInt(),  0x9000000000000000 );
      expect( (l+0x0000000000000000).toInt(),  0x8000000000000000 );
    });

    test( "operator -", () {
      var l = new Uint64(0x8000000000000000);
      expect( (l-0x10000000000000000).toInt(), 0x8000000000000000 );
      expect( (l-0x8000000000000000).toInt(),  0x0000000000000000 );
      expect( (l-0x1000000000000000).toInt(),  0x7000000000000000 );
      expect( (l-0x0000000000000000).toInt(),  0x8000000000000000 );
    });

    test( "operator *", () {
      var l = new Uint64(0x1000000000000000);
      expect( (l*0x0000000000000000).toInt(), 0x0000000000000000 );
      expect( (l*0x0000000000000001).toInt(), 0x1000000000000000 );
      expect( (l*0x0000000000000008).toInt(), 0x8000000000000000 );
      expect( (l*0x0000000000000010).toInt(), 0x0000000000000000 );
    });

    test( "operator /", () {
      var l = new Uint64(0x1000000000000000);
      expect( (l/0x0000000000000002).toInt(), 0x0800000000000000 );
      expect( (l/0x0800000000000000).toInt(), 0x0000000000000002 );
      expect( (l/0x0F00000000000000).toInt(), 0x0000000000000001 );
      expect( (l/0xFFFFFFFFFFFFFFFF).toInt(), 0x0000000000000000 );
    });

    test( "operator ~/", () {
      var l = new Uint64(0x1000000000000000);
      expect( (l/0x0000000000000002).toInt(), 0x0800000000000000 );
      expect( (l/0x0800000000000000).toInt(), 0x0000000000000002 );
      expect( (l/0x0F00000000000000).toInt(), 0x0000000000000001 );
      expect( (l/0xFFFFFFFFFFFFFFFF).toInt(), 0x0000000000000000 );
    });

    test( "operator %", () {
      var l = new Uint64(0x1000000000000000);
      expect( (l%0x0000000000000002).toInt(), 0x0000000000000000 );
      expect( (l%0x0000000000000008).toInt(), 0x0000000000000000 );
      expect( (l%0x0F00000000000000).toInt(), 0x0100000000000000 );
      expect( (l%0xFFFFFFFFFFFFFFFF).toInt(), 0x1000000000000000 );
    });

    test( "operator &", () {
      var l = new Uint64(0x5555555555555555);
      expect( (l&0x0000000000000000).toInt(), 0x0000000000000000 );
      expect( (l&0x0101010101010101).toInt(), 0x0101010101010101 );
      expect( (l&0xF0F0F0F0F0F0F0F0).toInt(), 0x5050505050505050 );
      expect( (l&0xFFFFFFFFFFFFFFFF).toInt(), 0x5555555555555555 );
    });

    test( "operator |", () {
      var l = new Uint64(0x5555555555555555);
      expect( (l|0x0000000000000000).toInt(), 0x5555555555555555 );
      expect( (l|0x0202020202020202).toInt(), 0x5757575757575757 );
      expect( (l|0xF0F0F0F0F0F0F0F0).toInt(), 0xF5F5F5F5F5F5F5F5 );
      expect( (l|0xFFFFFFFFFFFFFFFF).toInt(), 0xFFFFFFFFFFFFFFFF );
    });

    test( "operator ^", () {
      var l = new Uint64(0x5555555555555555);
      expect( (l^0x0000000000000000).toInt(), 0x5555555555555555 );
      expect( (l^0x0202020202020202).toInt(), 0x5757575757575757 );
      expect( (l^0xF0F0F0F0F0F0F0F0).toInt(), 0xA5A5A5A5A5A5A5A5 );
      expect( (l^0xFFFFFFFFFFFFFFFF).toInt(), 0xAAAAAAAAAAAAAAAA );
    });

    test( "operator <<", () {
      var val = new Uint64(0x1000000000000000);
      expect( (val<<0).toInt(),   0x1000000000000000 );
      expect( (val<<3).toInt(),   0x8000000000000000 );
      expect( (val<<4).toInt(),   0x0000000000000000 );
      expect( (val<<-61).toInt(), 0x8000000000000000 );
    });

    test( "operator >>", () {
      var val = new Uint64(0x8000000000000000);
      expect( (val>>0).toInt(),   0x8000000000000000 );
      expect( (val>>3).toInt(),   0x1000000000000000 );
      expect( (val>>4).toInt(),   0x0800000000000000 );
      expect( (val>>-61).toInt(), 0x1000000000000000 );
    });

    test( "rotl()", () {
      var val = new Uint64(0x1000000000000000);
      expect( val.rotl(0).toInt(),  0x1000000000000000 );
      expect( val.rotl(3).toInt(),  0x8000000000000000 );
      expect( val.rotl(64).toInt(), 0x1000000000000000 );
      try {
        val.rotl(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "rotr()", () {
      var val = new Uint64(0x1000000000000000);
      expect( val.rotr(0).toInt(),  0x1000000000000000 );
      expect( val.rotr(3).toInt(),  0x0200000000000000 );
      expect( val.rotr(64).toInt(), 0x1000000000000000 );
      try {
        val.rotr(-5);
        fail("expected exception when shift value is negative");
      } catch( e ) {
      }
    });

    test( "toBigEndian()", () {
      var out = new Uint8List(8);
      new Uint64(0x1020304050607080).toBigEndian( out, 0 );
      expect( out[0], equals(0x10) );
      expect( out[1], equals(0x20) );
      expect( out[2], equals(0x30) );
      expect( out[3], equals(0x40) );
      expect( out[4], equals(0x50) );
      expect( out[5], equals(0x60) );
      expect( out[6], equals(0x70) );
      expect( out[7], equals(0x80) );
    });

    test( "toLittleEndian()", () {
      var out = new Uint8List(8);
      new Uint64(0x1020304050607080).toLittleEndian( out, 0 );
      expect( out[0], equals(0x80) );
      expect( out[1], equals(0x70) );
      expect( out[2], equals(0x60) );
      expect( out[3], equals(0x50) );
      expect( out[4], equals(0x40) );
      expect( out[5], equals(0x30) );
      expect( out[6], equals(0x20) );
      expect( out[7], equals(0x10) );
    });

  });
}

