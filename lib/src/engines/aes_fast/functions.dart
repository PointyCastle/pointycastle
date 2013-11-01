// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

part of cipher.engines.aes_fast;

int _shift(int r, int shift) {
  return lsr( r, shift ) | (r << 32-shift);
}

/* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

const int _m1 = 0x80808080;
const int _m2 = 0x7f7f7f7f;
const int _m3 = 0x0000001b;

int _FFmulX(int x) {
  return (((x & _m2) << 1) ^ lsr((x & _m1) , 7) * _m3);
}

/* 
The following defines provide alternative definitions of FFmulX that might
give improved performance if a fast 32-bit multiply is not available.

private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); } 
private static final int  m4 = 0x1b1b1b1b;
private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); } 

*/

int _inv_mcol(int x) {
  int f2 = _FFmulX(x);
  int f4 = _FFmulX(f2);
  int f8 = _FFmulX(f4);
  int f9 = x ^ f8;
  
  return f2 ^ f4 ^ f8 ^ _shift(f2 ^ f9, 8) ^ _shift(f4 ^ f9, 16) ^ _shift(f9, 24);
}


int _subWord(int x) {
  return (_S[x&255]&255 | ((_S[(x>>8)&255]&255)<<8) | ((_S[(x>>16)&255]&255)<<16) | _S[(x>>24)&255]<<24);
}



