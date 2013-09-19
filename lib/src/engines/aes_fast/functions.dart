part of cipher_engines_aes_fast;

int _shift(int r, int shift) {
  return _lsr( r, shift ) | (r << 32-shift);
}

/* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

const int _m1 = 0x80808080;
const int _m2 = 0x7f7f7f7f;
const int _m3 = 0x0000001b;

int FFmulX(int x) {
  return (((x & _m2) << 1) ^ (_lsr((x & _m1) , 7) * _m3));
}

/* 
The following defines provide alternative definitions of FFmulX that might
give improved performance if a fast 32-bit multiply is not available.

private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); } 
private static final int  m4 = 0x1b1b1b1b;
private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); } 

*/

int _inv_mcol(int x) {
  int f2 = FFmulX(x);
  int f4 = FFmulX(f2);
  int f8 = FFmulX(f4);
  int f9 = x ^ f8;
  
  return f2 ^ f4 ^ f8 ^ _shift(f2 ^ f9, 8) ^ _shift(f4 ^ f9, 16) ^ _shift(f9, 24);
}


int _subWord(int x) {
  return (_S[x&255]&255 | ((_S[(x>>8)&255]&255)<<8) | ((_S[(x>>16)&255]&255)<<16) | _S[(x>>24)&255]<<24);
}


/**
 * Compute 32-bit logical shift right of a value. This emulates the JavaScript >>> operator.
 * Source: https://code.google.com/p/dart/issues/detail?id=1169
 */
int _lsr(int n, int shift) {
  int shift5 = shift & 0x1f;
  int n32 = 0xffffffff & n;
  if (shift5 == 0) {
    return n32;
  } else {
    return (n32 >> shift5) & ((0x7fffffff >> (shift5-1)));
  }
}

