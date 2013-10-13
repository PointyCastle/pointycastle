part of cipher_digests_ripemd160;

/** Cyclic logical shift left for 32 bit signed integers */
Int32 _clsl( Int32 x, int n ) {
  return (x << n) | _lsr( x, 32-n );
}

/** Logical shift right for 32 bit signed integers */
Int32 _lsr( Int32 n, int shift ) {
  if( shift<0 ) {
    shift = 32+(shift%32);
  }

  int shift5 = shift & 0x1f;
  Int32 n32 = n;
  if (shift5 == 0) {
    return n32;
  } else {
    return (n32 >> shift5) & ((0x7fffffff >> (shift5-1)));
  }
}

/** rounds 0-15 */
Int32 _f1( Int32 x, Int32 y, Int32 z ) {
  return x ^ y ^ z;
}

/** rounds 16-31 */
Int32 _f2( Int32 x, Int32 y, Int32 z ) {
  return (x & y) | (~x & z);
}

/** rounds 32-47 */
Int32 _f3( Int32 x, Int32 y, Int32 z ) {
  return (x | ~y) ^ z;
}

/** rounds 48-63 */
Int32 _f4( Int32 x, Int32 y, Int32 z ) {
  return (x & z) | (y & ~z);
}

/** rounds 64-79 */
Int32 _f5( Int32 x, Int32 y, Int32 z ) {
  return x ^ (y | ~z);
}
