
import "package:cipher/src/util.dart";

import "package:unittest/unittest.dart";

void main() {

  const val1111 = 0xFFFFFFFF;
  const val1010 = 0xAAAAAAAA;

  test( "toUint32()", () {

    expect( toUint32( 0x100000000 ), 0x00000000 );
    expect( toUint32( -1 ), 0xFFFFFFFF );

  });

  test( "clsl()", () {

    expect( clsl( 0x100000000, 1 ), 0x00000000 );
    expect( clsl( 0x80000000, 1 ), 0x00000001 );
    expect( clsl( 0x00000001, 1 ), 0x00000002 );
    expect( clsl( 0xFFFF0001, 8 ), 0xFF0001FF );

  });

  test( "lsl()", () {

    expect( lsl( 0x80000000, 1 ), 0x00000000 );
    expect( lsl( 0x00000001, 1 ), 0x00000002 );

  });

  test( "lsr() with positive shift", () {

    expect( lsr( val1111,  0 ), 0xFFFFFFFF );
    expect( lsr( val1111,  1 ), 0x7FFFFFFF );
    expect( lsr( val1111,  2 ), 0x3FFFFFFF );
    expect( lsr( val1111, 17 ), 0x00007FFF );
    expect( lsr( val1111, 31 ), 0x00000001 );
    expect( lsr( val1111, 32 ), 0xFFFFFFFF );
    expect( lsr( val1111, 33 ), 0x7FFFFFFF );
    expect( lsr( val1111, 64 ), 0xFFFFFFFF );
    expect( lsr( val1111, 65 ), 0x7FFFFFFF );

  });

  test( "lsr() with negative shift", () {

    expect( lsr( val1111,  -1 ), 0x00000001 );
    expect( lsr( val1111,  -2 ), 0x00000003 );
    expect( lsr( val1111, -17 ), 0x0001FFFF );
    expect( lsr( val1111, -31 ), 0x7FFFFFFF );
    expect( lsr( val1111, -32 ), 0xFFFFFFFF );
    expect( lsr( val1111, -33 ), 0x00000001 );
    expect( lsr( val1111, -64 ), 0xFFFFFFFF );
    expect( lsr( val1111, -65 ), 0x00000001 );

  });

}
