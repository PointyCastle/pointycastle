
import "package:cipher/src/util.dart";

import "package:unittest/unittest.dart";

void main() {

  const val1111 = 0xFFFFFFFF;
  const val1010 = 0xAAAAAAAA;
  
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
