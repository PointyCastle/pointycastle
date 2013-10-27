library factories_tests;

import "package:cipher/all.dart";

import "package:unittest/unittest.dart";
import "package:unittest/matcher.dart";

void main() {
  
  initCipher();
  
  test( "BlockCipher returns valid implementations", () {
  
    expect( new BlockCipher("AES"), new isInstanceOf<BlockCipher>("BlockCipher") );
    // TODO: chain block algorithms 
    // TODO: expect( new BlockCipher("SIC"), new isInstanceOf<BlockCipher>("BlockCipher") );
    // TODO: expect( new BlockCipher("CTR"), new isInstanceOf<BlockCipher>("BlockCipher") );

  });

  test( "StreamCipher returns valid implementations", () {
    
    expect( new StreamCipher("Salsa20"), new isInstanceOf<StreamCipher>("StreamCipher") );

  });

  test( "Digest returns valid implementations", () {
    
    expect( new Digest("RIPEMD-160"), new isInstanceOf<Digest>("Digest") );

  });

}
