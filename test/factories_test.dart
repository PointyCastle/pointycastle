library factories_tests;

import "package:cipher/all.dart";
import "package:cipher/engines/null.dart";

import "package:unittest/unittest.dart";
import "package:unittest/matcher.dart";

void main() {
  
  initCipher();
  
  test( "BlockCipher returns valid implementations", () {
  
    expect( new BlockCipher("AES"), new isInstanceOf<BlockCipher>("BlockCipher") );

  });

  test( "ChainingBlockCipher returns valid implementations", () {

    expect( new ChainingBlockCipher("SIC",new NullBlockCipher()), new isInstanceOf<BlockCipher>("BlockCipher") );
    expect( new ChainingBlockCipher("CTR",new NullBlockCipher()), new isInstanceOf<BlockCipher>("BlockCipher") );
    
  });

  test( "StreamCipher returns valid implementations", () {
    
    expect( new StreamCipher("Salsa20"), new isInstanceOf<StreamCipher>("StreamCipher") );

  });

  test( "Digest returns valid implementations", () {
    
    expect( new Digest("RIPEMD-160"), new isInstanceOf<Digest>("Digest") );

  });

}

