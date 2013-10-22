
import "dart:typed_data";

import "package:cipher/engines/aes_fast.dart";
import "package:cipher/params/key_parameter.dart";

import "../test_helpers/test_helpers.dart";

void main() {
  const CIPHER_BLOCKS = 20 * 1024 * 1024;
  const DECIPHER_BLOCKS = 20 * 1024 * 1024;

  benchmark(CIPHER_BLOCKS,true);
  benchmark(DECIPHER_BLOCKS,false);
}

void benchmark( int blocks, bool forEncryption ) {
  var key = createUint8ListFromListOfInts( [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF] );
  var params = new KeyParameter(key);
  var aes = new AESFastEngine()..init(forEncryption, params);
  var plainText = createUint8ListFromSequentialNumbers(aes.blockSize);
  var out = new Uint8List(plainText.length);
 
  var bytes = blocks*aes.blockSize;
  var bmsize = formatAsHumanSize(bytes);
  
  print("Benchmarking ${forEncryption?'encryption':'decryption'} of ${bmsize} of data");
  
  var start = new DateTime.now();
  for( var i=0 ; i<blocks ; i++ ) {
    aes.processBlock(plainText, 0, out, 0);
  }
  var end = new DateTime.now();
  
  var lap = end.millisecondsSinceEpoch - start.millisecondsSinceEpoch;
  
  print( "    Lap time:   $lap ms" );
  print( "    Throughput: ${formatAsHumanSize(1000*bytes/lap)}/s" );
  print( "" );

}
