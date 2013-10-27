part of cipher_cmd_benchmark;

const BENCHMARK_LENGTH_SECONDS = 2*60;  

void _doBenchmarkBlock(List<String> args) {
  var algorithmName = arg(args,0);
  
  if( algorithmName==null ) {
    print("cipher: no algorithm name specified");
  } else {
    try { 
      var cipher = new BlockCipher(algorithmName);
      
      print( "Note: benchmarks will take around $BENCHMARK_LENGTH_SECONDS seconds each.\n" );
      
      var CIPHER_BLOCKS = _adjustBenchmarkBlocks( cipher, BENCHMARK_LENGTH_SECONDS, true );
      _benchmarkBlock( true, cipher, CIPHER_BLOCKS, true );

      var DECIPHER_BLOCKS = _adjustBenchmarkBlocks( cipher, BENCHMARK_LENGTH_SECONDS, false );
      _benchmarkBlock( true, cipher, DECIPHER_BLOCKS, false );
      
    } catch( e ) {
      print("cipher: cannot create algorithm '${algorithmName}'");
      print("        (reason=${e})" );
    }
  }
}

int _adjustBenchmarkBlocks(BlockCipher cipher, int desiredLengthInSeconds, bool forEncryption ) {
  int duration = _benchmarkBlock( false, cipher, 1024*1024, forEncryption );
  int mb = (desiredLengthInSeconds*1000/duration).round();
  return mb*1024*1024;
}

int _benchmarkBlock( bool verbose, BlockCipher cipher, int blocks, bool forEncryption ) {
  var plainText = new Uint8List(cipher.blockSize);
  var out = new Uint8List(plainText.length);
 
  var bytes = blocks*cipher.blockSize;
  var bmsize = _formatAsHumanSize(bytes);
  
  if( verbose ) {
    print(
        "Benchmarking ${cipher.algorithmName} with "
        "${forEncryption?'encryption':'decryption'} of ${bmsize} of data:"
    );
  }
  
  var start = new DateTime.now();
  _initBlock(cipher,forEncryption);
  for( var i=0 ; i<blocks ; i++ ) {
    cipher.processBlock(plainText, 0, out, 0);
  }
  var end = new DateTime.now();
  
  var lap = end.millisecondsSinceEpoch - start.millisecondsSinceEpoch;
  
  if( verbose ) {
    print( "    Lap time:   $lap ms" );
    print( "    Throughput: ${_formatAsHumanSize(1000*bytes/lap)}/s" );
    print( "" );
  }
  
  return lap;
}

void _initBlock(BlockCipher cipher, bool forEncryption) {
  var cipherClass = reflectClass(cipher.runtimeType);
  var initMethod = cipherClass.methods[new Symbol("init")];
  var paramsType = initMethod.parameters[1].type;
  var params;
  
  if( paramsType == reflectType(CipherParameters) ) {
    params = null;
    
  } else if( paramsType == reflectType(KeyParameter) ) {
    var key = new Uint8List.fromList([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF]);
    params = new KeyParameter(key);
    
  } else {
    throw new UnsupportedError("No initializer for algorithm '${cipher.algorithmName}' found");
    
  }
  
  cipher.reset();
  cipher.init(forEncryption, params);
}

