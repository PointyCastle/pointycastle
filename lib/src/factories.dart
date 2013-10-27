part of cipher_api;

final _blockCipherFactories = new Map<String,dynamic>();
final _streamCipherFactories = new Map<String,dynamic>();
final _digestFactories = new Map<String,dynamic>();

void _registerBlockCipher( String algorithmName, BlockCipherFactory creator ) 
  => _registerAlgorithm(_blockCipherFactories, algorithmName, creator);
void _registerStreamCipher( String algorithmName, StreamCipherFactory creator )
  => _registerAlgorithm(_streamCipherFactories, algorithmName, creator);
void _registerDigest( String algorithmName, DigestFactory creator )
  => _registerAlgorithm(_digestFactories, algorithmName, creator);

BlockCipher _createBlockCipher( String algorithmName ) 
  => _createAlgorithm(_blockCipherFactories, algorithmName);
StreamCipher _createStreamCipher( String algorithmName ) 
  => _createAlgorithm(_streamCipherFactories, algorithmName);
Digest _createDigest( String algorithmName ) 
  => _createAlgorithm(_digestFactories, algorithmName);

/**
 * Generic factory creation method
 */
dynamic _createAlgorithm( Map factories, String algorithmName ) {
  var factory = factories[algorithmName];
  if( factory==null ) {
    throw new UnsupportedError("No algorithm with that name registered: ${algorithmName}");
  } else {
    return factory();
  }
}

/**
 * Generic factory registration method
 */
void _registerAlgorithm( Map factories, String algorithmName, dynamic creator ) {
  if( factories.containsKey(algorithmName) ) {
    throw new StateError("Algorithm with that name already registered: ${algorithmName}");
  }
  factories[algorithmName] = creator;
}
