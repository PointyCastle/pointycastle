part of cipher_api;


// Block ciphers factory
final _blockCipherFactories = new Map<String,BlockCipherFactory>();
void _registerBlockCipher( String algorithmName, BlockCipherFactory creator ) 
  => _registerAlgorithm(_blockCipherFactories, algorithmName, creator);
BlockCipher _createBlockCipher( String algorithmName ) 
  => _getFactory(_blockCipherFactories, algorithmName)();

// Chaining block ciphers factory
final _chainingBlockCipherFactories = new Map<String,ChainingBlockCipherFactory>();
void _registerChainingBlockCipher( String algorithmName, ChainingBlockCipherFactory creator ) 
  => _registerAlgorithm(_chainingBlockCipherFactories, algorithmName, creator);
ChainingBlockCipher _createChainingBlockCipher( String algorithmName, BlockCipher underlyingCipher ) 
  => _getFactory(_chainingBlockCipherFactories, algorithmName)(underlyingCipher);

// Stream ciphers factory
final _streamCipherFactories = new Map<String,StreamCipherFactory>();
void _registerStreamCipher( String algorithmName, StreamCipherFactory creator )
  => _registerAlgorithm(_streamCipherFactories, algorithmName, creator);
StreamCipher _createStreamCipher( String algorithmName ) 
  => _getFactory(_streamCipherFactories, algorithmName)();

// Digests factory
final _digestFactories = new Map<String,DigestFactory>();
void _registerDigest( String algorithmName, DigestFactory creator )
  => _registerAlgorithm(_digestFactories, algorithmName, creator);
Digest _createDigest( String algorithmName ) 
  => _getFactory(_digestFactories, algorithmName)();


/**
 * Generic factory creation method
 */
dynamic _getFactory( Map factories, String algorithmName ) {
  var factory = factories[algorithmName];
  if( factory==null ) {
    throw new UnsupportedError("No algorithm with that name registered: ${algorithmName}");
  } else {
    return factory;
  }
}

/**
 * Generic factory registration method
 */
void _registerAlgorithm( Map<String,dynamic> factories, String algorithmName, dynamic creator ) {
  if( factories.containsKey(algorithmName) ) {
    throw new StateError("Algorithm with that name already registered: ${algorithmName}");
  }
  factories[algorithmName] = creator;
}
