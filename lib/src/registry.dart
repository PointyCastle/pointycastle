// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

part of cipher.api;

/// A registry holds the factories indexed by algorithm names.
class Registry<Algorithm,AlgorithmFactory> {
  
  final _factories = new Map<String,AlgorithmFactory>();
  
  /// Shorthand for [put] method
  operator []=( String algorithName, AlgorithmFactory creator ) 
    => put(algorithName,creator);
  
  /// Shorthand for [get] method
  AlgorithmFactory operator []( String algorithmName ) 
    => get(algorithmName);
  
  /// Register an algorithm by its standard name. 
  void put( String algorithmName, AlgorithmFactory creator ) {
    _factories[algorithmName] = creator;
  }
  
  /// Get the factory for algorithm with name [algorithName]
  AlgorithmFactory get( String algorithmName ) {
    var factory = _factories[algorithmName];
    if( factory==null ) {
      throw new UnsupportedError("No algorithm with that name registered: ${algorithmName}");
    } else {
      return factory;
    }
  }

}

/// Factory function to create [BlockCipher]s. 
typedef BlockCipher BlockCipherFactory();

/// Factory function to create [ChainingBlockCipher]s. 
typedef ChainingBlockCipher ChainingBlockCipherFactory(BlockCipher underlyingCipher);

/// Factory function to create [StreamCipher]s. 
typedef StreamCipher StreamCipherFactory();

/// Factory function to create [Digest]s. 
typedef Digest DigestFactory();



/*

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
*/