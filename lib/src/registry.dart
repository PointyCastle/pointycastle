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

/// Factory function to create [Padding]s. 
typedef Padding PaddingFactory();

