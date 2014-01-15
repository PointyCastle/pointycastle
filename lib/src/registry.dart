// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.api;

/// A registry holds the map of factories indexed by algorithm names.
class Registry<T> {

  final _staticFactories = new Map<String,Function>();
  final _dynamicFactories = new List<Function>();

  /// Shorthand for [registerStaticFactory]
  operator []= (String algorithmName, T factory(String) )
    => registerStaticFactory(algorithmName, factory);

  /// Register an algorithm by its name.
  void registerStaticFactory( String algorithmName, T factory(String) ) {
    _staticFactories[algorithmName] = factory;
  }

  /// Register an algorithm factory method which can translate a variable algorithm name into an implementation.
  void registerDynamicFactory( T factory(String) ) {
    _dynamicFactories.add(factory);
  }

  /// Create an algorithm given its name
  T create( String algorithmName ) {
    var factory = _staticFactories[algorithmName];
    if( factory!=null ) {
      return factory(algorithmName);
    } else {
      for( factory in _dynamicFactories ) {
        var algorithm = factory(algorithmName);
        if( algorithm!=null ) {
          return algorithm;
        }
      }
    }
    throw new UnsupportedError("No algorithm with that name registered: ${algorithmName}");
  }

}
