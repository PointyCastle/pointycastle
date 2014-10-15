// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.registry;

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
