// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

/**
 * This library contains all out-of-the-box implementations of the interfaces provided in the API which are compatible only with
 * server side. It includes the [cipher.impl] library and extends it with more algorithms.
 *
 * You must call [initCipher] method before using this library to load all implementations into cipher's API factories.
 * There's no need to call [initCipher] from [cipher.impl] if you call [initCipher] from this library (though you can do it if
 * your project's layout needs it).
 */
library cipher.impl.server;

import "package:cipher/api.dart";
import "package:cipher/impl/base.dart" as base;

import "package:cipher/entropy/file_entropy_source.dart";
import "package:cipher/entropy/url_entropy_source.dart";
import "package:cipher/entropy/command_entropy_source.dart";

bool _initialized = false;

/// This is the initializer method for this library. It must be called prior to use any of the implementations.
void initCipher() {
  if( !_initialized ) {
    _initialized = true;
    base.initCipher();
    _registerEntropySources();
  }
}

void _registerEntropySources() {
  EntropySource.registry.registerDynamicFactory(_fileEntropySourceFactory);
  EntropySource.registry.registerDynamicFactory(_urlEntropySourceFactory);
  EntropySource.registry.registerDynamicFactory(_commandEntropySourceFactory);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

EntropySource _fileEntropySourceFactory(String algorithmName) {
  if( algorithmName.startsWith("file://") ) {
    var filePath = algorithmName.substring(7);
    return new FileEntropySource(filePath);
  }

  return null;
}

EntropySource _urlEntropySourceFactory(String algorithmName) {
  if( algorithmName.startsWith("http://") || algorithmName.startsWith("https://") ) {
    return new UrlEntropySource(algorithmName);
  }

  return null;
}

EntropySource _commandEntropySourceFactory(String algorithmName) {
  if (algorithmName.startsWith("command:")) {
    final cmdLine = algorithmName.substring(8);
    final parts = cmdLine.split("|");
    return new CommandEntropySource(1024, parts[0], parts.sublist(1));
  }

  return null;
}

dynamic _createOrNull( closure() ) {
  try {
   return closure();
  } on UnsupportedError catch( e ) {
    return null;
  }
}